#[macro_use]
extern crate tracing;

use crate::configs::GlobalConfig;
use anyhow::Result as AnyResult;
use components::{MetricsExporter, ProbeScheduler};
use configs::ConnectionParameters;
use hickory_resolver::AsyncResolver;
use prober::Prober;
use std::{num::NonZeroUsize, sync::Arc};
use store::Store;
use tokio::{sync::RwLock, task::JoinSet};

mod cert;
mod certificate_interceptor;
mod components;
mod configs;
mod error;
mod prober;
mod state;
mod store;

fn main() -> AnyResult<()> {
    // Load environment variables from the `.env` file
    dotenvy::dotenv().ok();
    // Initialize the logger after loading the environment variables
    tracing_subscriber::fmt::init();

    let app_config = GlobalConfig::load_config().expect("Failed to parse configuration files");

    // Setup async runtime
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(worker) = app_config.workers.and_then(NonZeroUsize::new) {
        runtime_builder.worker_threads(worker.into());
    }
    runtime_builder
        .enable_all()
        .build()
        .expect("Failed to bootstrap the Tokio runtime")
        .block_on(async_main(app_config))
}

async fn async_main(app_config: GlobalConfig) -> AnyResult<()> {
    let default_params = ConnectionParameters::load_from_global_config(&app_config).await?;

    let resolver = Arc::new(AsyncResolver::tokio_from_system_conf()?);
    let store = Arc::new(RwLock::new(Store::default()));
    let prober = Arc::new(Prober::new(resolver.clone(), default_params));

    let mut scheduler =
        ProbeScheduler::new(prober.clone(), store.clone(), app_config.scheduler.clone());
    let metrics_exporter = MetricsExporter::new(store.clone())?;

    for target_config in &app_config.targets {
        scheduler.load_from_target_config(target_config).await?;
    }

    let mut set = JoinSet::new();
    set.spawn(async move { scheduler.run().await });
    set.spawn(async move { metrics_exporter.run().await });
    set.join_next().await;

    Ok(())
}
