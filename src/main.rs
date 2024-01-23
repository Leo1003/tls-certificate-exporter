#[macro_use]
extern crate tracing;

use crate::configs::ApplicationConfig;
use anyhow::Result as AnyResult;
use components::{MetricsExporter, Prober};
use configs::ConnectionParameters;
use hickory_resolver::AsyncResolver;
use std::{num::NonZeroUsize, sync::Arc};
use tokio::{sync::RwLock, task::JoinSet};

mod certificate_interceptor;
mod components;
mod configs;
mod error;
mod types;

fn main() -> AnyResult<()> {
    // Load environment variables from the `.env` file
    dotenvy::dotenv().ok();
    // Initialize the logger after loading the environment variables
    tracing_subscriber::fmt::init();

    let app_config = ApplicationConfig::load_config().expect("Failed to parse configuration files");

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

async fn async_main(app_config: ApplicationConfig) -> AnyResult<()> {
    let default_params = ConnectionParameters::load_from_global_config(&app_config).await?;

    let resolver = AsyncResolver::tokio_from_system_conf()?;
    let prober = Arc::new(Prober::new(resolver.clone()));
    let metrics_exporter = MetricsExporter::new()?;

    let mut taskset = JoinSet::new();
    taskset.spawn(async move { metrics_exporter.run().await });
    taskset.join_next().await;

    Ok(())
}
