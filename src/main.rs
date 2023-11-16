#[macro_use]
extern crate serde_with;
#[macro_use]
extern crate tracing;

use crate::configs::GlobalConfig;
use anyhow::{Context, Result as AnyResult};
use components::ProbeScheduler;
use configs::ConnectionParameters;
use prober::Prober;
use std::{num::NonZeroUsize, sync::Arc};
use store::{Store, Target};
use tokio::sync::{Mutex, RwLock};
use trust_dns_resolver::AsyncResolver;

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
        .block_on(server_loop(app_config))
}

async fn server_loop(app_config: GlobalConfig) -> AnyResult<()> {
    let default_params = ConnectionParameters::load_from_global_config(&app_config).await?;

    let resolver = Arc::new(AsyncResolver::tokio_from_system_conf()?);
    let store = Arc::new(RwLock::new(Store::default()));
    let prober = Arc::new(Prober::new(resolver.clone(), default_params));

    let mut scheduler =
        ProbeScheduler::new(prober.clone(), store.clone(), app_config.scheduler.clone());

    for target_config in &app_config.targets {
        scheduler.load_from_target_config(target_config).await?;
    }

    let scheduler = Arc::new(Mutex::new(scheduler));
    let scheduler_clone = scheduler.clone();

    let scheduler_handle = tokio::spawn(async move { scheduler_clone.lock().await.run().await });

    tokio::join!(scheduler_handle);

    Ok(())
}
