#[macro_use]
extern crate serde_with;

use anyhow::{Context, Result as AnyResult};
use chrono::Utc;
use configs::{ConnectionParameters, RuntimeConfig, DEFAULT_INTERVAL};
use futures::stream::FuturesUnordered;
use prober::Prober;
use store::{Store, Target, TargetState};
use tokio::{sync::RwLock, time::sleep};
use trust_dns_resolver::AsyncResolver;

use crate::configs::GlobalConfig;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

mod app;
mod cert;
mod certificate_interceptor;
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
    let runtime_config = RuntimeConfig::load_from_config(app_config).await?;
    let resolver = Arc::new(AsyncResolver::tokio_from_system_conf()?);
    let store = Arc::new(RwLock::new(Store::with_default_params(
        runtime_config.default_parameters.clone(),
    )));
    let prober = Prober::new(resolver.clone(), runtime_config.default_parameters.clone());

    let mut store_lock = store.write().await;
    for targets in runtime_config.targets {
        store_lock.insert_target(targets.target, targets.parameters);
    }
    drop(store_lock);

    loop {
        let wait = store.read().await.wait_duration();
        sleep(wait).await;

        let store_lock = store.read().await;
        let targets: Vec<(Target, ConnectionParameters)> = store_lock
            .target_store
            .iter()
            .filter(|(target, state)| {
                if let Some(last_probe) = state.last_probe {
                    let interval = state
                        .parameters
                        .interval
                        .or(runtime_config.default_parameters.interval)
                        .unwrap_or(DEFAULT_INTERVAL);
                    (Utc::now() - last_probe).to_std().unwrap_or(Duration::ZERO) > interval
                } else {
                    true
                }
            })
            .map(|(target, state)| (target.clone(), state.parameters.clone()))
            .collect();
    }

    Ok(())
}
