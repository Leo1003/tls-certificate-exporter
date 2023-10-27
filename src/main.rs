#[macro_use]
extern crate serde_with;
#[macro_use]
extern crate tracing;

use crate::configs::GlobalConfig;
use anyhow::{Context, Result as AnyResult};
use configs::{ConnectionParameters, RuntimeConfig};
use futures::{stream::FuturesUnordered, StreamExt};
use prober::Prober;
use std::{num::NonZeroUsize, sync::Arc};
use store::{Store, Target};
use tokio::{sync::RwLock, time::sleep};
use trust_dns_resolver::AsyncResolver;

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
    let prober = Arc::new(Prober::new(
        resolver.clone(),
        runtime_config.default_parameters,
    ));

    let mut store_lock = store.write().await;
    for targets in runtime_config.targets {
        store_lock.insert_target(targets.target, targets.parameters);
    }
    drop(store_lock);

    loop {
        let wait = store.read().await.wait_duration();
        debug!("Sleep for: {}ms", wait.as_millis());
        sleep(wait).await;

        let targets: Vec<(Target, ConnectionParameters)> = store
            .read()
            .await
            .iter_need_probe()
            .map(|(target, state)| (target.clone(), state.parameters.clone()))
            .collect();

        let mut tasks =
            FuturesUnordered::from_iter(targets.into_iter().map(|(target, parameters)| {
                let prober = prober.clone();
                async move {
                    let task_result = prober.probe(&target, &parameters).await;
                    trace!("prober.probe() = {:?}", &task_result);
                    (target, task_result)
                }
            }));

        while let Some((target, task_result)) = tasks.next().await {
            match task_result {
                Ok(probe_results) => {
                    store
                        .write()
                        .await
                        .update_probe_result(&target, probe_results)?;
                }
                Err(e) => {
                    error!("Failed to probe the target: {}", e);
                }
            };
        }
    }

    Ok(())
}
