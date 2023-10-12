#[macro_use]
extern crate serde_with;

use configs::RuntimeConfig;
use error::AppResult;
use prober::Prober;
use store::Store;
use tokio::sync::RwLock;
use trust_dns_resolver::AsyncResolver;

use crate::configs::GlobalConfig;
use std::{num::NonZeroUsize, sync::Arc};

mod app;
mod cert;
mod certificate_interceptor;
mod configs;
mod error;
mod prober;
mod state;
mod store;

fn main() -> AppResult<()> {
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

async fn server_loop(app_config: GlobalConfig) -> AppResult<()> {
    let runtime_config = RuntimeConfig::load_from_config(app_config).await?;
    let resolver = Arc::new(AsyncResolver::tokio_from_system_conf()?);
    let store = Arc::new(RwLock::new(Store::with_config(runtime_config.target_default)));
    let prober = Prober::new(resolver.clone(), store.clone());

    Ok(())
}
