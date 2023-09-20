#[macro_use]
extern crate serde_with;

use crate::configs::GlobalConfig;
use std::num::NonZeroUsize;

mod app;
mod cert;
mod certificate_interceptor;
mod configs;
mod error;
mod prober;
mod state;
mod store;

fn main() {
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
        .block_on(server_loop())
}

async fn server_loop() {}
