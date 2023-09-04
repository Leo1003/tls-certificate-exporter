mod cert;
mod config;
mod error;
mod state;
mod store;

fn main() {
    // Load environment variables from the `.env` file
    dotenvy::dotenv().ok();
    // Initialize the logger after loading the environment variables
    tracing_subscriber::fmt::init();

    // Setup async runtime
    tokio::runtime::Builder::new_multi_thread()
        // .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(server_loop())
}

async fn server_loop() {}
