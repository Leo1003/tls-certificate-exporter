use super::{MetricsExporter, Prober};
use crate::{
    configs::{
        resolve_module_config, ApplicationConfig, ConnectionParameters,
        FileStore, FileType, ResolvedModuleConfig,
    },
    error::{AppResult, ErrorReason, HttpError, HttpResult},
    types::Target,
};
use anyhow::Result as AnyResult;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::get,
    Router,
};
use rustls_pki_types::PrivateKeyDer;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};

#[derive(Clone, Debug)]
pub struct ServerState {
    app_config: ApplicationConfig,
    prober: Prober,
    metrics_exporter: MetricsExporter,
    module_store: Arc<RwLock<HashMap<String, ResolvedModuleConfig>>>,
    file_store: Arc<Mutex<FileStore>>,
}

impl ServerState {
    pub fn load_from_config(
        app_config: ApplicationConfig,
        prober: Prober,
        metrics_exporter: MetricsExporter,
    ) -> AnyResult<Self> {
        let file_store = Arc::new(Mutex::new(FileStore::default()));
        let module_store =
            Arc::new(RwLock::new(resolve_module_config(&app_config.modules)?));
        Ok(Self {
            app_config,
            prober,
            metrics_exporter,
            module_store,
            file_store,
        })
    }

    pub async fn run_server(self) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 9880)).await?;
        axum::serve(listener, router(self)).await?;
        Ok(())
    }

    pub async fn load_parameters(
        &self,
        module_name: &str,
    ) -> AnyResult<ConnectionParameters> {
        let store_lock = self.module_store.read().await;
        let mut file_store_lock = self.file_store.lock().await;
        let module = store_lock
            .get(module_name)
            .ok_or(ErrorReason::UnknownModule)?;

        let mut parameters = ConnectionParameters {
            timeout: Some(module.timeout),
            trusted_anchors: file_store_lock
                .load_from_source_async(
                    &module.trustedanchors,
                    FileType::TrustAnchors,
                )
                .await?
                .try_into()?,
            server_name: module.server_name.clone(),
            insecure_skip_verify: module.insecure_skip_verify,
            ..Default::default()
        };

        if let Some(certs) = &module.certs {
            parameters.certs = file_store_lock
                .load_from_source_async(certs, FileType::Certificates)
                .await?
                .try_into()?;
        }
        if let Some(key) = &module.key {
            let key_der: PrivateKeyDer<'static> = file_store_lock
                .load_from_source_async(key, FileType::PrivateKey)
                .await?
                .try_into()?;
            parameters.key = Some(key_der.into());
        }
        Ok(parameters)
    }
}

fn router(state: ServerState) -> Router {
    Router::new()
        .route("/metrics", get(handle_metrics))
        .route("/probe", get(handle_probe))
        .with_state(state)
}

async fn handle_metrics(state: State<ServerState>) -> HttpResult<String> {
    todo!();
    // let encoder = TextEncoder::new();
    // let resp = encoder
    //     .encode_to_string(&state.registry.gather())
    //     .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Ok(resp)
}

async fn handle_probe(
    state: State<ServerState>,
    parameters: Query<ProbeParameters>,
) -> HttpResult<String> {
    let conn_parameters = state.load_parameters(&parameters.module).await?;

    let probe_results = state
        .prober
        .probe(&parameters.target, &conn_parameters)
        .await?;

    todo!();
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeParameters {
    pub target: Target,
    pub module: String,
}
