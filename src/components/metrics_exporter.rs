use crate::store::Store;
use anyhow::Result as AnyResult;
use axum::{extract::State, http::StatusCode, routing::get, Router};
use prometheus::{IntGaugeVec, Opts, Registry, TextEncoder};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::{net::TcpListener, sync::RwLock};

#[derive(Clone, Debug)]
struct ExporterState {
    pub store: Arc<RwLock<Store>>,
    pub registry: Registry,
    pub metric_not_before: IntGaugeVec,
    pub metric_not_after: IntGaugeVec,
}

#[derive(Clone, Debug)]
pub struct MetricsExporter {
    state: ExporterState,
}

impl MetricsExporter {
    pub fn new(store: Arc<RwLock<Store>>) -> AnyResult<Self> {
        let registry = Registry::new_custom(None, None)?;
        let cert_labels = ["target", "endpoint", "serial_number", "subject", "issuer"];

        let metric_not_before = IntGaugeVec::new(
            Opts::new("not_before", "Certificate not before timestamp")
                .namespace("tlsce")
                .subsystem("cert"),
            &cert_labels,
        )?;
        registry.register(Box::new(metric_not_before.clone()))?;
        let metric_not_after = IntGaugeVec::new(
            Opts::new("not_after", "Certificate not after timestamp")
                .namespace("tlsce")
                .subsystem("cert"),
            &cert_labels,
        )?;
        registry.register(Box::new(metric_not_after.clone()))?;

        Ok(Self {
            state: ExporterState {
                store,
                registry,
                metric_not_before,
                metric_not_after,
            },
        })
    }

    pub async fn run(&self) -> AnyResult<()> {
        let router = Router::new()
            .route("/metrics", get(Self::handle_metrics))
            .with_state(self.state.clone());

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 9880)).await?;
        axum::serve(listener, router).await?;
        Ok(())
    }

    async fn handle_metrics(state: State<ExporterState>) -> Result<String, StatusCode> {
        let store = state.store.read().await;

        for ep_state in store.endpoint_store.values() {
            for cert_id in &ep_state.cert_idents {
                let Some(cert) = store.cert_store.get(cert_id) else {
                    continue;
                };

                let label_values = [
                    ep_state
                        .target
                        .as_ref()
                        .map(|target| target.to_string())
                        .unwrap_or_default(),
                    ep_state.endpoint.to_string(),
                    cert.serial_number().to_string(),
                    cert.subject_common_name().unwrap_or_default(),
                    cert.issuer_common_name().unwrap_or_default(),
                ];
                // FIXME: Wait for array::each_ref() to be stabilized
                let label_values_ref = [
                    label_values[0].as_str(),
                    label_values[1].as_str(),
                    label_values[2].as_str(),
                    label_values[3].as_str(),
                    label_values[4].as_str(),
                ];

                let not_before = cert.not_before();
                let not_after = cert.not_after();

                match state
                    .metric_not_before
                    .get_metric_with_label_values(&label_values_ref)
                {
                    Ok(metric) => metric.set(not_before),
                    Err(e) => {
                        error!("Failed to get metric: {}", e);
                    }
                }
                match state
                    .metric_not_after
                    .get_metric_with_label_values(&label_values_ref)
                {
                    Ok(metric) => metric.set(not_after),
                    Err(e) => {
                        error!("Failed to get metric: {}", e);
                    }
                }
            }
        }

        let encoder = TextEncoder::new();
        let resp = encoder
            .encode_to_string(&state.registry.gather())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(resp)
    }
}
