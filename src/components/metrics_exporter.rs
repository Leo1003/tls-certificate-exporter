use anyhow::Result as AnyResult;
use axum::{extract::State, http::StatusCode, routing::get, Router};
use prometheus::{IntGaugeVec, Opts, Registry, TextEncoder};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::{net::TcpListener, sync::RwLock};

#[derive(Clone, Debug)]
struct ExporterState {
    pub registry: Registry,
    pub metric_not_before: IntGaugeVec,
    pub metric_not_after: IntGaugeVec,
}

#[derive(Clone, Debug)]
pub struct MetricsExporter {
    state: ExporterState,
}

impl MetricsExporter {
    pub fn new() -> AnyResult<Self> {
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

        let encoder = TextEncoder::new();
        let resp = encoder
            .encode_to_string(&state.registry.gather())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(resp)
    }
}
