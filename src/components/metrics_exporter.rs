use anyhow::Result as AnyResult;
use prometheus::{IntGaugeVec, Opts, Registry, TextEncoder};

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
        let cert_labels =
            ["target", "endpoint", "serial_number", "subject", "issuer"];

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
}
