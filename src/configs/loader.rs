use super::ConnectionParameters;
use crate::{
    certificate_interceptor::CertificateInterceptor,
    configs::{FileContent, GlobalConfig, TargetConfig},
    error::ErrorReason,
    store::Target,
};
use anyhow::{Context, Result as AnyResult};
use futures::{future::OptionFuture, stream::FuturesUnordered, TryStreamExt};
use std::sync::Arc;
use tokio_rustls::rustls::{Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey};
use webpki::TrustAnchor;

#[derive(Clone, Debug)]
pub struct TargetParameter {
    pub target: Target,
    pub conn_params: ConnectionParameters,
}

impl TargetParameter {
    pub fn new(target: Target, conn_params: ConnectionParameters) -> Self {
        Self { target, conn_params }
    }

    pub fn build_tls_config(&self) -> AnyResult<(ClientConfig, Arc<CertificateInterceptor>)> {
        self.conn_params.build_tls_config()
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub default_parameters: ConnectionParameters,
    pub targets: Vec<TargetParameter>,
}

impl RuntimeConfig {
    pub async fn load_from_config(config: GlobalConfig) -> AnyResult<Self> {
        let tasks = config
            .trusted_anchors
            .into_iter()
            .map(|file| async { load_trusted_anchors(file).await })
            .collect::<FuturesUnordered<_>>();

        let trusted_anchors = tasks.try_concat().await?;

        let mut default_parameters = ConnectionParameters {
            timeout: Some(config.default_timeout),
            interval: Some(config.default_interval),
            trusted_anchors,
            ..Default::default()
        };
        if let Err(e) = default_parameters.load_system_roots() {
            warn!("Failed to load CA certificates from system: {}", e);
        };

        let tasks = config
            .targets
            .into_iter()
            .map(|config| async { TargetParameter::load_from_config(config).await })
            .collect::<FuturesUnordered<_>>();
        let targets: Vec<TargetParameter> = tasks.try_collect().await?;

        Ok(Self {
            default_parameters,
            targets,
        })
    }
}

