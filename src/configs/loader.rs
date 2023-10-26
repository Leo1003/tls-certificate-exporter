use super::{ConnectionParameters, DefaultParameters};
use crate::{
    certificate_interceptor::CertificateInterceptor,
    configs::{FileContent, GlobalConfig, TargetConfig},
    error::{AppResult, ErrorReason},
    store::Target,
};
use futures::{future::OptionFuture, stream::FuturesUnordered, TryStreamExt};
use std::sync::Arc;
use tokio_rustls::rustls::{Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey};
use webpki::TrustAnchor;

#[derive(Clone, Debug)]
pub struct TargetParameter {
    pub target: Target,
    pub parameters: ConnectionParameters,
}

impl TargetParameter {
    pub fn new(target: Target, parameters: ConnectionParameters) -> Self {
        Self { target, parameters }
    }

    pub fn build_tls_config(&self) -> AppResult<(ClientConfig, Arc<CertificateInterceptor>)> {
        self.parameters.build_tls_config()
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub default_parameters: DefaultParameters,
    pub targets: Vec<TargetParameter>,
}

impl RuntimeConfig {
    pub async fn load_from_config(config: GlobalConfig) -> AppResult<Self> {
        let tasks = config
            .trusted_anchors
            .into_iter()
            .map(|file| async { load_trusted_anchors(file).await })
            .collect::<FuturesUnordered<_>>();

        let trusted_anchors = tasks.try_concat().await?;

        let default_parameters = DefaultParameters {
            timeout: config.default_timeout,
            interval: config.default_interval,
            trusted_anchors,
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

impl TargetParameter {
    pub async fn load_from_config(config: TargetConfig) -> AppResult<Self> {
        let ca = OptionFuture::from(
            config
                .tls_config
                .ca
                .map(|file| async { load_trusted_anchors(file).await }),
        )
        .await
        .transpose()?
        .unwrap_or_default();

        let cert = OptionFuture::from(
            config
                .tls_config
                .cert
                .map(|file| async { load_certificate(file).await }),
        )
        .await
        .transpose()?;

        let key = OptionFuture::from(
            config
                .tls_config
                .key
                .map(|file| async { load_private_key(file).await }),
        )
        .await
        .transpose()?;

        let parameters = ConnectionParameters {
            timeout: config.timeout,
            interval: config.interval,
            ca,
            cert,
            key,
            server_name: config.tls_config.server_name,
            insecure_skip_verify: config.tls_config.insecure_skip_verify,
        };

        Ok(Self::new(config.endpoint.parse()?, parameters))
    }
}

async fn load_certificate(file: FileContent) -> AppResult<Certificate> {
    let data = file.load_file().await?;
    let pem = pem::parse(data)?;

    match pem.tag() {
        "CERTIFICATE" => Ok(Certificate(pem.into_contents())),
        _ => Err(ErrorReason::InvalidPemTag.into()),
    }
}

async fn load_trusted_anchors(file: FileContent) -> AppResult<Vec<OwnedTrustAnchor>> {
    let data = file.load_file().await?;
    let pems = pem::parse_many(&data)?;

    let mut anchors = Vec::new();
    for pem in pems {
        match pem.tag() {
            "CERTIFICATE" => {
                let cert = TrustAnchor::try_from_cert_der(pem.contents())?;
                anchors.push(OwnedTrustAnchor::from_subject_spki_name_constraints(
                    cert.subject,
                    cert.spki,
                    cert.name_constraints,
                ));
            }
            _ => return Err(ErrorReason::InvalidPemTag.into()),
        }
    }

    Ok(anchors)
}

async fn load_private_key(file: FileContent) -> AppResult<PrivateKey> {
    let data = file.load_file().await?;
    let pem = pem::parse(data)?;

    match pem.tag() {
        "PRIVATE KEY" => Ok(PrivateKey(pem.into_contents())),
        _ => Err(ErrorReason::InvalidPemTag.into()),
    }
}
