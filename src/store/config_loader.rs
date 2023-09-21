use crate::{
    configs::{FileContent, GlobalConfig, TargetConfig},
    error::{AppResult, ErrorReason},
};
use futures::{future::OptionFuture, stream::FuturesUnordered, TryStreamExt};
use tokio_rustls::rustls::PrivateKey;
use x509_certificate::X509Certificate;

use super::{Store, Target, TargetDefaultConfig};

impl Store {
    pub async fn load_from_config(config: GlobalConfig) -> AppResult<Self> {
        let tasks = config
            .trusted_anchors
            .into_iter()
            .map(|file| async { load_certificates(file).await })
            .collect::<FuturesUnordered<_>>();

        let trusted_anchors = tasks.try_concat().await?;

        let target_default = TargetDefaultConfig {
            timeout: config.default_timeout,
            interval: config.default_interval,
            trusted_anchors,
        };

        let tasks = config
            .targets
            .into_iter()
            .map(|config| async { Target::load_from_config(config).await })
            .collect::<FuturesUnordered<_>>();
        let targets: Vec<Target> = tasks.try_collect().await?;

        Ok(Self {
            target_default,
            targets,
            cert_store: Default::default(),
            endpoint_store: Default::default(),
        })
    }
}

impl Target {
    pub async fn load_from_config(config: TargetConfig) -> AppResult<Self> {
        let ca = OptionFuture::from(
            config
                .tls_config
                .ca
                .map(|file| async { load_certificates(file).await }),
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

        Ok(Self {
            endpoint: config.endpoint,
            timeout: config.timeout,
            interval: config.interval,
            ca,
            cert,
            key,
            server_name: config.tls_config.server_name,
            insecure_skip_verify: config.tls_config.insecure_skip_verify,
        })
    }
}

async fn load_certificate(file: FileContent) -> AppResult<X509Certificate> {
    let data = file.load_file().await?;
    let pem = pem::parse(data)?;

    match pem.tag() {
        "CERTIFICATE" => Ok(X509Certificate::from_der(pem.contents())?),
        _ => Err(ErrorReason::InvalidPemTag.into()),
    }
}

async fn load_certificates(file: FileContent) -> AppResult<Vec<X509Certificate>> {
    let data = file.load_file().await?;
    let pems = pem::parse_many(&data)?;

    let mut certs = Vec::new();
    for pem in pems {
        match pem.tag() {
            "CERTIFICATE" => {
                let cert = X509Certificate::from_der(pem.contents())?;
                certs.push(cert);
            }
            _ => return Err(ErrorReason::InvalidPemTag.into()),
        }
    }

    Ok(certs)
}

async fn load_private_key(file: FileContent) -> AppResult<PrivateKey> {
    let data = file.load_file().await?;
    let pem = pem::parse(data)?;

    match pem.tag() {
        "PRIVATE KEY" => Ok(PrivateKey(pem.into_contents())),
        _ => Err(ErrorReason::InvalidPemTag.into()),
    }
}
