use crate::{
    configs::{FileContent, GlobalConfig, TargetConfig},
    error::{AppResult, ErrorReason},
};
use futures::{future::OptionFuture, stream::FuturesUnordered, TryStreamExt};
use tokio_rustls::rustls::{Certificate, OwnedTrustAnchor, PrivateKey};
use webpki::TrustAnchor;

use super::{Store, TargetDefaultConfig, TargetParameter};

impl Store {
    pub async fn load_from_config(config: GlobalConfig) -> AppResult<Self> {
        let tasks = config
            .trusted_anchors
            .into_iter()
            .map(|file| async { load_trusted_anchors(file).await })
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
            .map(|config| async { TargetParameter::load_from_config(config).await })
            .collect::<FuturesUnordered<_>>();
        let targets: Vec<TargetParameter> = tasks.try_collect().await?;

        Ok(Self {
            target_default,
            target_store: Default::default(),
            cert_store: Default::default(),
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

        Ok(Self {
            target: config.endpoint.parse()?,
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
