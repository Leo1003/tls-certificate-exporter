use crate::{
    certificate_interceptor::CertificateInterceptor,
    configs::{FileContent, GlobalConfig, TargetConfig},
    error::{AppError, AppResult, ErrorReason},
    store::Target,
};
use futures::{future::OptionFuture, stream::FuturesUnordered, TryStreamExt};
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore,
};
use webpki::TrustAnchor;

#[derive(Clone, Debug)]
pub struct TargetDefaultConfig {
    pub timeout: Duration,
    pub interval: Duration,
    pub trusted_anchors: Vec<OwnedTrustAnchor>,
}

impl Default for TargetDefaultConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            interval: Duration::from_secs(600),
            trusted_anchors: Default::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TargetParameter {
    pub target: Target,

    pub timeout: Option<Duration>,

    pub interval: Option<Duration>,

    pub ca: Vec<OwnedTrustAnchor>,

    pub cert: Option<Certificate>,

    pub key: Option<PrivateKey>,

    pub server_name: Option<String>,

    pub insecure_skip_verify: bool,
}

impl TargetParameter {
    pub fn build_tls_config(&self) -> AppResult<(ClientConfig, Arc<CertificateInterceptor>)> {
        let builder = ClientConfig::builder().with_safe_defaults();

        let root_certs = RootCertStore {
            roots: self.ca.clone(),
        };

        let interceptor = Arc::new(CertificateInterceptor::new(
            root_certs,
            self.insecure_skip_verify,
        ));

        let builder = builder.with_custom_certificate_verifier(interceptor.clone());
        let config = if let Some((cert, key)) = self.cert.as_ref().zip(self.key.as_ref()) {
            builder.with_client_auth_cert(vec![cert.clone()], key.clone())?
        } else {
            builder.with_no_client_auth()
        };

        Ok((config, interceptor))
    }
}

impl FromStr for TargetParameter {
    type Err = AppError;

    fn from_str(target: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            target: target.parse()?,
            timeout: Default::default(),
            interval: Default::default(),
            ca: Default::default(),
            cert: Default::default(),
            key: Default::default(),
            server_name: Default::default(),
            insecure_skip_verify: Default::default(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub target_default: TargetDefaultConfig,
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
