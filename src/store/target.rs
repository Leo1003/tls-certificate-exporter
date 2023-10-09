use crate::{
    certificate_interceptor::CertificateInterceptor,
    error::{AppError, AppResult, ErrorReason},
};
use chrono::{DateTime, Utc};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore,
};
use x509_certificate::X509Certificate;

use super::EndpointState;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl FromStr for Target {
    type Err = AppError;

    fn from_str(target: &str) -> Result<Self, Self::Err> {
        let (host, port) = target
            .rsplit_once(':')
            .ok_or(ErrorReason::InvalidEndpoint)?;
        let port: u16 = port.parse().map_err(|_| ErrorReason::InvalidEndpoint)?;

        Ok(Target {
            host: host.to_owned(),
            port,
        })
    }
}

impl Display for Target {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}:{}", self.host, self.port)
    }
}

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

#[derive(Clone, Debug, Default)]
pub struct TargetState {
    pub endpoints: Vec<EndpointState>,
    pub last_probe: Option<DateTime<Utc>>,
}
