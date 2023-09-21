use crate::error::{AppError, AppResult, ErrorReason};
use std::time::Duration;
use tokio_rustls::rustls::PrivateKey;
use x509_certificate::X509Certificate;

#[derive(Clone, Debug)]
pub struct TargetDefaultConfig {
    pub timeout: Duration,
    pub interval: Duration,
    pub trusted_anchors: Vec<X509Certificate>,
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
pub struct Target {
    pub endpoint: String,

    pub timeout: Option<Duration>,

    pub interval: Option<Duration>,

    pub ca: Vec<X509Certificate>,

    pub cert: Option<X509Certificate>,

    pub key: Option<PrivateKey>,

    pub server_name: Option<String>,

    pub insecure_skip_verify: bool,
}
