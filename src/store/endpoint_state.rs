use super::Endpoint;
use crate::{
    cert::CertificateIdentifier,
    certificate_interceptor::CertificateInterceptor,
    error::{AppError, AppResult, ErrorReason},
};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

#[derive(Clone, Debug)]
pub struct EndpointState {
    pub endpoint: Endpoint,
    pub tls_config: Arc<ClientConfig>,
    pub interceptor: Arc<CertificateInterceptor>,
    pub cert_idents: Vec<CertificateIdentifier>,
    pub last_probe: Option<DateTime<Utc>>,
    pub probe_result: bool,
}

impl EndpointState {
    pub fn new(
        endpoint: Endpoint,
        mut tls_config: ClientConfig,
        root_certs: RootCertStore,
    ) -> Self {
        let interceptor = Arc::new(CertificateInterceptor::new(root_certs));
        tls_config
            .dangerous()
            .set_certificate_verifier(interceptor.clone());

        Self {
            endpoint,
            tls_config: Arc::new(tls_config),
            interceptor,
            cert_idents: Default::default(),
            last_probe: Default::default(),
            probe_result: Default::default(),
        }
    }

    pub fn with_webpki_defaults(endpoint: Endpoint) -> Self {
        let interceptor = Arc::new(CertificateInterceptor::with_webpki_roots());

        let tls_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(interceptor.clone())
            .with_no_client_auth();

        Self {
            endpoint,
            tls_config: Arc::new(tls_config),
            interceptor,
            cert_idents: Default::default(),
            last_probe: Default::default(),
            probe_result: Default::default(),
        }
    }
}
