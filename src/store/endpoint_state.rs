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
    pub cert_idents: Vec<CertificateIdentifier>,
    pub probe_result: bool,
}

impl EndpointState {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            cert_idents: Default::default(),
            probe_result: Default::default(),
        }
    }
}
