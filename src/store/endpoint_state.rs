use super::{Endpoint, Target};
use crate::cert::CertificateIdentifier;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct EndpointState {
    pub endpoint: Endpoint,
    pub target: Option<Target>,
    pub cert_idents: Vec<CertificateIdentifier>,
    pub probe_result: Result<(), String>,
    pub last_update: Option<DateTime<Utc>>,
}

impl EndpointState {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            target: None,
            cert_idents: Default::default(),
            probe_result: Ok(()),
            last_update: None,
        }
    }

    pub fn with_target(endpoint: Endpoint, target: Target) -> Self {
        Self {
            endpoint,
            target: Some(target),
            cert_idents: Default::default(),
            probe_result: Ok(()),
            last_update: None,
        }
    }
}
