use super::Endpoint;
use crate::cert::CertificateIdentifier;

#[derive(Clone, Debug)]
pub struct EndpointState {
    pub endpoint: Endpoint,
    pub cert_idents: Vec<CertificateIdentifier>,
    pub probe_result: Result<(), String>,
}

impl EndpointState {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            cert_idents: Default::default(),
            probe_result: Ok(()),
        }
    }
}
