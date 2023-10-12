use crate::{
    cert::{CertificateIdentifier, ParsedCertificate},
    error::{AppError, AppResult}, configs::TargetDefaultConfig,
};
use chrono::Utc;
use std::collections::HashMap;
use tokio_rustls::rustls::Certificate;
use x509_certificate::X509Certificate;

mod endpoint;
mod endpoint_state;
mod target;

pub use endpoint::Endpoint;
pub use endpoint_state::EndpointState;
pub use target::{Target, TargetState};

#[derive(Clone, Debug, Default)]
pub struct Store {
    pub target_default: TargetDefaultConfig,
    pub target_store: HashMap<Target, TargetState>,
    //pub endpoint_store: HashMap<Endpoint, EndpointState>,
    pub cert_store: HashMap<CertificateIdentifier, ParsedCertificate>,
}

impl Store {
    pub fn with_config(target_default: TargetDefaultConfig) -> Self {
        Self {
            target_default,
            ..Default::default()
        }
    }

    pub fn add_pem_certificates(&mut self, buf: &[u8]) -> AppResult<()> {
        let certificates = X509Certificate::from_pem_multiple(buf)?
            .into_iter()
            .map(ParsedCertificate);
        for cert in certificates {
            let identifier = cert.certificate_identifier()?;
            self.cert_store.entry(identifier).or_insert(cert);
        }
        Ok(())
    }

    pub fn add_certificates(
        &mut self,
        certificates: impl IntoIterator<Item = Certificate>,
    ) -> AppResult<Vec<CertificateIdentifier>> {
        let certificates = certificates
            .into_iter()
            .map(X509Certificate::from_der)
            .map(|cert| cert.map(ParsedCertificate))
            .flat_map(|cert| {
                cert.map(|cert| {
                    cert.certificate_identifier()
                        .map(|identifier| (identifier, cert))
                })
                .map_err(AppError::from)
            })
            .collect::<AppResult<Vec<_>>>()?;

        let identifiers: Vec<CertificateIdentifier> = certificates
            .into_iter()
            .map(|(identifier, cert)| {
                self.cert_store.entry(identifier.clone()).or_insert(cert);
                identifier
            })
            .collect();

        Ok(identifiers)
    }

    pub fn update_probe_result(&mut self, target: &Target, ep_states: Vec<EndpointState>) {
        let target_state = TargetState {
            endpoints: ep_states,
            last_probe: Some(Utc::now()),
        };

        self.target_store.insert(target.clone(), target_state);
    }

    pub fn clear(&mut self) {
        self.cert_store.clear();
        self.target_store.clear();
    }
}
