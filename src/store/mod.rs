use crate::{
    cert::{CertificateIdentifier, ParsedCertificate},
    error::{AppError, AppResult, ErrorReason},
};
use chrono::Utc;
use std::collections::HashMap;
use tokio_rustls::rustls::Certificate;
use x509_certificate::X509Certificate;

mod config_loader;
mod endpoint;
mod endpoint_state;
mod target;

pub use endpoint::Endpoint;
pub use endpoint_state::EndpointState;
pub use target::{Target, TargetDefaultConfig};

#[derive(Clone, Debug, Default)]
pub struct Store {
    pub target_default: TargetDefaultConfig,
    pub targets: Vec<Target>,
    pub cert_store: HashMap<CertificateIdentifier, ParsedCertificate>,
    pub endpoint_store: HashMap<Endpoint, EndpointState>,
}

impl Store {
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
            //     .collect::<Result<Vec<_>, X509CertificateError>>()?;
            // let with_identifier = certificates
            //     .into_iter()
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

    pub fn update_endpoint_probe_result(
        &mut self,
        endpoint: &Endpoint,
        certificates: impl IntoIterator<Item = Certificate>,
        successful: bool,
    ) -> AppResult<&mut EndpointState> {
        let identifiers = self.add_certificates(certificates.into_iter())?;

        let Some(state) = self.endpoint_store.get_mut(endpoint) else {
            return Err(ErrorReason::InvalidEndpoint.into());
        };

        state.cert_idents = identifiers;
        state.last_probe = Some(Utc::now());
        state.probe_result = successful;

        Ok(state)
    }

    pub fn clear(&mut self) {
        self.cert_store.clear();
        self.endpoint_store.clear();
    }
}
