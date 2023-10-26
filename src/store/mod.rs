use crate::{
    cert::{CertificateIdentifier, ParsedCertificate},
    error::{AppError, AppResult}, configs::DefaultParameters, prober::ProbeResult,
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
    pub target_store: HashMap<Target, TargetState>,
    pub cert_store: HashMap<CertificateIdentifier, ParsedCertificate>,
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
        certificates: impl IntoIterator<Item = ParsedCertificate>,
    ) -> AppResult<Vec<CertificateIdentifier>> {
        let certificates: Vec<(CertificateIdentifier, ParsedCertificate)> = certificates
            .into_iter()
            .map(|cert| {
                cert.certificate_identifier()
                    .map(|identifier| (identifier, cert))
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

    pub fn update_probe_result(&mut self, target: &Target, probe_results: Vec<ProbeResult>) -> AppResult<()> {
        let ep_states: Vec<EndpointState> = probe_results
            .into_iter()
            .map(|probe| {
                self
                    .add_certificates(probe.certificates)
                    .map(|cert_idents| EndpointState {
                        endpoint: probe.endpoint,
                        cert_idents,
                        probe_result: probe.probe_result,
                    })
            })
            .collect::<AppResult<_>>()?;

        self.update_endpoints(target, ep_states);
        Ok(())
    }

    fn update_endpoints(&mut self, target: &Target, ep_states: Vec<EndpointState>) {
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
