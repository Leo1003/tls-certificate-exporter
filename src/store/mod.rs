use crate::{
    cert::{CertificateIdentifier, ParsedCertificate},
    prober::ProbeResult,
};
use anyhow::{Context, Result as AnyResult};
use chrono::Utc;
use std::collections::HashMap;
use x509_certificate::X509Certificate;

mod endpoint;
mod endpoint_state;
mod target;

pub use endpoint::Endpoint;
pub use endpoint_state::EndpointState;
pub use target::{Target, TargetState};

#[derive(Clone, Debug, Default)]
pub struct Store {
    //pub target_store: HashMap<Target, TargetState>,
    pub endpoint_store: HashMap<Endpoint, EndpointState>,
    pub cert_store: HashMap<CertificateIdentifier, ParsedCertificate>,
}

impl Store {
    pub fn add_pem_certificates(&mut self, buf: &[u8]) -> AnyResult<()> {
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
    ) -> AnyResult<Vec<CertificateIdentifier>> {
        let certificates: Vec<(CertificateIdentifier, ParsedCertificate)> = certificates
            .into_iter()
            .map(|cert| {
                cert.certificate_identifier()
                    .map(|identifier| (identifier, cert))
            })
            .collect::<AnyResult<Vec<_>>>()?;

        let identifiers: Vec<CertificateIdentifier> = certificates
            .into_iter()
            .map(|(identifier, cert)| {
                self.cert_store.entry(identifier.clone()).or_insert(cert);
                identifier
            })
            .collect();

        Ok(identifiers)
    }

    pub fn update_probe_result(
        &mut self,
        target: &Target,
        probe_results: Vec<ProbeResult>,
    ) -> AnyResult<()> {
        let ep_states: Vec<EndpointState> = probe_results
            .into_iter()
            .map(|probe| {
                self.add_certificates(probe.certificates)
                    .map(|cert_idents| EndpointState {
                        endpoint: probe.endpoint,
                        cert_idents,
                        probe_result: probe.probe_result,
                        target: Some(target.clone()),
                        last_update: Some(Utc::now()),
                    })
            })
            .collect::<AnyResult<_>>()?;

        self.update_endpoints(target, ep_states);
        Ok(())
    }

    fn update_endpoints(&mut self, target: &Target, ep_states: Vec<EndpointState>) {
        self.endpoint_store
            .extend(ep_states.into_iter().map(|ep| (ep.endpoint.clone(), ep)));
    }

    pub fn clear(&mut self) {
        self.cert_store.clear();
        self.endpoint_store.clear();
    }
}
