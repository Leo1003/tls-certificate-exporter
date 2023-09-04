use x509_certificate::X509Certificate;
use crate::{
    cert::{CertificateIdentifier, ParsedCertificate},
    error::AppResult,
    state::Endpoint,
};
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct Store {
    cert_store: HashMap<CertificateIdentifier, ParsedCertificate>,
}

impl Store {
    pub fn add_certificates(&mut self, buf: &[u8]) -> AppResult<()> {
        let certificates = X509Certificate::from_pem_multiple(buf)?
            .into_iter()
            .map(ParsedCertificate);
        for cert in certificates {
            let identifier = cert.certificate_identifier()?;
            self.cert_store.entry(identifier).or_insert(cert);
        }
        Ok(())
    }
}
