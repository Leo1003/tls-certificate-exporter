use crate::cert::{ParsedCertificate, CertificateIdentifier};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct CertStore {
    store: HashMap<CertificateIdentifier, ParsedCertificate>,
}
