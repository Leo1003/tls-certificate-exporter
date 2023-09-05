use crate::error::{AppResult, ErrorReason};
use x509_certificate::X509Certificate;

#[derive(Clone, Debug, Default)]
pub struct ConfigState {
    pub workers: Option<usize>,
    pub targets: Vec<Target>,
    pub trusted_anchors: Vec<X509Certificate>,
}

#[derive(Clone, Debug)]
pub struct Target {}
