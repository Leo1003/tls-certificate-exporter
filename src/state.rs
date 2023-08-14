use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Clone, Debug, Default)]
pub struct ConfigState {
    pub workers: Option<usize>,
    pub targets: Vec<Target>,
    pub trusted_anchors: Vec<X509Certificate<'static>>,
}

#[derive(Clone, Debug)]
pub struct Target {
}
