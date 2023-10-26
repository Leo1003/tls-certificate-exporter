use crate::{certificate_interceptor::CertificateInterceptor, error::AppResult};
use std::{sync::Arc, time::Duration};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore,
};

#[derive(Clone, Debug)]
pub struct DefaultParameters {
    pub timeout: Duration,
    pub interval: Duration,
    pub trusted_anchors: Vec<OwnedTrustAnchor>,
}

impl Default for DefaultParameters {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            interval: Duration::from_secs(600),
            trusted_anchors: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConnectionParameters {
    pub timeout: Option<Duration>,

    pub interval: Option<Duration>,

    pub ca: Vec<OwnedTrustAnchor>,

    pub cert: Option<Certificate>,

    pub key: Option<PrivateKey>,

    pub server_name: Option<String>,

    pub insecure_skip_verify: bool,
}

impl ConnectionParameters {
    pub fn build_tls_config(&self) -> AppResult<(ClientConfig, Arc<CertificateInterceptor>)> {
        let builder = ClientConfig::builder().with_safe_defaults();

        let root_certs = RootCertStore {
            roots: self.ca.clone(),
        };

        let interceptor = Arc::new(CertificateInterceptor::new(
            root_certs,
            self.insecure_skip_verify,
        ));

        let builder = builder.with_custom_certificate_verifier(interceptor.clone());
        let config = if let Some((cert, key)) = self.cert.as_ref().zip(self.key.as_ref()) {
            builder.with_client_auth_cert(vec![cert.clone()], key.clone())?
        } else {
            builder.with_no_client_auth()
        };

        Ok((config, interceptor))
    }

    pub fn load_webpki_roots(&mut self) {
        self.ca
            .extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
    }

    pub fn load_system_roots(&mut self) -> AppResult<()> {

        Ok(())
    }
}
