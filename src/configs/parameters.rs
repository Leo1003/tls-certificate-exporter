use crate::certificate_interceptor::CertificateInterceptor;
use anyhow::{Context, Result as AnyResult};
use std::{sync::Arc, time::Duration};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore,
};
use webpki::TrustAnchor;

#[derive(Clone, Debug, Default)]
pub struct ConnectionParameters {
    pub timeout: Option<Duration>,

    pub interval: Option<Duration>,

    pub trusted_anchors: Vec<OwnedTrustAnchor>,

    pub cert: Option<Certificate>,

    pub key: Option<PrivateKey>,

    pub server_name: Option<String>,

    pub insecure_skip_verify: bool,
}

impl ConnectionParameters {
    pub fn build_tls_config(&self) -> AnyResult<(ClientConfig, Arc<CertificateInterceptor>)> {
        let builder = ClientConfig::builder().with_safe_defaults();

        let root_certs = RootCertStore {
            roots: self.trusted_anchors.clone(),
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

    pub fn merge(&self, default_params: &ConnectionParameters) -> Self {
        let mut p = self.clone();

        if p.trusted_anchors.is_empty() {
            p.trusted_anchors = default_params.trusted_anchors.clone();
        }
        if p.timeout.is_none() {
            p.timeout = default_params.timeout;
        }
        if p.interval.is_none() {
            p.interval = default_params.interval;
        }

        p
    }

    pub fn load_certificate(&mut self, der: &[u8]) -> AnyResult<()> {
        let ta = TrustAnchor::try_from_cert_der(der)?;
        self.trusted_anchors
            .push(OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            ));
        Ok(())
    }

    pub fn load_webpki_roots(&mut self) {
        self.trusted_anchors
            .extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
    }

    pub fn load_system_roots(&mut self) -> AnyResult<()> {
        for cert in rustls_native_certs::load_native_certs()? {
            self.load_certificate(&cert.0)?;
        }
        Ok(())
    }
}
