use crossbeam::atomic::AtomicCell;
use std::{fmt::Debug, time::SystemTime};
use tokio_rustls::rustls::{
    client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier},
    Certificate, OwnedTrustAnchor, RootCertStore, ServerName,
};

/// If the certificate has issues, the connect will return Err.
/// Therefore, we need to get the certificates before verifying certificates.
pub struct CertificateInterceptor {
    certificates: AtomicCell<Option<Vec<Certificate>>>,
    verifier: WebPkiVerifier,
    insecure_skip_verify: bool,
}

impl CertificateInterceptor {
    pub fn new(roots: RootCertStore, insecure_skip_verify: bool) -> Self {
        Self::with_verifier(WebPkiVerifier::new(roots, None), insecure_skip_verify)
    }

    pub fn with_verifier(verifier: WebPkiVerifier, insecure_skip_verify: bool) -> Self {
        Self {
            certificates: Default::default(),
            verifier,
            insecure_skip_verify,
        }
    }

    pub fn with_webpki_roots() -> Self {
        let mut root_certs = RootCertStore::empty();
        root_certs.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        Self::new(root_certs, false)
    }

    pub fn get_certificates(&self) -> Option<Vec<Certificate>> {
        self.certificates.take()
    }
}

impl Debug for CertificateInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateInterceptor")
            .field("certificates", &"<Redacted>")
            .field("verifier", &"<Redacted>")
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .finish()
    }
}

impl ServerCertVerifier for CertificateInterceptor {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let mut certs = vec![end_entity.clone()];
        certs.extend_from_slice(intermediates);

        self.certificates.store(Some(certs));

        if self.insecure_skip_verify {
            Ok(ServerCertVerified::assertion())
        } else {
            self.verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                scts,
                ocsp_response,
                now,
            )
        }
    }
}
