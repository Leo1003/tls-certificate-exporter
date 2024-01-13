use crossbeam::atomic::AtomicCell;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::{fmt::Debug, sync::Arc};
use tokio_rustls::rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};

/// If the certificate has issues, the connect will return Err.
/// Therefore, we need to get the certificates before verifying certificates.
pub struct CertificateInterceptor {
    certificates: AtomicCell<Option<Vec<CertificateDer<'static>>>>,
    verifier: Arc<WebPkiServerVerifier>,
    insecure_skip_verify: bool,
}

impl CertificateInterceptor {
    pub fn new(roots: Arc<RootCertStore>, insecure_skip_verify: bool) -> Self {
        Self::with_verifier(
            WebPkiServerVerifier::builder(roots).build().unwrap(),
            insecure_skip_verify,
        )
    }

    pub fn with_verifier(verifier: Arc<WebPkiServerVerifier>, insecure_skip_verify: bool) -> Self {
        Self {
            certificates: Default::default(),
            verifier,
            insecure_skip_verify,
        }
    }

    pub fn with_webpki_roots() -> Self {
        let mut root_certs = RootCertStore::empty();
        root_certs
            .roots
            .extend_from_slice(webpki_roots::TLS_SERVER_ROOTS);
        Self::new(Arc::new(root_certs), false)
    }

    pub fn get_certificates(&self) -> Option<Vec<CertificateDer<'static>>> {
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
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let mut certs = vec![end_entity.clone().into_owned()];
        certs.extend(intermediates.iter().map(|cert| cert.clone().into_owned()));

        self.certificates.store(Some(certs));

        if self.insecure_skip_verify {
            Ok(ServerCertVerified::assertion())
        } else {
            self.verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}
