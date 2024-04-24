use thiserror::Error;

#[derive(Debug, Error)]
pub enum ErrorReason {
    #[error("failed to load the configuration")]
    Config(#[from] config::ConfigError),
    #[error("IO error")]
    Io(#[from] std::io::Error),
    #[error("X509 certificate parsing error")]
    X509(#[from] x509_certificate::X509CertificateError),
    #[error("Domain name lookup error")]
    Resolver(#[from] hickory_resolver::error::ResolveError),
    #[error("PEM encode/decode error")]
    PemError(#[from] pem::PemError),
    #[error("WebPKI error")]
    PkiError(#[from] webpki::Error),
    #[error("TLS error")]
    TlsError(#[from] tokio_rustls::rustls::Error),
    #[error("Invalid endpoint")]
    InvalidEndpoint,
    #[error("Missing private key")]
    MissingPrivateKey,
    #[error("File type mismatch")]
    FileTypeMismatch,
    #[error("Unknoen module")]
    UnknownModule,
    #[error("Unknown error")]
    Unknown,
}
