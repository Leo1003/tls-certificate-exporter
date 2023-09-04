#[cfg(feature = "backtrace")]
use backtrace::Backtrace;
use std::fmt::{Display, Formatter};
use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
pub struct AppError {
    reason: ErrorReason,
    #[cfg(feature = "backtrace")]
    bt: Backtrace,
}

impl AppError {
    pub(crate) fn new(reason: ErrorReason) -> Self {
        Self {
            reason,
            #[cfg(feature = "backtrace")]
            bt: Backtrace::new(),
        }
    }
}

impl<E> From<E> for AppError
where
    E: Into<ErrorReason>,
{
    fn from(reason: E) -> Self {
        Self::new(reason.into())
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", &self.reason)
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.reason.source()
    }
}

#[derive(Debug, Error)]
pub enum ErrorReason {
    #[error("failed to load the configuration")]
    Config(#[from] config::ConfigError),
    #[error("IO error")]
    Io(#[from] std::io::Error),
    #[error("X509 certificate parsing error")]
    X509(#[from] x509_certificate::X509CertificateError),
    #[error("Domain name lookup error")]
    Resolver(#[from] trust_dns_resolver::error::ResolveError),
    #[error("Invalid endpoint")]
    InvalidEndpoint,
}
