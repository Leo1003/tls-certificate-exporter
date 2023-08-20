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
    where E: Into<ErrorReason> {
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
}