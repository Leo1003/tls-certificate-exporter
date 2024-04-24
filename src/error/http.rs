use axum::{
    body::Body,
    http::{Response, StatusCode},
    response::IntoResponse,
};
use std::{
    error::Error,
    fmt::{Display, Formatter},
};

#[derive(Debug)]
pub struct HttpError {
    status_code: StatusCode,
    error: Box<dyn Error + Send + Sync + 'static>,
}

impl HttpError {
    pub fn new(status_code: StatusCode, error: impl Error + Send + Sync + 'static) -> Self {
        Self {
            status_code,
            error: Box::new(error),
        }
    }
}

impl From<anyhow::Error> for HttpError
{
    fn from(error: anyhow::Error) -> Self {
        Self {
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            error: error.into(),
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response<Body> {
        (self.status_code, self.error.to_string()).into_response()
    }
}

impl Display for HttpError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Error for HttpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.error)
    }
}
