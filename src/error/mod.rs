mod app;
mod http;
mod reason;

pub type AppResult<T> = Result<T, AppError>;
pub type HttpResult<T> = Result<T, HttpError>;

pub use app::AppError;
pub use http::HttpError;
pub use reason::ErrorReason;
