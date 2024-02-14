use crate::error::{AppError, ErrorReason};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl FromStr for Target {
    type Err = AppError;

    fn from_str(target: &str) -> Result<Self, Self::Err> {
        let (host, port) = target
            .rsplit_once(':')
            .ok_or(ErrorReason::InvalidEndpoint)?;
        let port: u16 =
            port.parse().map_err(|_| ErrorReason::InvalidEndpoint)?;

        Ok(Target {
            host: host.to_owned(),
            port,
        })
    }
}

impl Display for Target {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}:{}", self.host, self.port)
    }
}
