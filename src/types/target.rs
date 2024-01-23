use super::EndpointState;
use crate::{
    configs::{ConnectionParameters, SchedulerOverrideConfig},
    error::{AppError, ErrorReason},
};
use chrono::{DateTime, Utc};
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
        let port: u16 = port.parse().map_err(|_| ErrorReason::InvalidEndpoint)?;

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

#[derive(Clone, Debug, Default)]
pub struct TargetState {
    pub endpoints: Vec<EndpointState>,
    pub conn_params: ConnectionParameters,
    pub schedule_config: SchedulerOverrideConfig,
    pub last_probe: Option<DateTime<Utc>>,
    pub next_probe: Option<DateTime<Utc>>,
}
