use anyhow::Result as AnyResult;
use duration_str::{deserialize_duration, deserialize_option_duration};
use serde::{Deserialize, Serialize};
use std::{default::Default, time::Duration};

use super::{SchedulerOverrideConfig, FileContent};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetConfig {
    pub target: String,
    #[serde(default, deserialize_with = "deserialize_option_duration")]
    pub timeout: Option<Duration>,
    #[serde(default, flatten)]
    pub schedule_config: SchedulerOverrideConfig,
    #[serde(default)]
    pub tls_config: TargetTlsConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TargetTlsConfig {
    #[serde(default)]
    pub ca: Option<FileContent>,
    #[serde(default)]
    pub cert: Option<FileContent>,
    #[serde(default)]
    pub key: Option<FileContent>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure_skip_verify: bool,
}
