use anyhow::{Context, Result as AnyResult};
use config::{Config, Environment as ConfigEnv, File as ConfigFile};
use duration_str::{deserialize_duration, deserialize_option_duration};
use serde::{Deserialize, Serialize};
use std::{default::Default, ops::Add, time::Duration};

mod file_content;
mod parameters;

pub use file_content::FileContent;
pub use parameters::*;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GlobalConfig {
    pub workers: Option<usize>,

    #[serde(default = "default_timeout", deserialize_with = "deserialize_duration")]
    pub default_timeout: Duration,

    #[serde(default)]
    pub scheduler: SchedulerConfig,

    #[serde(default)]
    pub targets: Vec<TargetConfig>,

    #[serde(default)]
    pub trusted_anchors: Vec<FileContent>,
}

impl GlobalConfig {
    pub fn load_config() -> AnyResult<Self> {
        let cfg = Config::builder()
            .add_source(ConfigFile::with_name("/etc/tls-certificate-exporter/").required(false))
            .add_source(ConfigFile::with_name("config").required(false))
            .add_source(ConfigEnv::with_prefix("TLSCE").separator("."))
            .build()?
            .try_deserialize()?;
        Ok(cfg)
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            workers: Default::default(),
            default_timeout: default_timeout(),
            scheduler: Default::default(),
            targets: Default::default(),
            trusted_anchors: Default::default(),
        }
    }
}

const fn default_timeout() -> Duration {
    DEFAULT_TIMEOUT
}

const fn default_interval() -> Duration {
    DEFAULT_INTERVAL
}

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SchedulerConfig {
    #[serde(
        default = "default_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub interval: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            interval: default_interval(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SchedulerOverrideConfig {
    #[serde(default, deserialize_with = "deserialize_option_duration")]
    pub interval: Option<Duration>,
}

impl Add<&SchedulerConfig> for &SchedulerOverrideConfig {
    type Output = SchedulerConfig;

    fn add(self, rhs: &SchedulerConfig) -> Self::Output {
        SchedulerConfig {
            interval: self.interval.unwrap_or(rhs.interval),
        }
    }
}

impl Add<&SchedulerOverrideConfig> for &SchedulerOverrideConfig {
    type Output = SchedulerOverrideConfig;

    fn add(self, rhs: &SchedulerOverrideConfig) -> Self::Output {
        SchedulerOverrideConfig {
            interval: self.interval.or(rhs.interval),
        }
    }
}
