use crate::error::AppResult;

use config::{Config, Environment, File};
use duration_str::{deserialize_duration, deserialize_option_duration};
use std::default::Default;
use std::time::Duration;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GlobalConfig {
    pub workers: Option<usize>,

    #[serde(default = "default_timeout", deserialize_with = "deserialize_duration")]
    pub default_timeout: Duration,

    #[serde(default = "default_interval", deserialize_with = "deserialize_duration")]
    pub default_interval: Duration,
    
    pub targets: Vec<TargetConfig>,
    
    pub trusted_anchors: Vec<FileContent>,
}

impl GlobalConfig {
    pub fn load_config() -> AppResult<Self> {
        let cfg = Config::builder()
            .add_source(File::with_name("config").required(false))
            .add_source(Environment::default().separator("."))
            .build()?
            .try_deserialize()?;
        Ok(cfg)
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            workers: None,
            default_timeout: default_timeout(),
            default_interval: default_interval(),
            targets: Vec::new(),
            trusted_anchors: Vec::new(),
        }
    }
}

const fn default_timeout() -> Duration {
    Duration::from_secs(3)
}

const fn default_interval() -> Duration {
    Duration::from_secs(600)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetConfig {
    pub endpoint: String,
    #[serde(default, deserialize_with = "deserialize_option_duration")]
    pub timeout: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_option_duration")]
    pub interval: Option<Duration>,
    pub tls_config: TlsConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TlsConfig {
    pub ca: Option<FileContent>,
    pub cert: Option<FileContent>,
    pub key: Option<FileContent>,
    pub server_name: Option<String>,
    pub insecure_skip_verify: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FileContent {
    Inline {
        #[serde(with = "serde_bytes")]
        content: Vec<u8>,
    },
    Path {
        path: Vec<String>,
    }
}

