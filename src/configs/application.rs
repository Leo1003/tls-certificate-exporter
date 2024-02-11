use super::{default_timeout, FileContent, ModuleConfig};
use anyhow::Result as AnyResult;
use config::{Config, Environment as ConfigEnv, File as ConfigFile};
use duration_str::deserialize_duration;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, default::Default, time::Duration};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ApplicationConfig {
    pub workers: Option<usize>,

    #[serde(default)]
    pub filecaching: FileCaching,

    #[serde(default)]
    pub modules: HashMap<String, ModuleConfig>,
}

impl ApplicationConfig {
    pub fn load_config() -> AnyResult<Self> {
        let cfg = Config::builder()
            .add_source(ConfigFile::with_name("/etc/tls-certificate-exporter/").required(false))
            .add_source(ConfigFile::with_name("config").required(false))
            .add_source(ConfigEnv::with_prefix("TLSCE").separator("_"))
            .build()?
            .try_deserialize()?;
        Ok(cfg)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum FileCaching {
    #[default]
    Preload,
    Lazy,
    None,
}
