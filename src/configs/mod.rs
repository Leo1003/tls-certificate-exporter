use anyhow::Result as AnyResult;
use config::{Config, Environment as ConfigEnv, File as ConfigFile};
use duration_str::{deserialize_duration, deserialize_option_duration};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, default::Default, hash::Hash, ops::Add, time::Duration};

mod application;
mod file_content;
mod file_store;
mod module;
mod parameters;
mod private_key;
mod resolved;

pub use application::ApplicationConfig;
pub use file_content::FileContent;
pub use file_store::*;
pub use module::{ModuleConfig, Starttls};
pub use parameters::ConnectionParameters;
pub use resolved::{resolve_module_config, ResolvedModuleConfig};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

const fn default_timeout() -> Duration {
    DEFAULT_TIMEOUT
}
