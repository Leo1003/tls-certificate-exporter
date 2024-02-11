use super::FileContent;
use duration_str::deserialize_option_duration;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct ModuleConfig {
    #[serde(default)]
    pub extends: Vec<String>,

    #[serde(default, deserialize_with = "deserialize_option_duration")]
    pub timeout: Option<Duration>,

    #[serde(default)]
    pub trustedanchors: Option<FileContent>,

    #[serde(default)]
    pub certs: Option<FileContent>,

    #[serde(default)]
    pub key: Option<FileContent>,

    #[serde(default)]
    pub server_name: Option<String>,

    #[serde(default)]
    pub starttls: Option<Starttls>,

    #[serde(default)]
    pub insecure_skip_verify: Option<bool>,
}

impl ModuleConfig {
    pub fn extends_on(self, base_cfg: ModuleConfig) -> Self {
        Self {
            extends: self.extends,
            timeout: self.timeout.or(base_cfg.timeout),
            trustedanchors: self.trustedanchors.or(base_cfg.trustedanchors),
            certs: self.certs.or(base_cfg.certs),
            key: self.key.or(base_cfg.key),
            server_name: self.server_name.or(base_cfg.server_name),
            starttls: self.starttls.or(base_cfg.starttls),
            insecure_skip_verify: self.insecure_skip_verify.or(base_cfg.insecure_skip_verify),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Starttls {
    Ldap,
    Smtp,
    Imap,
    Pop3,
    Ftp,
    Xmpp,
    Nntp,
    Postgres,
}
