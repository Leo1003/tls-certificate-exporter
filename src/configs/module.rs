use super::FileSource;
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
    pub trustedanchors: Option<FileSource>,

    #[serde(default)]
    pub certs: Option<FileSource>,

    #[serde(default)]
    pub key: Option<FileSource>,

    #[serde(default)]
    pub server_name: Option<String>,

    #[serde(default)]
    pub starttls: Option<Starttls>,

    #[serde(default)]
    pub insecure_skip_verify: Option<bool>,
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
