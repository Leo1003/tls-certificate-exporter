use crate::error::ErrorReason;
use anyhow::Result as AnyResult;
use rustls_pki_types::PrivateKeyDer;
use std::{
    io::Cursor,
    ops::{Deref, DerefMut},
};

/// Private key with Clone
#[derive(Debug)]
pub struct PrivateKey(PrivateKeyDer<'static>);

impl PrivateKey {
    pub fn load_from_pem(data: &[u8]) -> AnyResult<Self> {
        let mut buf = Cursor::new(data);
        let key = rustls_pemfile::private_key(&mut buf)?.ok_or(ErrorReason::MissingPrivateKey)?;
        Ok(Self(key))
    }
}

impl Deref for PrivateKey {
    type Target = PrivateKeyDer<'static>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PrivateKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<PrivateKey> for PrivateKeyDer<'static> {
    fn from(val: PrivateKey) -> Self {
        val.0
    }
}

impl From<PrivateKeyDer<'static>> for PrivateKey {
    fn from(key: PrivateKeyDer<'static>) -> Self {
        Self(key)
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self(self.0.clone_key())
    }
}
