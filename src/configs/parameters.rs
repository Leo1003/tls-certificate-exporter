use super::{private_key::PrivateKey, FileContent};
use crate::{
    certificate_interceptor::CertificateInterceptor, error::ErrorReason,
};
use anyhow::Result as AnyResult;
use rustls_pki_types::CertificateDer;
use std::{io::Cursor, sync::Arc, time::Duration};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

#[derive(Clone, Debug)]
pub struct ConnectionParameters {
    pub timeout: Option<Duration>,

    pub trusted_anchors: RootCertStore,

    pub certs: Vec<CertificateDer<'static>>,

    pub key: Option<PrivateKey>,

    pub server_name: Option<String>,

    pub insecure_skip_verify: bool,
}

impl Default for ConnectionParameters {
    fn default() -> Self {
        Self {
            timeout: None,
            trusted_anchors: RootCertStore::empty(),
            certs: Vec::new(),
            key: None,
            server_name: None,
            insecure_skip_verify: false,
        }
    }
}

impl ConnectionParameters {
    pub fn build_tls_config(
        &self,
    ) -> AnyResult<(ClientConfig, Arc<CertificateInterceptor>)> {
        let builder = ClientConfig::builder();

        let root_certs = Arc::new(self.trusted_anchors.clone());

        let interceptor = Arc::new(CertificateInterceptor::new(
            root_certs,
            self.insecure_skip_verify,
        ));

        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(interceptor.clone());
        let config = if !self.certs.is_empty() {
            if let Some(key) = self.key.as_ref() {
                builder.with_client_auth_cert(
                    self.certs.clone(),
                    key.clone_key(),
                )?
            } else {
                return Err(ErrorReason::MissingPrivateKey.into());
            }
        } else {
            builder.with_no_client_auth()
        };

        Ok((config, interceptor))
    }

    pub fn merge(&self, default_params: &ConnectionParameters) -> Self {
        let mut p = self.clone();

        if p.trusted_anchors.is_empty() {
            p.trusted_anchors = default_params.trusted_anchors.clone();
        }
        if p.timeout.is_none() {
            p.timeout = default_params.timeout;
        }

        p
    }

    pub fn load_certificate(&mut self, der: &[u8]) -> AnyResult<()> {
        self.trusted_anchors.add(der.into())?;
        Ok(())
    }

    pub fn load_webpki_roots(&mut self) {
        self.trusted_anchors
            .roots
            .extend_from_slice(webpki_roots::TLS_SERVER_ROOTS);
    }

    pub fn load_system_roots(&mut self) -> AnyResult<()> {
        for cert in rustls_native_certs::load_native_certs()? {
            self.trusted_anchors.add(cert)?;
        }
        Ok(())
    }
}

async fn load_certificates(
    file: FileContent,
) -> AnyResult<Vec<CertificateDer<'static>>> {
    let data = file.load_file().await?;
    let mut buf = Cursor::new(data);
    let pems = rustls_pemfile::certs(&mut buf)
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    Ok(pems)
}

async fn load_private_key(file: FileContent) -> AnyResult<PrivateKey> {
    let data = file.load_file().await?;
    PrivateKey::load_from_pem(&data)
}
