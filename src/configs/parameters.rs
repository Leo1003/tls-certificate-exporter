use super::{FileContent, GlobalConfig, TargetConfig};
use crate::{certificate_interceptor::CertificateInterceptor, error::ErrorReason};
use anyhow::{Context, Result as AnyResult};
use futures::prelude::*;
use futures::{future::OptionFuture, stream::FuturesUnordered};
use std::{sync::Arc, time::Duration};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore,
};
use webpki::TrustAnchor;

#[derive(Clone, Debug, Default)]
pub struct ConnectionParameters {
    pub timeout: Option<Duration>,

    pub trusted_anchors: Vec<OwnedTrustAnchor>,

    pub cert: Option<Certificate>,

    pub key: Option<PrivateKey>,

    pub server_name: Option<String>,

    pub insecure_skip_verify: bool,
}

impl ConnectionParameters {
    pub fn build_tls_config(&self) -> AnyResult<(ClientConfig, Arc<CertificateInterceptor>)> {
        let builder = ClientConfig::builder().with_safe_defaults();

        let root_certs = RootCertStore {
            roots: self.trusted_anchors.clone(),
        };

        let interceptor = Arc::new(CertificateInterceptor::new(
            root_certs,
            self.insecure_skip_verify,
        ));

        let builder = builder.with_custom_certificate_verifier(interceptor.clone());
        let config = if let Some((cert, key)) = self.cert.as_ref().zip(self.key.as_ref()) {
            builder.with_client_auth_cert(vec![cert.clone()], key.clone())?
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
        let ta = TrustAnchor::try_from_cert_der(der)?;
        self.trusted_anchors
            .push(OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            ));
        Ok(())
    }

    pub fn load_webpki_roots(&mut self) {
        self.trusted_anchors
            .extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
    }

    pub fn load_system_roots(&mut self) -> AnyResult<()> {
        for cert in rustls_native_certs::load_native_certs()? {
            self.load_certificate(&cert.0)?;
        }
        Ok(())
    }

    pub async fn load_from_global_config(config: &GlobalConfig) -> AnyResult<Self> {
        let tasks = config
            .trusted_anchors
            .clone()
            .into_iter()
            .map(|file| async { load_trusted_anchors(file).await })
            .collect::<FuturesUnordered<_>>();

        let trusted_anchors = tasks.try_concat().await?;

        let mut default_parameters = ConnectionParameters {
            timeout: Some(config.default_timeout),
            trusted_anchors,
            ..Default::default()
        };
        if let Err(e) = default_parameters.load_system_roots() {
            warn!("Failed to load CA certificates from system: {}", e);
        };

        Ok(default_parameters)
    }

    pub async fn load_from_target_config(target_config: &TargetConfig) -> AnyResult<Self> {
        let trusted_anchors = OptionFuture::from(
            target_config
                .tls_config
                .ca
                .clone()
                .map(|file| async { load_trusted_anchors(file).await }),
        )
        .await
        .transpose()?
        .unwrap_or_default();

        let cert = OptionFuture::from(
            target_config
                .tls_config
                .cert
                .clone()
                .map(|file| async { load_certificate(file).await }),
        )
        .await
        .transpose()?;

        let key = OptionFuture::from(
            target_config
                .tls_config
                .key
                .clone()
                .map(|file| async { load_private_key(file).await }),
        )
        .await
        .transpose()?;

        Ok(Self {
            timeout: target_config.timeout,
            trusted_anchors,
            cert,
            key,
            server_name: target_config.tls_config.server_name.clone(),
            insecure_skip_verify: target_config.tls_config.insecure_skip_verify,
        })
    }
}

async fn load_certificate(file: FileContent) -> AnyResult<Certificate> {
    let data = file.load_file().await?;
    let pem = pem::parse(data)?;

    match pem.tag() {
        "CERTIFICATE" => Ok(Certificate(pem.into_contents())),
        _ => Err(ErrorReason::InvalidPemTag.into()),
    }
}

async fn load_trusted_anchors(file: FileContent) -> AnyResult<Vec<OwnedTrustAnchor>> {
    let data = file.load_file().await?;
    let pems = pem::parse_many(&data)?;

    let mut anchors = Vec::new();
    for pem in pems {
        match pem.tag() {
            "CERTIFICATE" => {
                let cert = TrustAnchor::try_from_cert_der(pem.contents())?;
                anchors.push(OwnedTrustAnchor::from_subject_spki_name_constraints(
                    cert.subject,
                    cert.spki,
                    cert.name_constraints,
                ));
            }
            _ => return Err(ErrorReason::InvalidPemTag.into()),
        }
    }

    Ok(anchors)
}

async fn load_private_key(file: FileContent) -> AnyResult<PrivateKey> {
    let data = file.load_file().await?;
    let pem = pem::parse(data)?;

    match pem.tag() {
        "PRIVATE KEY" => Ok(PrivateKey(pem.into_contents())),
        _ => Err(ErrorReason::InvalidPemTag.into()),
    }
}
