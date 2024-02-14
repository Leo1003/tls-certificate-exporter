use crate::{
    certificate_interceptor::CertificateInterceptor,
    configs::{
        resolve_module_config, ApplicationConfig, FileStore, FileType,
        ResolvedModuleConfig,
    },
    error::ErrorReason,
};
use anyhow::Result as AnyResult;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tokio_rustls::rustls::ClientConfig;

#[derive(Clone, Debug)]
pub struct ApplicationContext {
    pub file_store: Arc<Mutex<FileStore>>,
    pub modules: HashMap<String, ResolvedModuleConfig>,
}

impl ApplicationContext {
    pub fn load_from_config(config: ApplicationConfig) -> AnyResult<Self> {
        let file_store = Arc::new(Mutex::new(FileStore::default()));
        let modules = resolve_module_config(&config.modules)?;
        Ok(Self {
            file_store,
            modules,
        })
    }

    pub async fn build_tls_config(
        &self,
        module_name: &str,
    ) -> AnyResult<(ClientConfig, Arc<CertificateInterceptor>)> {
        let module = self
            .modules
            .get(module_name)
            .ok_or(ErrorReason::UnknownModule)?;

        let builder = ClientConfig::builder();
        let mut store = self.file_store.lock().await;

        let trustanchors = Arc::new(
            store
                .load_from_source_async(
                    &module.trustedanchors,
                    FileType::TrustAnchors,
                )
                .await?
                .clone_trust_anchors()
                .ok_or(ErrorReason::InvalidPemTag)?,
        );

        let interceptor = Arc::new(CertificateInterceptor::new(
            trustanchors,
            module.insecure_skip_verify,
        ));

        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(interceptor.clone());

        let config = if let Some(certs_fc) = &module.certs {
            let certs = store
                .load_from_source_async(certs_fc, FileType::Certificates)
                .await?
                .clone_certificates()
                .ok_or(ErrorReason::InvalidPemTag)?;
            let key = store
                .load_from_source_async(
                    module
                        .key
                        .as_ref()
                        .ok_or(ErrorReason::MissingPrivateKey)?,
                    FileType::PrivateKey,
                )
                .await?
                .clone_private_key()
                .ok_or(ErrorReason::InvalidPemTag)?;

            builder.with_client_auth_cert(certs, key)?
        } else {
            builder.with_no_client_auth()
        };

        Ok((config, interceptor))
    }
}
