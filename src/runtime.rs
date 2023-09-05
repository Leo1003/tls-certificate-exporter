use chrono::Utc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::{
    cert,
    error::{AppResult, ErrorReason},
    store::{Endpoint, Store},
};

#[derive(Debug, Default)]
pub struct Application {
    store: Store,
}

impl Application {
    pub async fn probe(&mut self, endpoint: Endpoint) -> AppResult<()> {
        let Some(state) = self.store.endpoint_store.get(&endpoint) else {
            return Err(ErrorReason::InvalidEndpoint.into());
        };

        let connector = TlsConnector::from(state.tls_config.clone());
        let stream = TcpStream::connect(&endpoint.endpoint).await?;

        let result = connector
            .connect(endpoint.server_name.clone(), stream)
            .await;

        if let Some(certificates) = state.interceptor.get_certificates() {
            let identifiers = self.store.add_certificates(certificates.into_iter())?;

            let Some(state) = self.store.endpoint_store.get_mut(&endpoint) else {
                return Err(ErrorReason::InvalidEndpoint.into());
            };
            state.cert_idents = identifiers;
        }

        let Some(state) = self.store.endpoint_store.get_mut(&endpoint) else {
            return Err(ErrorReason::InvalidEndpoint.into());
        };

        state.last_probe = Some(Utc::now());
        state.probe_result = result.is_ok();

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::store::EndpointState;
    use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
    use trust_dns_resolver::TokioAsyncResolver;

    #[tokio::test]
    async fn probe_rust_lang_org() {
        let mut app = Application::default();

        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
        let endpoint = Endpoint::resolve("www.rust-lang.org:443", &resolver)
            .await
            .unwrap();

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        for ep in endpoint {
            app.store.endpoint_store.insert(
                ep.clone(),
                EndpointState::new(ep.clone(), config.clone(), root_cert_store.clone()),
            );

            app.probe(ep).await.unwrap();
        }

        println!("Endpoints: ");
        for (endpoint, state) in &app.store.endpoint_store {
            println!("{}: ", endpoint);
            for id in &state.cert_idents {
                println!("    {}", id);
            }
        }
        println!();

        println!("Certificates: ");
        for (ident, cert) in &app.store.cert_store {
            println!(
                "[{}]: [{} ~ {}] {}",
                ident,
                cert.not_before(),
                cert.not_after(),
                cert
            );
        }
        assert!(!app.store.cert_store.is_empty());
    }
}
