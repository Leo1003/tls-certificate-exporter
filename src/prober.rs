use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::{
    error::{AppResult, ErrorReason},
    store::{Endpoint, Store},
};

#[derive(Debug, Default)]
pub struct Prober {
    store: Store,
}

impl Prober {
    pub async fn probe(&mut self, endpoint: Endpoint) -> AppResult<()> {
        let Some(state) = self.store.endpoint_store.get(&endpoint) else {
            return Err(ErrorReason::InvalidEndpoint.into());
        };

        let connector = TlsConnector::from(state.tls_config.clone());
        let stream = TcpStream::connect(&endpoint.endpoint).await?;

        let result = connector
            .connect(endpoint.server_name.clone(), stream)
            .await;

        let Some(certificates) = state.interceptor.get_certificates() else {
            // Don't get certificates, might be connection error
            if let Err(err) = result {
                return Err(err.into());
            } else {
                return Err(ErrorReason::Unknown.into());
            }
        };

        self.store
            .update_endpoint_probe_result(&endpoint, certificates, result.is_ok())?;

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
        let mut app = Prober::default();

        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
        let endpoint = Endpoint::resolve("www.rust-lang.org:443", &resolver)
            .await
            .unwrap();

        for ep in endpoint {
            app.store
                .endpoint_store
                .insert(ep.clone(), EndpointState::with_webpki_defaults(ep.clone()));

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
