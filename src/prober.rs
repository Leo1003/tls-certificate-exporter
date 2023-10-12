use crate::{
    configs::TargetParameter,
    error::{AppResult, ErrorReason},
    store::{Endpoint, EndpointState, Store},
};
use futures::{stream::FuturesUnordered, TryStreamExt};
use std::sync::Arc;
use tokio::{net::TcpStream, sync::RwLock};
use tokio_rustls::{rustls::Certificate, TlsConnector};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug)]
pub struct Prober {
    resolver: Arc<TokioAsyncResolver>,
    store: Arc<RwLock<Store>>,
}

impl Prober {
    pub fn new(resolver: Arc<TokioAsyncResolver>, store: Arc<RwLock<Store>>) -> Self {
        Self { resolver, store }
    }

    pub async fn probe(&mut self, target: &TargetParameter) -> AppResult<()> {
        let endpoints = Endpoint::resolve(&target.target, &self.resolver)
            .await
            .unwrap();

        let tasks: FuturesUnordered<_> = endpoints
            .into_iter()
            .map(|ep| async move { Self::probe_endpoint(target, &ep).await })
            .collect();
        let probe_results: Vec<ProbeResult> = tasks.try_collect().await?;

        // Lock the store here instead of lock it inside the iterator
        let mut store_wl = self.store.write().await;
        let ep_states: Vec<EndpointState> = probe_results
            .into_iter()
            .map(|probe| {
                store_wl
                    .add_certificates(probe.certificates)
                    .map(|cert_idents| EndpointState {
                        endpoint: probe.endpoint,
                        cert_idents,
                        probe_result: probe.probe_result,
                    })
            })
            .collect::<AppResult<_>>()?;

        store_wl.update_probe_result(&target.target, ep_states);
        // It's a good practice to remember to drop the write lock explicitly asap
        drop(store_wl);

        Ok(())
    }

    async fn probe_endpoint(
        target: &TargetParameter,
        endpoint: &Endpoint,
    ) -> AppResult<ProbeResult> {
        let (tls_config, interceptor) = target.build_tls_config()?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let stream = TcpStream::connect(&endpoint.sockaddr).await?;

        let result = connector
            .connect(endpoint.server_name.clone(), stream)
            .await;

        let Some(certificates) = interceptor.get_certificates() else {
            // Don't get certificates, might be connection error
            if let Err(err) = result {
                return Err(err.into());
            } else {
                return Err(ErrorReason::Unknown.into());
            }
        };

        Ok(ProbeResult {
            endpoint: endpoint.clone(),
            certificates,
            probe_result: result.is_ok(),
        })
    }
}

#[derive(Clone, Debug)]
struct ProbeResult {
    pub endpoint: Endpoint,
    pub certificates: Vec<Certificate>,
    pub probe_result: bool,
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use trust_dns_resolver::TokioAsyncResolver;

    #[tokio::test]
    async fn probe_rust_lang_org() {
        let resolver = Arc::new(TokioAsyncResolver::tokio_from_system_conf().unwrap());
        let store = RwLock::new(Store::default());
        let mut prober = Prober::new(resolver, store);

        prober
            .probe(&TargetParameter::from_str("www.rust-lang.org:443").unwrap())
            .await
            .unwrap();

        println!("Endpoints: ");
        for (target, state) in &prober.store.read().await.target_store {
            for endpoint in &state.endpoints {
                println!("{}[{}]: ", target, endpoint.endpoint);
                for id in &endpoint.cert_idents {
                    println!("    {}", id);
                }
            }
        }
        println!();

        println!("Certificates: ");
        for (ident, cert) in &prober.store.read().await.cert_store {
            println!(
                "[{}]: [{} ~ {}] {}",
                ident,
                cert.not_before(),
                cert.not_after(),
                cert
            );
        }
        assert!(!prober.store.read().await.cert_store.is_empty());
    }
}
