use crate::{
    cert::ParsedCertificate,
    configs::{ConnectionParameters, DefaultParameters},
    error::{AppResult, ErrorReason},
    store::{Endpoint, Target},
};
use futures::{stream::FuturesUnordered, TryStreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use trust_dns_resolver::TokioAsyncResolver;
use x509_certificate::X509Certificate;

#[derive(Debug)]
pub struct Prober {
    resolver: Arc<TokioAsyncResolver>,
    target_default: DefaultParameters,
}

impl Prober {
    pub fn new(resolver: Arc<TokioAsyncResolver>, target_default: DefaultParameters) -> Self {
        Self {
            resolver,
            target_default,
        }
    }

    pub async fn probe(
        &mut self,
        target: &Target,
        parameters: &ConnectionParameters,
    ) -> AppResult<Vec<ProbeResult>> {
        let endpoints = Endpoint::resolve(target, &self.resolver).await.unwrap();

        let tasks: FuturesUnordered<_> = endpoints
            .into_iter()
            .map(|ep| async move { Self::probe_endpoint(&ep, parameters).await })
            .collect();
        tasks.try_collect().await
    }

    pub async fn probe_endpoint(
        endpoint: &Endpoint,
        parameters: &ConnectionParameters,
    ) -> AppResult<ProbeResult> {
        let (tls_config, interceptor) = parameters.build_tls_config()?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let stream = TcpStream::connect(&endpoint.sockaddr).await?;

        let conn_result = connector
            .connect(endpoint.server_name.clone(), stream)
            .await;

        let Some(certificates) = interceptor.get_certificates() else {
            // Didn't get certificates, might be connection error
            if let Err(err) = conn_result {
                return Err(err.into());
            } else {
                return Err(ErrorReason::Unknown.into());
            }
        };

        let parsed_certs = certificates
            .into_iter()
            .map(X509Certificate::from_der)
            .map(|cert| cert.map(ParsedCertificate))
            .collect::<Result<_, _>>()?;

        Ok(ProbeResult {
            endpoint: endpoint.clone(),
            certificates: parsed_certs,
            probe_result: conn_result.is_ok(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub endpoint: Endpoint,
    pub certificates: Vec<ParsedCertificate>,
    pub probe_result: bool,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::store::Target;
    use std::str::FromStr;
    use trust_dns_resolver::TokioAsyncResolver;

    #[tokio::test]
    async fn probe_rust_lang_org() {
        let resolver = Arc::new(TokioAsyncResolver::tokio_from_system_conf().unwrap());
        let mut prober = Prober::new(resolver, DefaultParameters::default());

        let target = Target::from_str("www.rust-lang.org:443").unwrap();
        let mut parameters = ConnectionParameters::default();
        parameters.load_webpki_roots();

        let probe_results = prober.probe(&target, &parameters).await.unwrap();

        println!("Endpoints: ");
        for pr in probe_results {
            println!("{}[{}]: {}", target, pr.endpoint, pr.probe_result);
            for cert in &pr.certificates {
                println!(
                    "[{}]: [{} ~ {}] {}",
                    cert.certificate_identifier().unwrap(),
                    cert.not_before(),
                    cert.not_after(),
                    cert
                );
            }
        }
    }
}
