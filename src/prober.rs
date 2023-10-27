use crate::{
    cert::ParsedCertificate,
    configs::{ConnectionParameters, DEFAULT_TIMEOUT},
    error::ErrorReason,
    store::{Endpoint, Target},
};
use anyhow::{Context, Result as AnyResult};
use futures::{stream::FuturesUnordered, TryStreamExt};
use std::{
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use trust_dns_resolver::TokioAsyncResolver;
use x509_certificate::X509Certificate;

#[derive(Debug)]
pub struct Prober {
    resolver: Arc<TokioAsyncResolver>,
    default_params: ConnectionParameters,
}

impl Prober {
    pub fn new(resolver: Arc<TokioAsyncResolver>, default_params: ConnectionParameters) -> Self {
        Self {
            resolver,
            default_params,
        }
    }

    pub async fn probe(
        &self,
        target: &Target,
        parameters: &ConnectionParameters,
    ) -> AnyResult<Vec<ProbeResult>> {
        let params = parameters.merge(&self.default_params);

        let endpoints = timeout(
            params.timeout.unwrap_or(DEFAULT_TIMEOUT),
            Endpoint::resolve(target, &self.resolver),
        )
        .await
        .with_context(|| "Name resolution timeout")??;

        let tasks: FuturesUnordered<_> = endpoints
            .into_iter()
            .map(|ep| {
                // Borrow before `move` block
                let params_ref = &params;
                async move { Self::probe_endpoint(&ep, params_ref).await }
            })
            .collect();
        tasks.try_collect().await
    }

    pub async fn probe_endpoint(
        endpoint: &Endpoint,
        parameters: &ConnectionParameters,
    ) -> AnyResult<ProbeResult> {
        let (tls_config, interceptor) = parameters.build_tls_config()?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let stream = TcpStream::connect(&endpoint.sockaddr).await?;

        let conn_result = match timeout(
            parameters.timeout.unwrap_or(DEFAULT_TIMEOUT),
            connector.connect(endpoint.server_name.clone(), stream),
        )
        .await
        {
            Ok(conn_result) => conn_result.map(|_| ()),
            Err(elapsed) => Err(IoError::new(IoErrorKind::TimedOut, elapsed)),
        };

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
            probe_result: conn_result.map_err(|e| e.to_string()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub endpoint: Endpoint,
    pub certificates: Vec<ParsedCertificate>,
    pub probe_result: Result<(), String>,
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
        let prober = Prober::new(resolver, ConnectionParameters::default());

        let target = Target::from_str("www.rust-lang.org:443").unwrap();
        let mut parameters = ConnectionParameters::default();
        parameters.load_webpki_roots();

        let probe_results = prober.probe(&target, &parameters).await.unwrap();

        println!("Endpoints: ");
        for pr in probe_results {
            println!("{}[{}]: {:?}", target, pr.endpoint, pr.probe_result);
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
