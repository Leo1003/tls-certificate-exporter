use crate::{
    certificate_interceptor::CertificateInterceptor,
    configs::{ConnectionParameters, ResolvedModuleConfig, DEFAULT_TIMEOUT},
    error::ErrorReason,
    types::{Endpoint, ParsedCertificate, Target},
};
use anyhow::{Context, Result as AnyResult};
use futures::{stream::FuturesUnordered, TryStreamExt};
use hickory_resolver::TokioAsyncResolver;
use std::{
    io::{Error as IoError, ErrorKind as IoErrorKind},
    sync::Arc,
};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{rustls::ClientConfig, TlsConnector};
use x509_certificate::X509Certificate;

#[derive(Clone, Debug)]
pub struct Prober {
    resolver: TokioAsyncResolver,
}

impl Prober {
    pub fn new(resolver: TokioAsyncResolver) -> Self {
        Self { resolver }
    }

    pub async fn probe(
        &self,
        target: &Target,
        parameters: &ConnectionParameters,
    ) -> AnyResult<Vec<ProbeResult>> {
        let endpoints = timeout(
            parameters.timeout.unwrap_or(DEFAULT_TIMEOUT),
            Endpoint::resolve(target, &self.resolver),
        )
        .await
        .with_context(|| "Name resolution timeout")??;

        let tasks: FuturesUnordered<_> = endpoints
            .into_iter()
            .map(|ep| async move { Self::probe_endpoint(&ep, parameters).await })
            .collect();
        tasks.try_collect().await
    }

    pub async fn probe_endpoint(
        endpoint: &Endpoint,
        parameters: &ConnectionParameters,
    ) -> AnyResult<ProbeResult> {
        let (tls_config, mut interceptor) = parameters.build_tls_config()?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let stream = TcpStream::connect(&endpoint.sockaddr).await?;

        // TODO: Handle STARTTLS

        let conn_result = match timeout(
            parameters.timeout.unwrap_or(DEFAULT_TIMEOUT),
            connector.connect(endpoint.server_name.clone(), stream),
        )
        .await
        {
            Ok(conn_result) => conn_result.map(|_| ()),
            Err(elapsed) => Err(IoError::new(IoErrorKind::TimedOut, elapsed)),
        };
        // Drop the connection here to make the interceptor's reference count decrease to 1
        drop(connector);

        // The interceptor shall not be copied by `Arc::make_mut()` since the reference count should be 1
        // Using `Arc::make_mut()` instead of `Arc::get_mut()` is just to simplify the codes
        let interceptor_inner = Arc::make_mut(&mut interceptor);
        let Some(certificates) = interceptor_inner.get_certificates() else {
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
    use crate::types::Target;
    use hickory_resolver::TokioAsyncResolver;
    use std::str::FromStr;

    #[tokio::test]
    async fn probe_rust_lang_org() {
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
        let prober = Prober::new(resolver);

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
