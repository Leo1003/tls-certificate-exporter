use crate::{
    certificate_interceptor::CertificateInterceptor,
    configs::{ConnectionParameters, DEFAULT_TIMEOUT},
    error::{AppError, ErrorReason},
    types::{Endpoint, ParsedCertificate, Target},
};
use anyhow::{Context, Result as AnyResult};
use futures::{stream::FuturesUnordered, StreamExt};
use hickory_resolver::TokioAsyncResolver;
use std::{
    io::{Error as IoError, ErrorKind as IoErrorKind},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpStream,
    time::{timeout, Instant},
};
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
            .map(
                |ep| async move { Self::probe_endpoint(&ep, parameters).await },
            )
            .collect();
        Ok(tasks.collect().await)
    }

    pub async fn probe_endpoint(
        endpoint: &Endpoint,
        parameters: &ConnectionParameters,
    ) -> ProbeResult {
        let (tls_config, mut interceptor) = match parameters.build_tls_config()
        {
            Ok((config, interceptor)) => (config, interceptor),
            Err(e) => {
                return ProbeResult {
                    endpoint: endpoint.clone(),
                    certificates: Err(e.to_string()),
                    connect_time: Duration::default(),
                    connect_result: Err(e.to_string()),
                }
            }
        };

        let conn_begin = Instant::now();
        let conn_result = match timeout(
            parameters.timeout.unwrap_or(DEFAULT_TIMEOUT),
            Self::connect(endpoint, tls_config),
        )
        .await
        {
            Ok(conn_result) => conn_result,
            Err(elapsed) => Err(IoError::new(IoErrorKind::TimedOut, elapsed)),
        };
        let conn_end = Instant::now();

        // The interceptor shall not be copied by `Arc::make_mut()` since the reference count should be 1
        // Using `Arc::make_mut()` instead of `Arc::get_mut()` is just to simplify the codes
        let parsed_certs_result =
            Self::extract_certificates(Arc::make_mut(&mut interceptor));

        ProbeResult {
            endpoint: endpoint.clone(),
            certificates: parsed_certs_result.map_err(|e| e.to_string()),
            connect_time: conn_end - conn_begin,
            connect_result: conn_result.map_err(|e| e.to_string()),
        }
    }

    async fn connect(
        endpoint: &Endpoint,
        tls_config: ClientConfig,
    ) -> Result<(), IoError> {
        let connector = TlsConnector::from(Arc::new(tls_config));
        let stream = TcpStream::connect(&endpoint.sockaddr).await?;

        // TODO: Handle STARTTLS

        connector
            .connect(endpoint.server_name.clone(), stream)
            .await
            .map(|_| ())
    }

    fn extract_certificates(
        interceptor: &mut CertificateInterceptor,
    ) -> AnyResult<Vec<ParsedCertificate>> {
        let certificates = interceptor
            .get_certificates()
            .ok_or(AppError::from(ErrorReason::CertificatesFetchError))?;

        let parsed_certs = certificates
            .into_iter()
            .map(X509Certificate::from_der)
            .map(|cert| cert.map(ParsedCertificate))
            .collect::<Result<_, _>>()?;

        Ok(parsed_certs)
    }
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub endpoint: Endpoint,
    pub certificates: Result<Vec<ParsedCertificate>, String>,
    pub connect_time: Duration,
    pub connect_result: Result<(), String>,
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
            println!("{}[{}]: {:?}", target, pr.endpoint, pr.connect_result);
            for cert in &pr.certificates.unwrap() {
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
