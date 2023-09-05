use crate::{
    cert::{CertificateIdentifier, ParsedCertificate},
    certificate_interceptor::CertificateInterceptor,
    error::{AppError, AppResult, ErrorReason},
};
use chrono::{DateTime, Utc};
use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    net::{AddrParseError, IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio_rustls::rustls::{Certificate, ClientConfig, RootCertStore, ServerName, OwnedTrustAnchor};
use trust_dns_resolver::{name_server::ConnectionProvider, AsyncResolver, TryParseIp};
use x509_certificate::X509Certificate;

#[derive(Clone, Debug, Default)]
pub struct Store {
    pub cert_store: HashMap<CertificateIdentifier, ParsedCertificate>,
    pub endpoint_store: HashMap<Endpoint, EndpointState>,
}

impl Store {
    pub fn add_pem_certificates(&mut self, buf: &[u8]) -> AppResult<()> {
        let certificates = X509Certificate::from_pem_multiple(buf)?
            .into_iter()
            .map(ParsedCertificate);
        for cert in certificates {
            let identifier = cert.certificate_identifier()?;
            self.cert_store.entry(identifier).or_insert(cert);
        }
        Ok(())
    }

    pub fn add_certificates(
        &mut self,
        certificates: impl IntoIterator<Item = Certificate>,
    ) -> AppResult<Vec<CertificateIdentifier>> {
        let certificates = certificates
            .into_iter()
            .map(X509Certificate::from_der)
            .map(|cert| cert.map(ParsedCertificate))
            //     .collect::<Result<Vec<_>, X509CertificateError>>()?;
            // let with_identifier = certificates
            //     .into_iter()
            .flat_map(|cert| {
                cert.map(|cert| {
                    cert.certificate_identifier()
                        .map(|identifier| (identifier, cert))
                })
                .map_err(AppError::from)
            })
            .collect::<AppResult<Vec<_>>>()?;

        let identifiers: Vec<CertificateIdentifier> = certificates
            .into_iter()
            .map(|(identifier, cert)| {
                self.cert_store.entry(identifier.clone()).or_insert(cert);
                identifier
            })
            .collect();

        Ok(identifiers)
    }

    pub fn update_endpoint_probe_result(
        &mut self,
        endpoint: &Endpoint,
        certificates: impl IntoIterator<Item = Certificate>,
        successful: bool,
    ) -> AppResult<&mut EndpointState> {
        let identifiers = self.add_certificates(certificates.into_iter())?;

        let Some(state) = self.endpoint_store.get_mut(&endpoint) else {
            return Err(ErrorReason::InvalidEndpoint.into());
        };

        state.cert_idents = identifiers;
        state.last_probe = Some(Utc::now());
        state.probe_result = successful;

        Ok(state)
    }

    pub fn clear(&mut self) {
        self.cert_store.clear();
        self.endpoint_store.clear();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub endpoint: SocketAddr,
    pub server_name: ServerName,
}

impl Endpoint {
    pub fn address(&self) -> IpAddr {
        self.endpoint.ip()
    }

    pub fn port(&self) -> u16 {
        self.endpoint.port()
    }

    pub async fn resolve<P: ConnectionProvider>(
        endpoint: &str,
        resolver: &AsyncResolver<P>,
    ) -> AppResult<Vec<Self>> {
        let (addr, port) = endpoint
            .split_once(':')
            .ok_or(ErrorReason::InvalidEndpoint)?;
        let port: u16 = port.parse().map_err(|_| ErrorReason::InvalidEndpoint)?;

        if let Some(ip) = addr.try_parse_ip().and_then(|record| record.ip_addr()) {
            Ok(vec![Self {
                endpoint: SocketAddr::new(ip, port),
                server_name: ServerName::IpAddress(ip),
            }])
        } else {
            let server_name =
                ServerName::try_from(addr).map_err(|_| ErrorReason::InvalidEndpoint)?;
            Ok(resolver
                .lookup_ip(addr)
                .await?
                .into_iter()
                .map(|ip| Self {
                    endpoint: SocketAddr::new(ip, port),
                    server_name: server_name.clone(),
                })
                .collect())
        }
    }
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let ServerName::DnsName(dns) = &self.server_name {
            write!(f, "{}({})", self.endpoint, dns.as_ref())
        } else {
            write!(f, "{}", self.endpoint)
        }
    }
}

impl FromStr for Endpoint {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sockaddr = SocketAddr::from_str(s)?;

        Ok(Self {
            endpoint: sockaddr,
            server_name: ServerName::IpAddress(sockaddr.ip()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct EndpointState {
    pub endpoint: Endpoint,
    pub tls_config: Arc<ClientConfig>,
    pub interceptor: Arc<CertificateInterceptor>,
    pub cert_idents: Vec<CertificateIdentifier>,
    pub last_probe: Option<DateTime<Utc>>,
    pub probe_result: bool,
}

impl EndpointState {
    pub fn new(
        endpoint: Endpoint,
        mut tls_config: ClientConfig,
        root_certs: RootCertStore,
    ) -> Self {
        let interceptor = Arc::new(CertificateInterceptor::new(root_certs));
        tls_config
            .dangerous()
            .set_certificate_verifier(interceptor.clone());

        Self {
            endpoint,
            tls_config: Arc::new(tls_config),
            interceptor,
            cert_idents: Default::default(),
            last_probe: Default::default(),
            probe_result: Default::default(),
        }
    }

    pub fn with_webpki_defaults(endpoint: Endpoint) -> Self {
        let mut root_certs = RootCertStore::empty();
        root_certs.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let interceptor = Arc::new(CertificateInterceptor::new(root_certs));

        let tls_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(interceptor.clone())
            .with_no_client_auth();

        Self {
            endpoint,
            tls_config: Arc::new(tls_config),
            interceptor,
            cert_idents: Default::default(),
            last_probe: Default::default(),
            probe_result: Default::default(),
        }
    }
}
