use crate::error::{AppResult, ErrorReason};
use std::{
    net::{AddrParseError, IpAddr, SocketAddr},
    str::FromStr,
};
use trust_dns_resolver::{name_server::ConnectionProvider, AsyncResolver, TryParseIp};
use x509_certificate::X509Certificate;

#[derive(Clone, Debug, Default)]
pub struct ConfigState {
    pub workers: Option<usize>,
    pub targets: Vec<Target>,
    pub trusted_anchors: Vec<X509Certificate>,
}

#[derive(Clone, Debug)]
pub struct Target {}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub endpoint: SocketAddr,
    pub server_name: Option<String>,
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
                server_name: None,
            }])
        } else {
            Ok(resolver
                .lookup_ip(addr)
                .await?
                .into_iter()
                .map(|ip| Self {
                    endpoint: SocketAddr::new(ip, port),
                    server_name: Some(addr.to_owned()),
                })
                .collect())
        }
    }
}

impl FromStr for Endpoint {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            endpoint: SocketAddr::from_str(s)?,
            server_name: None,
        })
    }
}
