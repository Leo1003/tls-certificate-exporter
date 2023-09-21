use crate::error::{AppResult, ErrorReason};
use std::{
    fmt::{Display, Formatter},
    net::{AddrParseError, IpAddr, SocketAddr},
    str::FromStr,
};
use tokio_rustls::rustls::ServerName;
use trust_dns_resolver::{name_server::ConnectionProvider, AsyncResolver, TryParseIp};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub sockaddr: SocketAddr,
    pub server_name: ServerName,
}

impl Endpoint {
    pub fn address(&self) -> IpAddr {
        self.sockaddr.ip()
    }

    pub fn port(&self) -> u16 {
        self.sockaddr.port()
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
                sockaddr: SocketAddr::new(ip, port),
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
                    sockaddr: SocketAddr::new(ip, port),
                    server_name: server_name.clone(),
                })
                .collect())
        }
    }
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let ServerName::DnsName(dns) = &self.server_name {
            write!(f, "{}({})", self.sockaddr, dns.as_ref())
        } else {
            write!(f, "{}", self.sockaddr)
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(sockaddr: SocketAddr) -> Self {
        Self {
            sockaddr,
            server_name: ServerName::IpAddress(sockaddr.ip()),
        }
    }
}

impl FromStr for Endpoint {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SocketAddr::from_str(s).map(Self::from)
    }
}
