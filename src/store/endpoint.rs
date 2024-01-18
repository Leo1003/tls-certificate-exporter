use crate::error::ErrorReason;
use anyhow::Result as AnyResult;
use hickory_resolver::{name_server::ConnectionProvider, AsyncResolver, TryParseIp};
use rustls_pki_types::ServerName;
use std::{
    fmt::{Display, Formatter},
    net::{AddrParseError, IpAddr, SocketAddr},
    str::FromStr,
};

use super::target::Target;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub sockaddr: SocketAddr,
    pub server_name: ServerName<'static>,
}

impl Endpoint {
    #[allow(unused)]
    pub fn address(&self) -> IpAddr {
        self.sockaddr.ip()
    }

    #[allow(unused)]
    pub fn port(&self) -> u16 {
        self.sockaddr.port()
    }

    pub async fn resolve<P: ConnectionProvider>(
        target: &Target,
        resolver: &AsyncResolver<P>,
    ) -> AnyResult<Vec<Self>> {
        if let Some(ip) = target
            .host
            .try_parse_ip()
            .and_then(|record| record.ip_addr())
        {
            Ok(vec![Self {
                sockaddr: SocketAddr::new(ip, target.port),
                server_name: ServerName::IpAddress(ip.into()),
            }])
        } else {
            let server_name = ServerName::try_from(target.host.as_str())
                .map_err(|_| ErrorReason::InvalidEndpoint)?;
            Ok(resolver
                .lookup_ip(&target.host)
                .await?
                .into_iter()
                .map(|ip| Self {
                    sockaddr: SocketAddr::new(ip, target.port),
                    server_name: server_name.to_owned(),
                })
                .collect())
        }
    }
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            if let ServerName::DnsName(dns) = &self.server_name {
                write!(f, "{:#}({})", self.sockaddr, dns.as_ref())
            } else {
                write!(f, "{:#}", self.sockaddr)
            }
        } else {
            write!(f, "{}", self.sockaddr)
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(sockaddr: SocketAddr) -> Self {
        Self {
            sockaddr,
            server_name: ServerName::IpAddress(sockaddr.ip().into()),
        }
    }
}

impl FromStr for Endpoint {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SocketAddr::from_str(s).map(Self::from)
    }
}
