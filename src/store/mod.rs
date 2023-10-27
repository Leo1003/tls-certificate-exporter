use crate::{
    cert::{CertificateIdentifier, ParsedCertificate},
    configs::{ConnectionParameters, DEFAULT_INTERVAL},
    prober::ProbeResult,
};
use anyhow::{Context, Result as AnyResult};
use chrono::Utc;
use std::{collections::HashMap, time::Duration};
use tokio_rustls::rustls::Certificate;
use x509_certificate::X509Certificate;

mod endpoint;
mod endpoint_state;
mod target;

pub use endpoint::Endpoint;
pub use endpoint_state::EndpointState;
pub use target::{Target, TargetState};

#[derive(Clone, Debug, Default)]
pub struct Store {
    pub default_params: ConnectionParameters,
    pub target_store: HashMap<Target, TargetState>,
    pub cert_store: HashMap<CertificateIdentifier, ParsedCertificate>,
}

impl Store {
    pub fn with_default_params(default_params: ConnectionParameters) -> Self {
        Self {
            default_params,
            ..Default::default()
        }
    }

    pub fn add_pem_certificates(&mut self, buf: &[u8]) -> AnyResult<()> {
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
        certificates: impl IntoIterator<Item = ParsedCertificate>,
    ) -> AnyResult<Vec<CertificateIdentifier>> {
        let certificates: Vec<(CertificateIdentifier, ParsedCertificate)> = certificates
            .into_iter()
            .map(|cert| {
                cert.certificate_identifier()
                    .map(|identifier| (identifier, cert))
            })
            .collect::<AnyResult<Vec<_>>>()?;

        let identifiers: Vec<CertificateIdentifier> = certificates
            .into_iter()
            .map(|(identifier, cert)| {
                self.cert_store.entry(identifier.clone()).or_insert(cert);
                identifier
            })
            .collect();

        Ok(identifiers)
    }

    pub fn insert_target(&mut self, target: Target, parameters: ConnectionParameters) {
        self.target_store.insert(
            target,
            TargetState {
                parameters,
                ..Default::default()
            },
        );
    }

    pub fn iter_need_probe(&self) -> impl Iterator<Item = (&Target, &TargetState)> {
        self.target_store.iter().filter(|(target, state)| {
            if let Some(last_probe) = state.last_probe {
                let interval = state
                    .parameters
                    .interval
                    .or(self.default_params.interval)
                    .unwrap_or(DEFAULT_INTERVAL);

                (Utc::now() - last_probe).to_std().unwrap_or(Duration::ZERO) > interval
            } else {
                true
            }
        })
    }

    /// Return the duration should wait to probe targets.
    pub fn wait_duration(&self) -> Duration {
        let now = Utc::now();

        self.target_store
            .values()
            .fold(DEFAULT_INTERVAL, |dura, v| {
                let nextdura = if let Some(last_probe) = v.last_probe {
                    let interval = v
                        .parameters
                        .interval
                        .or(self.default_params.interval)
                        .unwrap_or(DEFAULT_INTERVAL);

                    let nextprobe = last_probe + interval;
                    (nextprobe - now).to_std().unwrap_or(Duration::ZERO)
                } else {
                    Duration::ZERO
                };

                dura.min(nextdura)
            })
    }

    pub fn update_probe_result(
        &mut self,
        target: &Target,
        probe_results: Vec<ProbeResult>,
    ) -> AnyResult<()> {
        let ep_states: Vec<EndpointState> = probe_results
            .into_iter()
            .map(|probe| {
                self.add_certificates(probe.certificates)
                    .map(|cert_idents| EndpointState {
                        endpoint: probe.endpoint,
                        cert_idents,
                        probe_result: probe.probe_result,
                    })
            })
            .collect::<AnyResult<_>>()?;

        self.update_endpoints(target, ep_states);
        Ok(())
    }

    fn update_endpoints(&mut self, target: &Target, ep_states: Vec<EndpointState>) {
        if let Some(target_state) = self.target_store.get_mut(target) {
            target_state.endpoints = ep_states;
            target_state.last_probe = Some(Utc::now());
        } else {
            let target_state = TargetState {
                endpoints: ep_states,
                parameters: Default::default(),
                last_probe: Some(Utc::now()),
            };

            self.target_store.insert(target.clone(), target_state);
        }
    }

    pub fn clear(&mut self) {
        self.cert_store.clear();
        self.target_store.iter_mut().for_each(|(_key, state)| {
            state.endpoints.clear();
            state.last_probe = None;
        });
    }

    pub fn clear_all(&mut self) {
        self.cert_store.clear();
        self.target_store.clear();
    }
}
