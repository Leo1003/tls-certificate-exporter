use anyhow::Result as AnyResult;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use num_bigint::BigUint;
use std::{
    fmt::{Display, Formatter},
    ops::Deref,
};
use x509_certificate::{asn1time::Time, X509Certificate};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCertificate(pub X509Certificate);

impl ParsedCertificate {
    pub fn serial_number(&self) -> BigUint {
        let number = &self.0.as_ref().tbs_certificate.serial_number;
        BigUint::from_bytes_be(number.as_slice())
    }

    pub fn not_before(&self) -> i64 {
        match &self.0.as_ref().tbs_certificate.validity.not_before {
            Time::UtcTime(t) => t.timestamp(),
            Time::GeneralTime(t) => {
                DateTime::<Utc>::from(t.clone()).timestamp()
            }
        }
    }

    pub fn not_after(&self) -> i64 {
        match &self.0.as_ref().tbs_certificate.validity.not_after {
            Time::UtcTime(t) => t.timestamp(),
            Time::GeneralTime(t) => {
                DateTime::<Utc>::from(t.clone()).timestamp()
            }
        }
    }

    pub fn certificate_identifier(&self) -> AnyResult<CertificateIdentifier> {
        Ok(CertificateIdentifier {
            serial_number: self.serial_number(),
            fingerprint: self.0.sha256_fingerprint()?.as_ref().to_owned(),
        })
    }
}

impl Deref for ParsedCertificate {
    type Target = X509Certificate;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for ParsedCertificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let der = self.0.encode_der().map_err(|_| std::fmt::Error)?;
        write!(f, "{}", STANDARD.encode(der))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificateIdentifier {
    serial_number: BigUint,
    fingerprint: Vec<u8>,
}

impl Display for CertificateIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}#{}",
            STANDARD.encode(&self.fingerprint),
            &self.serial_number
        )
    }
}
