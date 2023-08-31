use num_bigint::BigUint;
use crate::error::AppResult;
use chrono::{DateTime, Utc};
use x509_certificate::{X509Certificate, asn1time::Time};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCertificate(pub X509Certificate);

impl ParsedCertificate {
    pub fn common_name(&self) -> Option<String> {
        self.0.subject_common_name()
    }

    pub fn issuer_common_name(&self) -> Option<String> {
        self.0.issuer_common_name()
    }

    pub fn serial_number(&self) -> BigUint {
        let number = &self.0.as_ref().tbs_certificate.serial_number;

        BigUint::from_bytes_be(number.as_slice())
    }

    pub fn not_before(&self) -> i64 {
        match &self.0.as_ref().tbs_certificate.validity.not_before {
            Time::UtcTime(t) => t.timestamp(),
            Time::GeneralTime(t) => DateTime::<Utc>::from(t.clone()).timestamp(),
        }
    }

    pub fn not_after(&self) -> i64 {
        match &self.0.as_ref().tbs_certificate.validity.not_after {
            Time::UtcTime(t) => t.timestamp(),
            Time::GeneralTime(t) => DateTime::<Utc>::from(t.clone()).timestamp(),
        }
    }

    pub fn certificate_identifier(&self) -> AppResult<CertificateIdentifier> {
        Ok(CertificateIdentifier {
            serial_number: self.serial_number(),
            fingerprint: self.0.sha256_fingerprint()?.as_ref().to_owned(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificateIdentifier {
    serial_number: BigUint,
    fingerprint: Vec<u8>,
}
