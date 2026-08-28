use std::{path::PathBuf, time::Duration};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};
use url::Url;
use x509_parser::prelude::parse_x509_certificate;

use crate::{
    ClientError,
    transport::{ApiTransport, TransportRequest, TransportResponse},
};

#[derive(Debug, Clone)]
pub enum CertificateMode {
    SystemTrust,
    CustomCa {
        pem_path: PathBuf,
    },
    Pinned {
        certificate_pem: PathBuf,
        spki_sha256: String,
    },
}

pub struct HttpsTransport {
    base_url: Url,
    client: reqwest::Client,
    expected_spki: Option<String>,
}

impl HttpsTransport {
    pub fn new(base_url: Url, certificate_mode: CertificateMode) -> Result<Self, ClientError> {
        if base_url.scheme() != "https" {
            return Err(ClientError::Configuration(
                "server URL must use https://; plaintext HTTP is not supported".to_owned(),
            ));
        }
        if !base_url.username().is_empty() || base_url.password().is_some() {
            return Err(ClientError::Configuration(
                "credentials must not be embedded in the server URL".to_owned(),
            ));
        }
        if base_url.host_str().is_none() {
            return Err(ClientError::Configuration(
                "server URL must include a hostname".to_owned(),
            ));
        }

        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .tls_info(true);
        let expected_spki = match certificate_mode {
            CertificateMode::SystemTrust => None,
            CertificateMode::CustomCa { pem_path } => {
                let certificate = load_certificate(&pem_path)?;
                builder = builder
                    .tls_built_in_root_certs(false)
                    .add_root_certificate(certificate);
                None
            }
            CertificateMode::Pinned {
                certificate_pem,
                spki_sha256,
            } => {
                if !spki_sha256.starts_with("sha256/") {
                    return Err(ClientError::Configuration(
                        "SPKI pin must use the sha256/<base64> format".to_owned(),
                    ));
                }
                let certificate = load_certificate(&certificate_pem)?;
                builder = builder
                    .tls_built_in_root_certs(false)
                    .add_root_certificate(certificate);
                Some(spki_sha256)
            }
        };
        let client = builder
            .build()
            .map_err(|error| ClientError::Tls(error.to_string()))?;
        Ok(Self {
            base_url,
            client,
            expected_spki,
        })
    }
}

#[async_trait]
impl ApiTransport for HttpsTransport {
    async fn execute(&self, request: TransportRequest) -> Result<TransportResponse, ClientError> {
        let url = self
            .base_url
            .join(request.path_and_query.trim_start_matches('/'))
            .map_err(|error| ClientError::Configuration(error.to_string()))?;
        let mut outgoing = self.client.request(request.method, url).body(request.body);
        for (name, value) in &request.headers {
            outgoing = outgoing.header(name, value);
        }
        let response = outgoing.send().await.map_err(classify_reqwest)?;
        if let Some(expected) = &self.expected_spki {
            let tls_info = response
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .ok_or_else(|| {
                    ClientError::Tls("peer certificate details were unavailable".to_owned())
                })?;
            let certificate = tls_info.peer_certificate().ok_or_else(|| {
                ClientError::Tls("server did not present a leaf certificate".to_owned())
            })?;
            let actual = spki_sha256(certificate)?;
            if &actual != expected {
                return Err(ClientError::Tls(format!(
                    "server public-key pin mismatch (expected {expected}, received {actual})"
                )));
            }
        }
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await.map_err(classify_reqwest)?.to_vec();
        Ok(TransportResponse {
            status,
            headers,
            body,
        })
    }
}

pub fn spki_sha256(certificate_der: &[u8]) -> Result<String, ClientError> {
    let (_, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|error| ClientError::Tls(format!("could not parse peer certificate: {error}")))?;
    let digest = Sha256::digest(certificate.public_key().raw);
    Ok(format!("sha256/{}", STANDARD.encode(digest)))
}

pub fn spki_sha256_from_pem(path: &std::path::Path) -> Result<String, ClientError> {
    let file = std::fs::File::open(path).map_err(|error| {
        ClientError::Configuration(format!(
            "could not read certificate {}: {error}",
            path.display()
        ))
    })?;
    let certificate = rustls_pemfile::certs(&mut std::io::BufReader::new(file))
        .next()
        .transpose()
        .map_err(|error| ClientError::Tls(format!("certificate PEM is invalid: {error}")))?
        .ok_or_else(|| ClientError::Tls("certificate PEM contains no certificate".to_owned()))?;
    spki_sha256(certificate.as_ref())
}

fn load_certificate(path: &std::path::Path) -> Result<reqwest::Certificate, ClientError> {
    let pem = std::fs::read(path).map_err(|error| {
        ClientError::Configuration(format!(
            "could not read certificate {}: {error}",
            path.display()
        ))
    })?;
    reqwest::Certificate::from_pem(&pem)
        .map_err(|error| ClientError::Tls(format!("certificate PEM is invalid: {error}")))
}

fn classify_reqwest(error: reqwest::Error) -> ClientError {
    if error.is_timeout() {
        ClientError::Timeout
    } else if error.is_connect() {
        let message = error.to_string();
        if message.to_ascii_lowercase().contains("certificate")
            || message.to_ascii_lowercase().contains("tls")
        {
            ClientError::Tls(message)
        } else {
            ClientError::Connect(message)
        }
    } else {
        ClientError::Connect(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plaintext_url() {
        let error = HttpsTransport::new(
            Url::parse("http://localhost:7500/").unwrap(),
            CertificateMode::SystemTrust,
        )
        .err()
        .expect("HTTP URL must fail");
        assert!(error.to_string().contains("plaintext HTTP"));
    }
}
