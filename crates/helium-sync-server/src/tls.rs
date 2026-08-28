use std::{fs::File, io::BufReader, path::Path, sync::Arc};

use rustls::{
    ServerConfig,
    crypto::ring::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::CertifiedKey,
    version::TLS13,
};
use x509_parser::prelude::parse_x509_certificate;

fn read_material(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let cert_file = File::open(cert_path)
        .map_err(|error| format!("cannot open certificate {}: {error}", cert_path.display()))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot parse certificate PEM: {error}"))?;
    if certs.is_empty() {
        return Err("certificate PEM contains no certificates".to_owned());
    }
    let key_file = File::open(key_path)
        .map_err(|error| format!("cannot open private key {}: {error}", key_path.display()))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|error| format!("cannot parse private key PEM: {error}"))?
        .ok_or_else(|| {
            "private key PEM contains no supported PKCS#1, PKCS#8, or SEC1 key".to_owned()
        })?;
    Ok((certs, key))
}

pub fn validate_material(cert_path: &Path, key_path: &Path) -> Result<(), String> {
    let (certs, key) = read_material(cert_path, key_path)?;
    let (_, certificate) = parse_x509_certificate(certs[0].as_ref())
        .map_err(|error| format!("end-entity certificate is not valid X.509 DER: {error}"))?;
    if !certificate.validity().is_valid() {
        return Err(
            "end-entity certificate is not currently valid (check not-before and expiry dates)"
                .to_owned(),
        );
    }
    let signing_key = any_supported_type(&key)
        .map_err(|error| format!("private key algorithm is unsupported: {error}"))?;
    CertifiedKey::new(certs, signing_key)
        .keys_match()
        .map_err(|error| format!("certificate and private key do not match: {error}"))
}

pub fn load_rustls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<axum_server::tls_rustls::RustlsConfig, crate::ServerError> {
    validate_material(cert_path, key_path).map_err(crate::ServerError::Tls)?;
    let (certs, key) = read_material(cert_path, key_path).map_err(crate::ServerError::Tls)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|error| crate::ServerError::Tls(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| crate::ServerError::Tls(error.to_string()))?;
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(config),
    ))
}
