//! Transport, encryption, state, and orchestration for Helium Sync clients.

pub mod api;
pub mod crypto;
pub mod https;
pub mod orchestration;
pub mod secrets;
pub mod ssh;
pub mod state;
pub mod transport;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid configuration: {0}")]
    Configuration(String),
    #[error("DNS lookup or TCP connection failed: {0}")]
    Connect(String),
    #[error("TLS certificate validation failed: {0}")]
    Tls(String),
    #[error("HTTPS request timed out")]
    Timeout,
    #[error("SSH host key is unknown; verify fingerprint {fingerprint}")]
    SshHostKeyUnknown { fingerprint: String },
    #[error("SSH host key changed or did not match the trusted key: {0}")]
    SshHostKeyChanged(String),
    #[error("SSH authentication failed")]
    SshAuthentication,
    #[error("SSH connection failed: {0}")]
    Ssh(String),
    #[error("remote Unix socket is unavailable: {0}")]
    RemoteSocket(String),
    #[error("server authentication failed")]
    ApiAuthentication,
    #[error(
        "server protocol is incompatible (client {client_min}-{client_max}, server {server_min}-{server_max})"
    )]
    ProtocolIncompatible {
        client_min: u16,
        client_max: u16,
        server_min: u16,
        server_max: u16,
    },
    #[error("server returned {status} {code}: {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("secret storage failed: {0}")]
    SecretStore(String),
    #[error("local state failed: {0}")]
    State(String),
    #[error("profile operation failed: {0}")]
    Profile(#[from] helium_sync_profile::ProfileError),
    #[error("protocol serialization failed: {0}")]
    Serialization(String),
}
