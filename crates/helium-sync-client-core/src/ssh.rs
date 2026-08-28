use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use russh::{
    Disconnect, client,
    keys::{check_known_hosts, check_known_hosts_path, load_secret_key, ssh_key},
};
use secrecy::{ExposeSecret as _, SecretString};
use thiserror::Error;

use crate::{
    ClientError,
    transport::{ApiTransport, TransportRequest, TransportResponse},
};

#[derive(Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub private_key: PathBuf,
    pub private_key_passphrase: Option<SecretString>,
    pub remote_socket: String,
    pub application_known_hosts: PathBuf,
    /// Set only after the user explicitly confirms the displayed SHA-256 fingerprint.
    pub trusted_fingerprint: Option<String>,
}

pub struct SshTransport {
    config: SshConfig,
}

impl SshTransport {
    pub fn new(config: SshConfig) -> Result<Self, ClientError> {
        if config.host.trim().is_empty()
            || config.username.trim().is_empty()
            || config.remote_socket.trim().is_empty()
        {
            return Err(ClientError::Configuration(
                "SSH host, username, and remote socket are required".to_owned(),
            ));
        }
        if !config.private_key.is_file() {
            return Err(ClientError::Configuration(format!(
                "SSH private key {} is not readable",
                config.private_key.display()
            )));
        }
        Ok(Self { config })
    }
}

#[derive(Debug, Error)]
enum HandlerError {
    #[error(transparent)]
    Protocol(#[from] russh::Error),
    #[error("unknown SSH host key: {0}")]
    Unknown(String),
    #[error("SSH host key changed: {0}")]
    Changed(String),
}

struct Handler {
    host: String,
    port: u16,
    app_known_hosts: PathBuf,
    trusted_fingerprint: Option<String>,
}

impl client::Handler for Handler {
    type Error = HandlerError;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match check_known_hosts(&self.host, self.port, server_public_key) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(error) => return Err(HandlerError::Changed(error.to_string())),
        }
        match check_known_hosts_path(
            &self.host,
            self.port,
            server_public_key,
            &self.app_known_hosts,
        ) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(error) => return Err(HandlerError::Changed(error.to_string())),
        }

        let fingerprint = server_public_key
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        if self.trusted_fingerprint.as_deref() == Some(&fingerprint) {
            russh::keys::known_hosts::learn_known_hosts_path(
                &self.host,
                self.port,
                server_public_key,
                &self.app_known_hosts,
            )
            .map_err(|error| HandlerError::Changed(error.to_string()))?;
            return Ok(true);
        }
        Err(HandlerError::Unknown(fingerprint))
    }
}

#[async_trait]
impl ApiTransport for SshTransport {
    async fn execute(&self, request: TransportRequest) -> Result<TransportResponse, ClientError> {
        let key = load_secret_key(
            &self.config.private_key,
            self.config
                .private_key_passphrase
                .as_ref()
                .map(|value| value.expose_secret()),
        )
        .map_err(|error| ClientError::Ssh(format!("could not load SSH private key: {error}")))?;
        let ssh_config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(30)),
            ..client::Config::default()
        });
        let handler = Handler {
            host: self.config.host.clone(),
            port: self.config.port,
            app_known_hosts: self.config.application_known_hosts.clone(),
            trusted_fingerprint: self.config.trusted_fingerprint.clone(),
        };
        let mut session = client::connect(
            ssh_config,
            (self.config.host.as_str(), self.config.port),
            handler,
        )
        .await
        .map_err(map_handler_error)?;
        let hash = session
            .best_supported_rsa_hash()
            .await
            .map_err(|error| ClientError::Ssh(error.to_string()))?
            .flatten();
        let authentication = session
            .authenticate_publickey(
                self.config.username.clone(),
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
            .map_err(|error| ClientError::Ssh(error.to_string()))?;
        if !authentication.success() {
            return Err(ClientError::SshAuthentication);
        }

        let channel = session
            .channel_open_direct_streamlocal(self.config.remote_socket.clone())
            .await
            .map_err(|error| ClientError::RemoteSocket(error.to_string()))?;
        let io = TokioIo::new(channel.into_stream());
        let (mut sender, connection) = http1::handshake(io)
            .await
            .map_err(|error| ClientError::RemoteSocket(error.to_string()))?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(error = %error, "SSH HTTP channel closed");
            }
        });

        let mut outgoing = http::Request::builder()
            .method(request.method)
            .uri(&request.path_and_query)
            .header(http::header::HOST, "helium-sync-unix-socket");
        for (name, value) in &request.headers {
            outgoing = outgoing.header(name, value);
        }
        let outgoing = outgoing
            .body(Full::new(Bytes::from(request.body)))
            .map_err(|error| ClientError::Serialization(error.to_string()))?;
        let response = sender
            .send_request(outgoing)
            .await
            .map_err(|error| ClientError::RemoteSocket(error.to_string()))?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| ClientError::RemoteSocket(error.to_string()))?
            .to_bytes()
            .to_vec();
        let _ = session
            .disconnect(Disconnect::ByApplication, "request complete", "en")
            .await;
        Ok(TransportResponse {
            status,
            headers,
            body,
        })
    }
}

fn map_handler_error(error: HandlerError) -> ClientError {
    match error {
        HandlerError::Unknown(fingerprint) => ClientError::SshHostKeyUnknown { fingerprint },
        HandlerError::Changed(message) => ClientError::SshHostKeyChanged(message),
        HandlerError::Protocol(error) => ClientError::Ssh(error.to_string()),
    }
}
