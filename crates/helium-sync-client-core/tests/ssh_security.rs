use std::{path::PathBuf, sync::Arc};

use helium_sync_client_core::{
    api::ApiClient,
    crypto::MasterKey,
    orchestration::{ClientCore, SYNTHETIC_SENTINEL},
    ssh::{SshConfig, SshTransport},
};
use helium_sync_common::DeviceId;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use russh::{
    Channel, ChannelId,
    keys::{PrivateKey, ssh_key},
    server::{self, Auth, Msg, Server as _, Session},
};
use secrecy::SecretString;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

const TOKEN: &str = "ssh-transport-token-0123456789abcdef";

#[derive(Clone)]
struct TestSshServer {
    router: axum::Router,
}

impl server::Server for TestSshServer {
    type Handler = Self;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl server::Handler for TestSshServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if socket_path != "/run/helium-sync/server.sock" {
            return Ok(());
        }
        reply.accept().await;
        let service = TowerToHyperService::new(self.router.clone());
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(channel.into_stream()), service)
                .await;
        });
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[tokio::test]
async fn ssh_streamlocal_round_trip_hides_plaintext() {
    let temp = tempfile::tempdir().unwrap();
    let client_key_path = temp.path().join("client_key");
    let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
    std::fs::write(
        &client_key_path,
        client_key.to_openssh(ssh_key::LineEnding::LF).unwrap(),
    )
    .unwrap();

    let host_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
    let host_fingerprint = host_key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    let server_config = Arc::new(server::Config {
        auth_rejection_time: std::time::Duration::from_millis(10),
        keys: vec![host_key],
        ..server::Config::default()
    });

    let pool = helium_sync_server::storage::memory().await.unwrap();
    let api_state =
        helium_sync_server::api::AppState::new(pool, &SecretString::from(TOKEN.to_owned()));
    let mut ssh_server = TestSshServer {
        router: helium_sync_server::router(api_state),
    };
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let backend_address = reservation.local_addr().unwrap();
    drop(reservation);
    let server_task = tokio::spawn(async move {
        ssh_server
            .run_on_address(server_config, backend_address)
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let proxy_capture = Arc::clone(&captured);
    let proxy_task = tokio::spawn(async move {
        loop {
            let Ok((incoming, _)) = proxy_listener.accept().await else {
                break;
            };
            let capture = Arc::clone(&proxy_capture);
            tokio::spawn(async move {
                let outgoing = TcpStream::connect(backend_address).await.unwrap();
                proxy_connection(incoming, outgoing, capture).await;
            });
        }
    });

    let transport = SshTransport::new(SshConfig {
        host: "127.0.0.1".to_owned(),
        port: proxy_address.port(),
        username: "test".to_owned(),
        private_key: client_key_path,
        private_key_passphrase: None,
        remote_socket: "/run/helium-sync/server.sock".to_owned(),
        application_known_hosts: PathBuf::from(temp.path()).join("known_hosts"),
        trusted_fingerprint: Some(host_fingerprint),
    })
    .unwrap();
    let api = Arc::new(ApiClient::new(
        Arc::new(transport),
        SecretString::from(TOKEN.to_owned()),
    ));
    let core = ClientCore::new(api, MasterKey::generate(), DeviceId::new());
    core.register_device("SSH security test").await.unwrap();
    assert!(core.synthetic_round_trip().await.unwrap().plaintext_matches);

    let bytes = captured.lock().await.clone();
    assert!(!contains(&bytes, SYNTHETIC_SENTINEL.as_bytes()));
    assert!(!contains(&bytes, TOKEN.as_bytes()));
    assert!(temp.path().join("known_hosts").is_file());

    server_task.abort();
    proxy_task.abort();
}

async fn proxy_connection(incoming: TcpStream, outgoing: TcpStream, captured: Arc<Mutex<Vec<u8>>>) {
    let (mut incoming_read, mut incoming_write) = incoming.into_split();
    let (mut outgoing_read, mut outgoing_write) = outgoing.into_split();
    let upstream_capture = Arc::clone(&captured);
    let upstream = async move {
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = incoming_read.read(&mut buffer).await.unwrap_or(0);
            if read == 0 {
                let _ = outgoing_write.shutdown().await;
                break;
            }
            upstream_capture
                .lock()
                .await
                .extend_from_slice(&buffer[..read]);
            if outgoing_write.write_all(&buffer[..read]).await.is_err() {
                break;
            }
        }
    };
    let downstream = async move {
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = outgoing_read.read(&mut buffer).await.unwrap_or(0);
            if read == 0 {
                let _ = incoming_write.shutdown().await;
                break;
            }
            captured.lock().await.extend_from_slice(&buffer[..read]);
            if incoming_write.write_all(&buffer[..read]).await.is_err() {
                break;
            }
        }
    };
    tokio::join!(upstream, downstream);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
