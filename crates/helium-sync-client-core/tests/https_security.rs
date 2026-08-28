use std::sync::Arc;

use helium_sync_client_core::{
    api::ApiClient,
    crypto::MasterKey,
    https::{CertificateMode, HttpsTransport},
    orchestration::{ClientCore, SYNTHETIC_SENTINEL},
};
use helium_sync_common::DeviceId;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use secrecy::SecretString;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use url::Url;

const TOKEN: &str = "transport-test-token-0123456789abcdef";

#[tokio::test]
async fn https_round_trip_hides_plaintext_and_rejects_bad_trust() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let cert_path = temp.path().join("server.crt");
    let key_path = temp.path().join("server.key");
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();

    let pool = helium_sync_server::storage::memory().await.unwrap();
    let state = helium_sync_server::api::AppState::new(pool, &SecretString::from(TOKEN.to_owned()));
    let server_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    server_listener.set_nonblocking(true).unwrap();
    let server_address = server_listener.local_addr().unwrap();
    let tls = helium_sync_server::tls::load_rustls_config(&cert_path, &key_path).unwrap();
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let server_task = tokio::spawn(async move {
        axum_server::from_tcp_rustls(server_listener, tls)
            .unwrap()
            .handle(server_handle)
            .serve(helium_sync_server::router(state).into_make_service())
            .await
            .unwrap();
    });

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
                let outgoing = TcpStream::connect(server_address).await.unwrap();
                proxy_connection(incoming, outgoing, capture).await;
            });
        }
    });

    let trusted = HttpsTransport::new(
        Url::parse(&format!("https://localhost:{}/", proxy_address.port())).unwrap(),
        CertificateMode::CustomCa {
            pem_path: cert_path.clone(),
        },
    )
    .unwrap();
    let api = Arc::new(ApiClient::new(
        Arc::new(trusted),
        SecretString::from(TOKEN.to_owned()),
    ));
    let core = ClientCore::new(api, MasterKey::generate(), DeviceId::new());
    core.register_device("HTTPS security test").await.unwrap();
    assert!(core.synthetic_round_trip().await.unwrap().plaintext_matches);

    let bytes = captured.lock().await.clone();
    assert!(!contains(&bytes, SYNTHETIC_SENTINEL.as_bytes()));
    assert!(!contains(&bytes, TOKEN.as_bytes()));

    let untrusted = HttpsTransport::new(
        Url::parse(&format!("https://localhost:{}/", proxy_address.port())).unwrap(),
        CertificateMode::SystemTrust,
    )
    .unwrap();
    let untrusted_api = ApiClient::new(Arc::new(untrusted), SecretString::from(TOKEN.to_owned()));
    assert!(untrusted_api.negotiate().await.is_err());

    let mismatched = HttpsTransport::new(
        Url::parse(&format!("https://127.0.0.1:{}/", proxy_address.port())).unwrap(),
        CertificateMode::CustomCa {
            pem_path: cert_path,
        },
    )
    .unwrap();
    let mismatched_api = ApiClient::new(Arc::new(mismatched), SecretString::from(TOKEN.to_owned()));
    assert!(mismatched_api.negotiate().await.is_err());

    handle.graceful_shutdown(Some(std::time::Duration::from_secs(1)));
    proxy_task.abort();
    let _ = server_task.await;
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
