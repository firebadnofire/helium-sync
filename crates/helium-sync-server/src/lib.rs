//! Linux Helium Sync server implementation.

pub mod api;
pub mod auth;
pub mod config;
pub mod storage;
pub mod tls;

use axum::Router;
use config::ServerConfig;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Storage(#[from] sqlx::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("TLS configuration failed: {0}")]
    Tls(String),
    #[error("the server runtime is supported only on Linux")]
    UnsupportedPlatform,
    #[error("listener stopped unexpectedly: {0}")]
    Listener(String),
}

pub async fn prepare(config: &ServerConfig) -> Result<api::AppState, ServerError> {
    config.validate()?;
    tokio::fs::create_dir_all(&config.data_dir).await?;
    if let Some(parent) = config.database.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if let Some(parent) = config.unix_socket.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let pool = storage::open(&config.database).await?;
    Ok(api::AppState::new(pool, &config.token))
}

pub fn router(state: api::AppState) -> Router {
    api::router(state)
}

#[cfg(target_os = "linux")]
async fn hsts(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        axum::http::HeaderValue::from_static("max-age=31536000"),
    );
    response
}

#[cfg(target_os = "linux")]
pub async fn serve(config: ServerConfig) -> Result<(), ServerError> {
    use std::{
        os::unix::fs::{FileTypeExt as _, PermissionsExt as _},
        time::Duration,
    };
    use tokio::sync::watch;

    let state = prepare(&config).await?;
    let tls_config = tls::load_rustls_config(&config.tls_certificate, &config.tls_private_key)?;

    if config.unix_socket.exists() {
        let metadata = std::fs::symlink_metadata(&config.unix_socket)?;
        if !metadata.file_type().is_socket() {
            return Err(ServerError::Config(config::ConfigError::Invalid(format!(
                "refusing to replace non-socket path {}",
                config.unix_socket.display()
            ))));
        }
        match tokio::net::UnixStream::connect(&config.unix_socket).await {
            Ok(_) => {
                return Err(ServerError::Config(config::ConfigError::Invalid(format!(
                    "Unix socket {} is already active",
                    config.unix_socket.display()
                ))));
            }
            Err(_) => std::fs::remove_file(&config.unix_socket)?,
        }
    }

    // Bind and configure every listener before serving either one. In particular,
    // a TCP port conflict must not leave a Unix-only process that still appears
    // healthy to a service manager.
    let tcp_listener = bind_tcp_listener(config.listen)?;
    let tcp_server = axum_server::from_tcp_rustls(tcp_listener, tls_config)?;

    let unix_listener = tokio::net::UnixListener::bind(&config.unix_socket)?;
    let socket_setup = (|| -> Result<(), ServerError> {
        std::fs::set_permissions(
            &config.unix_socket,
            std::fs::Permissions::from_mode(config.unix_socket_mode),
        )?;
        if let Some(group_name) = &config.unix_socket_group {
            let group = nix::unistd::Group::from_name(group_name)
                .map_err(|error| {
                    ServerError::Config(config::ConfigError::Invalid(format!(
                        "failed to resolve Unix socket group {group_name:?}: {error}"
                    )))
                })?
                .ok_or_else(|| {
                    ServerError::Config(config::ConfigError::Invalid(format!(
                        "Unix socket group {group_name:?} does not exist"
                    )))
                })?;
            nix::unistd::chown(&config.unix_socket, None, Some(group.gid)).map_err(|error| {
                ServerError::Config(config::ConfigError::Invalid(format!(
                    "failed to set Unix socket group {group_name:?}: {error}"
                )))
            })?;
        }
        Ok(())
    })();
    if let Err(error) = socket_setup {
        drop(unix_listener);
        let _ = remove_owned_socket(&config.unix_socket);
        return Err(error);
    }

    let shared = router(state);
    let https_router = shared.clone().layer(axum::middleware::from_fn(hsts));
    let handle = axum_server::Handle::new();
    let tcp_handle = handle.clone();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let tcp = tokio::spawn(async move {
        tcp_server
            .handle(tcp_handle)
            .serve(https_router.into_make_service())
            .await
    });
    let unix = tokio::spawn(async move {
        axum::serve(unix_listener, shared.into_make_service())
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await
    });

    shutdown_signal().await?;
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
    let _ = shutdown_tx.send(true);

    let tcp_result = tcp
        .await
        .map_err(|error| ServerError::Listener(error.to_string()))?;
    let unix_result = unix
        .await
        .map_err(|error| ServerError::Listener(error.to_string()))?;
    tcp_result.map_err(|error| ServerError::Listener(error.to_string()))?;
    unix_result?;

    remove_owned_socket(&config.unix_socket)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_tcp_listener(
    address: std::net::SocketAddr,
) -> Result<std::net::TcpListener, std::io::Error> {
    let listener = std::net::TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(target_os = "linux")]
async fn shutdown_signal() -> Result<(), std::io::Error> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_owned_socket(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::FileTypeExt as _;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn serve(_config: ServerConfig) -> Result<(), ServerError> {
    Err(ServerError::UnsupportedPlatform)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{fs, net::TcpListener, time::Duration};

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use secrecy::SecretString;

    use super::*;

    #[tokio::test]
    async fn occupied_tcp_port_fails_before_unix_socket_is_created() {
        let temp = tempfile::tempdir().unwrap();
        let tls_dir = temp.path().join("tls");
        fs::create_dir(&tls_dir).unwrap();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(["localhost".to_owned()]).unwrap();
        let certificate = tls_dir.join("server.crt");
        let private_key = tls_dir.join("server.key");
        fs::write(&certificate, cert.pem()).unwrap();
        fs::write(&private_key, signing_key.serialize_pem()).unwrap();

        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = occupied.local_addr().unwrap();
        let unix_socket = temp.path().join("run/server.sock");
        let config = ServerConfig {
            listen,
            unix_socket: unix_socket.clone(),
            unix_socket_mode: 0o660,
            unix_socket_group: None,
            data_dir: temp.path().join("data"),
            tls_certificate: certificate,
            tls_private_key: private_key,
            token: SecretString::from("0123456789abcdef0123456789abcdef".to_owned()),
            database: temp.path().join("data/server.sqlite3"),
            log_level: "info".to_owned(),
        };

        let error = tokio::time::timeout(Duration::from_secs(2), serve(config))
            .await
            .expect("port conflict must fail promptly")
            .unwrap_err();
        assert!(
            matches!(error, ServerError::Io(ref source) if source.kind() == std::io::ErrorKind::AddrInUse),
            "unexpected error: {error}"
        );
        assert!(!unix_socket.exists());
    }

    #[test]
    fn prepared_tcp_listener_is_nonblocking() {
        let listener = bind_tcp_listener("127.0.0.1:0".parse().unwrap()).unwrap();
        let error = listener.accept().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }
}
