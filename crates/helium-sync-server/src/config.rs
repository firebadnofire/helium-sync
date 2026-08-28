use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse configuration {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Default)]
pub struct ConfigOverrides {
    pub config: Option<PathBuf>,
    pub listen: Option<SocketAddr>,
    pub unix_socket: Option<PathBuf>,
    pub unix_socket_group: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub tls_certificate: Option<PathBuf>,
    pub tls_private_key: Option<PathBuf>,
    pub database: Option<PathBuf>,
    pub log_level: Option<String>,
    pub token_file: Option<PathBuf>,
}

pub struct ServerConfig {
    pub listen: SocketAddr,
    pub unix_socket: PathBuf,
    pub unix_socket_mode: u32,
    pub unix_socket_group: Option<String>,
    pub data_dir: PathBuf,
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
    pub token: SecretString,
    pub database: PathBuf,
    pub log_level: String,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerConfig")
            .field("listen", &self.listen)
            .field("unix_socket", &self.unix_socket)
            .field(
                "unix_socket_mode",
                &format_args!("{:04o}", self.unix_socket_mode),
            )
            .field("unix_socket_group", &self.unix_socket_group)
            .field("data_dir", &self.data_dir)
            .field("tls_certificate", &self.tls_certificate)
            .field("tls_private_key", &self.tls_private_key)
            .field("token", &"[REDACTED]")
            .field("database", &self.database)
            .field("log_level", &self.log_level)
            .finish()
    }
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    server: Option<FileServer>,
    tls: Option<FileTls>,
    auth: Option<FileAuth>,
    storage: Option<FileStorage>,
    logging: Option<FileLogging>,
}

#[derive(Debug, Default, Deserialize)]
struct FileServer {
    listen: Option<String>,
    unix_socket: Option<PathBuf>,
    unix_socket_mode: Option<String>,
    unix_socket_group: Option<String>,
    data_dir: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct FileTls {
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct FileAuth {
    token: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FileStorage {
    database: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct FileLogging {
    level: Option<String>,
}

impl ServerConfig {
    pub fn load(overrides: ConfigOverrides) -> Result<Self, ConfigError> {
        let config_path = overrides
            .config
            .clone()
            .or_else(|| env_path("HELIUM_SYNC_CONFIG"));
        let file = match config_path {
            Some(path) => {
                let value = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
                    path: path.clone(),
                    source,
                })?;
                toml::from_str(&value).map_err(|source| ConfigError::Parse { path, source })?
            }
            None => FileConfig::default(),
        };

        let file_server = file.server.unwrap_or_default();
        let file_tls = file.tls.unwrap_or_default();
        let file_auth = file.auth.unwrap_or_default();
        let file_storage = file.storage.unwrap_or_default();
        let file_logging = file.logging.unwrap_or_default();

        let data_dir = overrides
            .data_dir
            .or_else(|| env_path("HELIUM_SYNC_DATA_DIR"))
            .or(file_server.data_dir)
            .unwrap_or_else(|| PathBuf::from("/var/lib/helium-sync"));
        let listen_text = overrides
            .listen
            .map(|value| value.to_string())
            .or_else(|| env::var("HELIUM_SYNC_LISTEN").ok())
            .or(file_server.listen)
            .unwrap_or_else(|| "0.0.0.0:7500".to_owned());
        let listen = listen_text.parse().map_err(|_| {
            ConfigError::Invalid(format!("listen address {listen_text:?} is not valid"))
        })?;
        let token = if let Some(path) = overrides.token_file {
            fs::read_to_string(&path)
                .map_err(|source| ConfigError::Read { path, source })?
                .trim()
                .to_owned()
        } else {
            env::var("HELIUM_SYNC_TOKEN")
                .ok()
                .or(file_auth.token)
                .unwrap_or_default()
        };
        let socket_mode = env::var("HELIUM_SYNC_UNIX_SOCKET_MODE")
            .ok()
            .or(file_server.unix_socket_mode)
            .unwrap_or_else(|| "0660".to_owned());
        let mode_digits = socket_mode
            .strip_prefix("0o")
            .unwrap_or(socket_mode.trim_start_matches('0'));
        let mode_digits = if mode_digits.is_empty() {
            "0"
        } else {
            mode_digits
        };
        let unix_socket_mode = u32::from_str_radix(mode_digits, 8).map_err(|_| {
            ConfigError::Invalid(format!("Unix socket mode {socket_mode:?} is not octal"))
        })?;

        let config = Self {
            listen,
            unix_socket: overrides
                .unix_socket
                .or_else(|| env_path("HELIUM_SYNC_UNIX_SOCKET"))
                .or(file_server.unix_socket)
                .unwrap_or_else(|| PathBuf::from("/run/helium-sync/server.sock")),
            unix_socket_mode,
            unix_socket_group: overrides
                .unix_socket_group
                .or_else(|| env::var("HELIUM_SYNC_UNIX_SOCKET_GROUP").ok())
                .or(file_server.unix_socket_group),
            tls_certificate: overrides
                .tls_certificate
                .or_else(|| env_path("HELIUM_SYNC_TLS_CERTIFICATE"))
                .or(file_tls.certificate)
                .unwrap_or_default(),
            tls_private_key: overrides
                .tls_private_key
                .or_else(|| env_path("HELIUM_SYNC_TLS_PRIVATE_KEY"))
                .or(file_tls.private_key)
                .unwrap_or_default(),
            database: overrides
                .database
                .or_else(|| env_path("HELIUM_SYNC_DATABASE"))
                .or(file_storage.database)
                .unwrap_or_else(|| data_dir.join("server.sqlite3")),
            log_level: overrides
                .log_level
                .or_else(|| env::var("HELIUM_SYNC_LOG_LEVEL").ok())
                .or(file_logging.level)
                .unwrap_or_else(|| "info".to_owned()),
            token: SecretString::from(token),
            data_dir,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let token = self.token.expose_secret();
        if token.len() < 32 || token == "replace-me" {
            return Err(ConfigError::Invalid(
                "authentication token must contain at least 32 characters and must not be the example placeholder"
                    .to_owned(),
            ));
        }
        if self.unix_socket_mode & !0o777 != 0 || self.unix_socket_mode == 0 {
            return Err(ConfigError::Invalid(
                "Unix socket mode must be a non-zero permission mode between 0001 and 0777"
                    .to_owned(),
            ));
        }
        validate_file(&self.tls_certificate, "TLS certificate")?;
        validate_file(&self.tls_private_key, "TLS private key")?;
        validate_parent(&self.data_dir, "data directory")?;
        validate_parent(&self.database, "database")?;
        validate_parent(&self.unix_socket, "Unix socket")?;
        crate::tls::validate_material(&self.tls_certificate, &self.tls_private_key)
            .map_err(ConfigError::Invalid)?;
        Ok(())
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn validate_file(path: &Path, label: &str) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::Invalid(format!("{label} path is required")));
    }
    let metadata = fs::metadata(path).map_err(|error| {
        ConfigError::Invalid(format!(
            "{label} {} is not readable: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(ConfigError::Invalid(format!(
            "{label} {} is not a file",
            path.display()
        )));
    }
    Ok(())
}

fn validate_parent(path: &Path, label: &str) -> Result<(), ConfigError> {
    let mut candidate = if path.extension().is_some() {
        path.parent().unwrap_or(Path::new("."))
    } else {
        path
    };
    while !candidate.exists() {
        candidate = candidate.parent().ok_or_else(|| {
            ConfigError::Invalid(format!("{label} {} has no existing parent", path.display()))
        })?;
    }
    let metadata = fs::metadata(candidate).map_err(|error| {
        ConfigError::Invalid(format!(
            "cannot inspect {label} parent {}: {error}",
            candidate.display()
        ))
    })?;
    if !metadata.is_dir() || metadata.permissions().readonly() {
        return Err(ConfigError::Invalid(format!(
            "{label} parent {} is not a writable directory",
            candidate.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_token() {
        let config = ServerConfig {
            listen: "127.0.0.1:7500".parse().unwrap(),
            unix_socket: "/tmp/test.sock".into(),
            unix_socket_mode: 0o660,
            unix_socket_group: None,
            data_dir: "/tmp".into(),
            tls_certificate: "/tmp/cert".into(),
            tls_private_key: "/tmp/key".into(),
            token: SecretString::from("THIS_TOKEN_MUST_NEVER_APPEAR_123456".to_owned()),
            database: "/tmp/db".into(),
            log_level: "info".to_owned(),
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("THIS_TOKEN"));
        assert!(debug.contains("REDACTED"));
    }
}
