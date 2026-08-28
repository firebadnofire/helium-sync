use std::{path::PathBuf, sync::Arc};

use directories::ProjectDirs;
use helium_sync_client_core::{
    api::ApiClient,
    crypto::MasterKey,
    https::{CertificateMode, HttpsTransport, spki_sha256_from_pem},
    orchestration::{ClientCore, SyncProof},
    secrets::{NativeSecretStore, SecretStore as _},
    ssh::{SshConfig, SshTransport},
    state::LocalState,
};
use helium_sync_profile::{DiscoveryOptions, DiscoveryReport};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::sync::Mutex;
use url::Url;

struct UiSession {
    core: Arc<ClientCore>,
    recovery_code: SecretString,
}

struct UiState {
    session: Mutex<Option<UiSession>>,
    secrets: NativeSecretStore,
    data_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpsInput {
    url: String,
    port: u16,
    api_token: String,
    certificate_mode: String,
    certificate_path: Option<PathBuf>,
    spki_pin: Option<String>,
    device_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshInput {
    host: String,
    port: u16,
    username: String,
    private_key: PathBuf,
    private_key_passphrase: Option<String>,
    remote_socket: String,
    api_token: String,
    trusted_fingerprint: Option<String>,
    device_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticCheck {
    name: String,
    ok: bool,
    summary: String,
    details: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticReport {
    checks: Vec<DiagnosticCheck>,
}

#[tauri::command]
fn discover_profiles() -> Result<DiscoveryReport, String> {
    helium_sync_profile::discover(&DiscoveryOptions::from_environment())
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn inspect_certificate(path: PathBuf) -> Result<String, String> {
    spki_sha256_from_pem(&path).map_err(|error| error.to_string())
}

#[tauri::command]
async fn connect_https(
    input: HttpsInput,
    state: State<'_, UiState>,
) -> Result<DiagnosticReport, String> {
    let mut url_text = input.url.trim().to_owned();
    if !url_text.contains("://") {
        url_text = format!("https://{url_text}");
    }
    let mut url = Url::parse(&url_text).map_err(|error| format!("Server URL: {error}"))?;
    if url.port().is_none() {
        url.set_port(Some(input.port))
            .map_err(|()| "Server URL cannot accept a port".to_owned())?;
    }
    if !url.path().ends_with('/') {
        url.set_path("/");
    }
    let certificate_mode = match input.certificate_mode.as_str() {
        "system" => CertificateMode::SystemTrust,
        "custom_ca" => CertificateMode::CustomCa {
            pem_path: input
                .certificate_path
                .ok_or_else(|| "Custom CA certificate path is required".to_owned())?,
        },
        "pinned" => CertificateMode::Pinned {
            certificate_pem: input
                .certificate_path
                .ok_or_else(|| "Pinned certificate path is required".to_owned())?,
            spki_sha256: input
                .spki_pin
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| "SPKI pin is required".to_owned())?,
        },
        _ => return Err("Unknown certificate mode".to_owned()),
    };
    let endpoint = url.to_string();
    let transport =
        HttpsTransport::new(url, certificate_mode).map_err(|error| error.to_string())?;
    connect(
        Arc::new(transport),
        input.api_token,
        input.device_name,
        &state,
        "HTTPS",
        &endpoint,
    )
    .await
}

#[tauri::command]
async fn connect_ssh(
    input: SshInput,
    state: State<'_, UiState>,
) -> Result<DiagnosticReport, String> {
    if let Some(passphrase) = &input.private_key_passphrase
        && !passphrase.is_empty()
    {
        state
            .secrets
            .set(
                "ssh-key-passphrase",
                &SecretString::from(passphrase.clone()),
            )
            .map_err(|error| error.to_string())?;
    }
    let endpoint = format!("{}:{}:{}", input.host, input.port, input.remote_socket);
    let transport = SshTransport::new(SshConfig {
        host: input.host,
        port: input.port,
        username: input.username,
        private_key: input.private_key,
        private_key_passphrase: input
            .private_key_passphrase
            .filter(|value| !value.is_empty())
            .map(SecretString::from),
        remote_socket: input.remote_socket,
        application_known_hosts: state.data_dir.join("known_hosts"),
        trusted_fingerprint: input
            .trusted_fingerprint
            .filter(|value| !value.trim().is_empty()),
    })
    .map_err(|error| error.to_string())?;
    connect(
        Arc::new(transport),
        input.api_token,
        input.device_name,
        &state,
        "SSH",
        &endpoint,
    )
    .await
}

async fn connect(
    transport: Arc<dyn helium_sync_client_core::transport::ApiTransport>,
    api_token: String,
    device_name: String,
    state: &State<'_, UiState>,
    transport_name: &str,
    endpoint: &str,
) -> Result<DiagnosticReport, String> {
    if api_token.len() < 32 {
        return Err("API token must contain at least 32 characters".to_owned());
    }
    state
        .secrets
        .set("api-token", &SecretString::from(api_token.clone()))
        .map_err(|error| error.to_string())?;
    let (master_key, recovery_code) = load_or_create_master_key(&state.secrets)?;
    let local = LocalState::open(&state.data_dir.join("client.sqlite3"))
        .await
        .map_err(|error| error.to_string())?;
    local
        .save_connection(endpoint, &transport_name.to_ascii_lowercase(), endpoint)
        .await
        .map_err(|error| error.to_string())?;
    let device_id = local.device_id().await.map_err(|error| error.to_string())?;
    let api = Arc::new(ApiClient::new(transport, SecretString::from(api_token)));
    let version = api.negotiate().await.map_err(|error| error.to_string())?;
    let status = api.status().await.map_err(|error| error.to_string())?;
    let core = Arc::new(ClientCore::new(api, master_key, device_id));
    core.register_device(device_name.trim())
        .await
        .map_err(|error| error.to_string())?;
    *state.session.lock().await = Some(UiSession {
        core,
        recovery_code,
    });
    Ok(DiagnosticReport {
        checks: vec![
            check(
                format!("{transport_name} connection"),
                format!("{transport_name} transport connected"),
                "Certificate or host-key verification succeeded.".to_owned(),
            ),
            check(
                "API authentication".to_owned(),
                "Bearer token accepted".to_owned(),
                "The token was sent only in the authenticated transport.".to_owned(),
            ),
            check(
                "Protocol".to_owned(),
                format!("Protocol {} compatible", status.protocol.0),
                format!(
                    "Server {} supports {}-{} with capabilities: {}",
                    version.server_version,
                    version.protocol.min.0,
                    version.protocol.max.0,
                    version.capabilities.join(", ")
                ),
            ),
            check(
                "Database".to_owned(),
                "Server health is OK".to_owned(),
                format!(
                    "Server status: {}; database: {}",
                    status.status, status.database
                ),
            ),
        ],
    })
}

#[tauri::command]
async fn run_synthetic(state: State<'_, UiState>) -> Result<SyncProof, String> {
    let core = session_core(&state).await?;
    core.synthetic_round_trip()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn run_bookmarks(
    profile_directory: String,
    state: State<'_, UiState>,
) -> Result<SyncProof, String> {
    let report = helium_sync_profile::discover(&DiscoveryOptions::from_environment())
        .map_err(|error| error.to_string())?;
    let profile = report
        .profiles
        .iter()
        .find(|profile| profile.directory_name == profile_directory)
        .ok_or_else(|| "Selected Helium profile is no longer available".to_owned())?;
    let core = session_core(&state).await?;
    core.bookmark_round_trip(profile)
        .await
        .map(|(proof, _)| proof)
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn reveal_recovery_code(state: State<'_, UiState>) -> Result<String, String> {
    state
        .session
        .lock()
        .await
        .as_ref()
        .map(|session| session.recovery_code.expose_secret().to_owned())
        .ok_or_else(|| "Connect to a server before revealing the recovery code".to_owned())
}

#[tauri::command]
async fn import_recovery_code(
    recovery_code: String,
    state: State<'_, UiState>,
) -> Result<(), String> {
    MasterKey::from_recovery_code(&recovery_code).map_err(|error| error.to_string())?;
    state
        .secrets
        .set("sync-master-key", &SecretString::from(recovery_code))
        .map_err(|error| error.to_string())?;
    *state.session.lock().await = None;
    Ok(())
}

async fn session_core(state: &State<'_, UiState>) -> Result<Arc<ClientCore>, String> {
    state
        .session
        .lock()
        .await
        .as_ref()
        .map(|session| Arc::clone(&session.core))
        .ok_or_else(|| "Connect to a server first".to_owned())
}

fn load_or_create_master_key(
    store: &NativeSecretStore,
) -> Result<(MasterKey, SecretString), String> {
    if let Some(stored) = store
        .get("sync-master-key")
        .map_err(|error| error.to_string())?
    {
        let code = stored.expose_secret().to_owned();
        let key = MasterKey::from_recovery_code(&code).map_err(|error| error.to_string())?;
        return Ok((key, SecretString::from(code)));
    }
    let key = MasterKey::generate();
    let code = key.recovery_code();
    store
        .set("sync-master-key", &SecretString::from(code.clone()))
        .map_err(|error| error.to_string())?;
    Ok((key, SecretString::from(code)))
}

fn check(name: String, summary: String, details: String) -> DiagnosticCheck {
    DiagnosticCheck {
        name,
        ok: true,
        summary,
        details,
    }
}

fn main() {
    let project_dirs = ProjectDirs::from("org", "helium-sync", "Helium Sync")
        .expect("operating system did not provide an application data directory");
    let data_dir = project_dirs.data_local_dir().to_path_buf();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(UiState {
            session: Mutex::new(None),
            secrets: NativeSecretStore::new("org.helium-sync.client"),
            data_dir,
        })
        .invoke_handler(tauri::generate_handler![
            discover_profiles,
            inspect_certificate,
            connect_https,
            connect_ssh,
            run_synthetic,
            run_bookmarks,
            reveal_recovery_code,
            import_recovery_code,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Helium Sync desktop client");
}
