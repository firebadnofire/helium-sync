use std::{path::PathBuf, process::Command, sync::Arc};

use directories::{ProjectDirs, UserDirs};
use helium_sync_client_core::{
    api::ApiClient,
    crypto::MasterKey,
    https::{CertificateMode, HttpsTransport, spki_sha256_from_pem},
    orchestration::{
        BOOKMARK_NAMESPACE, ClientCore, EXTENSION_MANIFEST_NAMESPACE, ExtensionManifestV1,
        SyncProof,
    },
    secrets::{NativeSecretStore, SecretStore as _},
    ssh::{SshConfig, SshTransport},
    state::LocalState,
};
use helium_sync_profile::{
    BookmarkStats, BookmarkStatus, DiscoveredProfile, DiscoveryOptions, ExtensionBundleDescriptor,
    ExtensionBundleStats, bookmark_stats, create_extension_bundle, create_profile, merge_bookmarks,
    read_bookmarks, restore_bookmarks, restore_extension_bundle,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tauri::State;
use tokio::sync::Mutex;
use url::Url;

struct UiSession {
    core: Arc<ClientCore>,
    recovery_code: SecretString,
    local: Arc<LocalState>,
    server_id: String,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileView {
    directory_name: String,
    display_name: String,
    browser_name: String,
    bookmark_status: BookmarkStatus,
    is_default: bool,
    auto_sync: bool,
    has_saved_copy: bool,
    stats: Option<BookmarkStats>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileReport {
    profiles: Vec<ProfileView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncFeedback {
    action: String,
    profile_directory: String,
    profile_name: String,
    stats: BookmarkStats,
    revision: u64,
    conflicts: u64,
    backup_path: Option<PathBuf>,
    extension_stats: Option<ExtensionBundleStats>,
    extension_backup_path: Option<PathBuf>,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LaunchResult {
    profile_name: String,
    sync: Option<SyncFeedback>,
    message: String,
}

struct ExtensionSyncOutcome {
    stats: ExtensionBundleStats,
    backup_path: Option<PathBuf>,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginResult {
    diagnostics: DiagnosticReport,
    sync: Option<SyncFeedback>,
}

#[tauri::command]
async fn discover_profiles(state: State<'_, UiState>) -> Result<ProfileReport, String> {
    let local = local_state(&state).await?;
    profile_report(&state, &local).await
}

#[tauri::command]
async fn create_browser_profile(
    display_name: String,
    state: State<'_, UiState>,
) -> Result<ProfileReport, String> {
    let display_name = display_name.trim();
    if display_name.is_empty() || display_name.chars().count() > 128 {
        return Err("Profile name must contain 1 to 128 characters".to_owned());
    }
    ensure_helium_closed()?;
    let installation =
        helium_sync_profile::discover_installation(&DiscoveryOptions::from_environment())
            .map_err(|error| error.to_string())?;
    let profile = create_profile(&installation.user_data_dir).map_err(|error| error.to_string())?;
    let local = local_state(&state).await?;
    local
        .ensure_profile(&profile.directory_name, display_name)
        .await
        .map_err(|error| error.to_string())?;
    profile_report(&state, &local).await
}

#[tauri::command]
async fn launch_profile(
    profile_directory: String,
    state: State<'_, UiState>,
) -> Result<LaunchResult, String> {
    let profile = discovered_profile(&profile_directory)?;
    ensure_helium_closed()?;
    let sync = if state.session.lock().await.is_some()
        && profile.bookmark_status == BookmarkStatus::Readable
    {
        let (core, local, server_id) = session_context(&state).await?;
        Some(
            sync_profile_with_server(&core, &local, &server_id, &profile, &downloads_dir()?)
                .await?,
        )
    } else {
        None
    };
    let installation =
        helium_sync_profile::discover_installation(&DiscoveryOptions::from_environment())
            .map_err(|error| error.to_string())?;
    let executable = installation
        .executable
        .filter(|path| path.is_file())
        .ok_or_else(|| {
            "Helium executable was not found. Set HELIUM_SYNC_HELIUM_PATH to the executable."
                .to_owned()
        })?;
    Command::new(&executable)
        .arg(format!("--profile-directory={}", profile.directory_name))
        .spawn()
        .map_err(|error| format!("Could not launch {}: {error}", executable.display()))?;
    let name = profile_name(&local_state(&state).await?, &profile).await?;
    Ok(LaunchResult {
        profile_name: name.clone(),
        sync,
        message: format!("Launched {name}. Close Helium before switching profiles."),
    })
}

#[tauri::command]
fn inspect_certificate(path: PathBuf) -> Result<String, String> {
    spki_sha256_from_pem(&path).map_err(|error| error.to_string())
}

#[tauri::command]
async fn connect_https(
    input: HttpsInput,
    state: State<'_, UiState>,
) -> Result<LoginResult, String> {
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
async fn connect_ssh(input: SshInput, state: State<'_, UiState>) -> Result<LoginResult, String> {
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
) -> Result<LoginResult, String> {
    if api_token.len() < 32 {
        return Err("API token must contain at least 32 characters".to_owned());
    }
    state
        .secrets
        .set("api-token", &SecretString::from(api_token.clone()))
        .map_err(|error| error.to_string())?;
    let (master_key, recovery_code) = load_or_create_master_key(&state.secrets)?;
    let local = Arc::new(local_state(state).await?);
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
    let forced_sync = forced_default_sync(&local, &core, endpoint).await?;
    *state.session.lock().await = Some(UiSession {
        core,
        recovery_code,
        local,
        server_id: endpoint.to_owned(),
    });
    Ok(LoginResult {
        sync: forced_sync,
        diagnostics: DiagnosticReport {
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
        },
    })
}

#[tauri::command]
async fn rename_profile(
    profile_directory: String,
    display_name: String,
    state: State<'_, UiState>,
) -> Result<ProfileReport, String> {
    let local = local_state(&state).await?;
    ensure_discovered_profiles(&local).await?;
    local
        .rename_profile(&profile_directory, &display_name)
        .await
        .map_err(|error| error.to_string())?;
    profile_report(&state, &local).await
}

#[tauri::command]
async fn set_default_profile(
    profile_directory: String,
    state: State<'_, UiState>,
) -> Result<ProfileReport, String> {
    let local = local_state(&state).await?;
    ensure_discovered_profiles(&local).await?;
    local
        .set_default_profile(&profile_directory)
        .await
        .map_err(|error| error.to_string())?;
    profile_report(&state, &local).await
}

#[tauri::command]
async fn set_profile_auto_sync(
    profile_directory: String,
    enabled: bool,
    state: State<'_, UiState>,
) -> Result<ProfileReport, String> {
    let local = local_state(&state).await?;
    ensure_discovered_profiles(&local).await?;
    local
        .set_auto_sync(&profile_directory, enabled)
        .await
        .map_err(|error| error.to_string())?;
    profile_report(&state, &local).await
}

#[tauri::command]
async fn save_profile(
    profile_directory: String,
    state: State<'_, UiState>,
) -> Result<SyncFeedback, String> {
    ensure_helium_closed()?;
    let profile = discovered_profile(&profile_directory)?;
    let (core, local, server_id) = session_context(&state).await?;
    save_profile_to_server(&core, &local, &server_id, &profile).await
}

#[tauri::command]
async fn load_profile(
    profile_directory: String,
    state: State<'_, UiState>,
) -> Result<SyncFeedback, String> {
    ensure_helium_closed()?;
    let profile = discovered_profile(&profile_directory)?;
    let (core, local, server_id) = session_context(&state).await?;
    load_profile_from_server(&core, &local, &server_id, &profile).await
}

#[tauri::command]
async fn sync_profile(
    profile_directory: String,
    state: State<'_, UiState>,
) -> Result<SyncFeedback, String> {
    ensure_helium_closed()?;
    let profile = discovered_profile(&profile_directory)?;
    let (core, local, server_id) = session_context(&state).await?;
    sync_profile_with_server(&core, &local, &server_id, &profile, &downloads_dir()?).await
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

async fn local_state(state: &State<'_, UiState>) -> Result<LocalState, String> {
    LocalState::open(&state.data_dir.join("client.sqlite3"))
        .await
        .map_err(|error| error.to_string())
}

async fn ensure_discovered_profiles(local: &LocalState) -> Result<Vec<DiscoveredProfile>, String> {
    let report = helium_sync_profile::discover(&DiscoveryOptions::from_environment())
        .map_err(|error| error.to_string())?;
    for profile in &report.profiles {
        let initial_name = if profile.directory_name == "Default" {
            "You"
        } else {
            &profile.display_name
        };
        local
            .ensure_profile(&profile.directory_name, initial_name)
            .await
            .map_err(|error| error.to_string())?;
    }
    let preferences = local
        .profile_preferences()
        .await
        .map_err(|error| error.to_string())?;
    let current_default_is_present = preferences.iter().any(|preference| {
        preference.is_default
            && report
                .profiles
                .iter()
                .any(|profile| profile.directory_name == preference.directory_name)
    });
    if !current_default_is_present
        && let Some(profile) = report
            .profiles
            .iter()
            .find(|profile| profile.directory_name == "Default")
            .or_else(|| report.profiles.first())
    {
        local
            .set_default_profile(&profile.directory_name)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(report.profiles)
}

async fn profile_report(
    state: &State<'_, UiState>,
    local: &LocalState,
) -> Result<ProfileReport, String> {
    let profiles = ensure_discovered_profiles(local).await?;
    let preferences = local
        .profile_preferences()
        .await
        .map_err(|error| error.to_string())?;
    let connected_server = state
        .session
        .lock()
        .await
        .as_ref()
        .map(|session| session.server_id.clone());
    let mut views = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let preference = preferences
            .iter()
            .find(|preference| preference.directory_name == profile.directory_name);
        let has_saved_copy = if let Some(server_id) = &connected_server {
            local
                .mapping(server_id, BOOKMARK_NAMESPACE, &profile.directory_name)
                .await
                .map_err(|error| error.to_string())?
                .is_some()
        } else {
            false
        };
        let stats = if profile.bookmark_status == BookmarkStatus::Readable {
            helium_sync_profile::read_bookmarks(&profile.bookmarks_path, &profile.directory_name)
                .ok()
                .map(|snapshot| bookmark_stats(&snapshot))
        } else {
            None
        };
        views.push(ProfileView {
            directory_name: profile.directory_name,
            display_name: preference.map_or_else(
                || profile.display_name.clone(),
                |value| value.display_name.clone(),
            ),
            browser_name: profile.display_name,
            bookmark_status: profile.bookmark_status,
            is_default: preference.is_some_and(|value| value.is_default),
            auto_sync: preference.is_none_or(|value| value.auto_sync),
            has_saved_copy,
            stats,
        });
    }
    Ok(ProfileReport { profiles: views })
}

fn discovered_profile(profile_directory: &str) -> Result<DiscoveredProfile, String> {
    helium_sync_profile::discover(&DiscoveryOptions::from_environment())
        .map_err(|error| error.to_string())?
        .profiles
        .into_iter()
        .find(|profile| profile.directory_name == profile_directory)
        .ok_or_else(|| "Selected Helium profile is no longer available".to_owned())
}

async fn session_context(
    state: &State<'_, UiState>,
) -> Result<(Arc<ClientCore>, Arc<LocalState>, String), String> {
    state
        .session
        .lock()
        .await
        .as_ref()
        .map(|session| {
            (
                Arc::clone(&session.core),
                Arc::clone(&session.local),
                session.server_id.clone(),
            )
        })
        .ok_or_else(|| "Sign in to a server first".to_owned())
}

async fn profile_name(local: &LocalState, profile: &DiscoveredProfile) -> Result<String, String> {
    Ok(local
        .profile_preferences()
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|preference| preference.directory_name == profile.directory_name)
        .map_or_else(|| profile.display_name.clone(), |value| value.display_name))
}

fn capture_extensions(
    profile: &DiscoveredProfile,
) -> Result<(ExtensionBundleDescriptor, Vec<u8>), String> {
    let staging = tempfile::tempdir().map_err(|error| format!("Extension staging: {error}"))?;
    let archive_path = staging.path().join("extensions.zip");
    let descriptor =
        create_extension_bundle(profile, &archive_path).map_err(|error| error.to_string())?;
    let archive = std::fs::read(&archive_path)
        .map_err(|error| format!("Could not read staged extension archive: {error}"))?;
    Ok((descriptor, archive))
}

async fn persist_extension_sync_state(
    core: &ClientCore,
    local: &LocalState,
    server_id: &str,
    profile: &DiscoveredProfile,
    manifest: &ExtensionManifestV1,
    proof: &SyncProof,
) -> Result<(), String> {
    let encrypted = core
        .protect_extension_sync_base(&profile.directory_name, manifest.archive_sha256.as_bytes())
        .map_err(|error| format!("Extension sync state: {error}"))?;
    local
        .save_sync_state(
            server_id,
            EXTENSION_MANIFEST_NAMESPACE,
            &profile.directory_name,
            proof.object_id,
            proof.revision,
            &encrypted,
        )
        .await
        .map_err(|error| error.to_string())
}

async fn extension_base_hash(
    core: &ClientCore,
    local: &LocalState,
    server_id: &str,
    profile: &DiscoveredProfile,
) -> Result<Option<String>, String> {
    local
        .sync_base(
            server_id,
            EXTENSION_MANIFEST_NAMESPACE,
            &profile.directory_name,
        )
        .await
        .map_err(|error| error.to_string())?
        .map(|encrypted| {
            let plaintext = core
                .open_extension_sync_base(&profile.directory_name, &encrypted)
                .map_err(|error| format!("Stored extension sync base: {error}"))?;
            String::from_utf8(plaintext)
                .map_err(|error| format!("Stored extension sync base is invalid: {error}"))
        })
        .transpose()
}

async fn remote_extension_manifest(
    core: &ClientCore,
    local: &LocalState,
    server_id: &str,
    profile: &DiscoveredProfile,
) -> Result<Option<(ExtensionManifestV1, SyncProof)>, String> {
    let mapping = local
        .mapping(
            server_id,
            EXTENSION_MANIFEST_NAMESPACE,
            &profile.directory_name,
        )
        .await
        .map_err(|error| error.to_string())?;
    match mapping {
        Some(mapping) => core
            .load_extension_manifest(mapping.object_id)
            .await
            .map(Some)
            .map_err(|error| error.to_string()),
        None => core
            .discover_extension_bundle(&profile.directory_name)
            .await
            .map_err(|error| error.to_string()),
    }
}

async fn save_extensions_to_server(
    core: &ClientCore,
    local: &LocalState,
    server_id: &str,
    profile: &DiscoveredProfile,
) -> Result<ExtensionSyncOutcome, String> {
    let (descriptor, archive) = capture_extensions(profile)?;
    let remote = remote_extension_manifest(core, local, server_id, profile).await?;
    let (proof, manifest) = core
        .save_extension_bundle(
            &descriptor,
            &archive,
            remote.as_ref().map(|value| value.1.object_id),
            remote.as_ref().map(|value| value.1.revision),
        )
        .await
        .map_err(|error| error.to_string())?;
    persist_extension_sync_state(core, local, server_id, profile, &manifest, &proof).await?;
    Ok(ExtensionSyncOutcome {
        stats: manifest.stats,
        backup_path: None,
        message: "Uploaded installed extensions and extension data.".to_owned(),
    })
}

async fn load_extensions_from_server(
    core: &ClientCore,
    local: &LocalState,
    server_id: &str,
    profile: &DiscoveredProfile,
    backup_dir: &std::path::Path,
) -> Result<ExtensionSyncOutcome, String> {
    let (_, manifest_proof) = remote_extension_manifest(core, local, server_id, profile)
        .await?
        .ok_or_else(|| "This profile has no saved extension copy.".to_owned())?;
    let (manifest, archive, proof) = core
        .load_extension_bundle(manifest_proof.object_id)
        .await
        .map_err(|error| error.to_string())?;
    let staging = tempfile::tempdir().map_err(|error| format!("Extension staging: {error}"))?;
    let archive_path = staging.path().join("extensions.zip");
    std::fs::write(&archive_path, archive)
        .map_err(|error| format!("Could not stage downloaded extension archive: {error}"))?;
    let restored = restore_extension_bundle(profile, &archive_path, backup_dir)
        .map_err(|error| error.to_string())?;
    persist_extension_sync_state(core, local, server_id, profile, &manifest, &proof).await?;
    Ok(ExtensionSyncOutcome {
        stats: restored.stats,
        backup_path: Some(restored.backup_path),
        message: "Restored installed extensions and extension data after backup.".to_owned(),
    })
}

async fn sync_extensions_with_server(
    core: &ClientCore,
    local: &LocalState,
    server_id: &str,
    profile: &DiscoveredProfile,
    backup_dir: &std::path::Path,
) -> Result<ExtensionSyncOutcome, String> {
    let (descriptor, archive) = capture_extensions(profile)?;
    let Some((remote, proof)) = remote_extension_manifest(core, local, server_id, profile).await?
    else {
        let (proof, manifest) = core
            .save_extension_bundle(&descriptor, &archive, None, None)
            .await
            .map_err(|error| error.to_string())?;
        persist_extension_sync_state(core, local, server_id, profile, &manifest, &proof).await?;
        return Ok(ExtensionSyncOutcome {
            stats: manifest.stats,
            backup_path: None,
            message: "Started encrypted extension sync.".to_owned(),
        });
    };
    let base = extension_base_hash(core, local, server_id, profile).await?;
    if base.is_none() && descriptor.archive_sha256 == remote.archive_sha256 {
        persist_extension_sync_state(core, local, server_id, profile, &remote, &proof).await?;
        return Ok(ExtensionSyncOutcome {
            stats: remote.stats,
            backup_path: None,
            message: "Extensions are already up to date.".to_owned(),
        });
    }
    let local_changed = base
        .as_ref()
        .is_none_or(|hash| hash != &descriptor.archive_sha256);
    let remote_changed = base
        .as_ref()
        .is_none_or(|hash| hash != &remote.archive_sha256);
    match (base.is_some(), local_changed, remote_changed) {
        (_, false, false) | (false, _, false) => {
            persist_extension_sync_state(core, local, server_id, profile, &remote, &proof).await?;
            Ok(ExtensionSyncOutcome {
                stats: remote.stats,
                backup_path: None,
                message: "Extensions are already up to date.".to_owned(),
            })
        }
        (false, _, true) | (true, false, true) => {
            load_extensions_from_server(core, local, server_id, profile, backup_dir).await
        }
        (true, true, false) => save_extensions_to_server(core, local, server_id, profile).await,
        (true, true, true) => Err(
            "Extensions changed both locally and on the server. Use Recovery to explicitly replace the server copy or restore the server copy."
                .to_owned(),
        ),
    }
}

async fn save_profile_to_server(
    core: &ClientCore,
    local: &LocalState,
    server_id: &str,
    profile: &DiscoveredProfile,
) -> Result<SyncFeedback, String> {
    let extensions = save_extensions_to_server(core, local, server_id, profile)
        .await
        .map_err(|error| format!("Extension save failed before bookmarks were changed: {error}"))?;
    let mapping = local
        .mapping(server_id, BOOKMARK_NAMESPACE, &profile.directory_name)
        .await
        .map_err(|error| error.to_string())?;
    let (proof, snapshot) = core
        .save_bookmarks(
            profile,
            mapping.as_ref().map(|value| value.object_id),
            mapping.as_ref().map(|value| value.revision),
        )
        .await
        .map_err(|error| error.to_string())?;
    persist_sync_state(core, local, server_id, profile, &snapshot, &proof).await?;
    let stats = bookmark_stats(&snapshot);
    Ok(SyncFeedback {
        action: "saved".to_owned(),
        profile_directory: profile.directory_name.clone(),
        profile_name: profile_name(local, profile).await?,
        message: format!(
            "Saved {} bookmarks in {} folders. {}",
            stats.bookmarks, stats.folders, extensions.message
        ),
        stats,
        revision: proof.revision,
        conflicts: 0,
        backup_path: None,
        extension_stats: Some(extensions.stats),
        extension_backup_path: extensions.backup_path,
    })
}

async fn load_profile_from_server(
    core: &ClientCore,
    local: &LocalState,
    server_id: &str,
    profile: &DiscoveredProfile,
) -> Result<SyncFeedback, String> {
    let downloads = downloads_dir()?;
    let extensions = load_extensions_from_server(core, local, server_id, profile, &downloads)
        .await
        .map_err(|error| {
            format!("Extension restore failed before bookmarks were changed: {error}")
        })?;
    let mapping = local
        .mapping(server_id, BOOKMARK_NAMESPACE, &profile.directory_name)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            "This profile has no saved server copy. Save it before loading.".to_owned()
        })?;
    let (snapshot, proof) = core
        .load_bookmarks(mapping.object_id)
        .await
        .map_err(|error| error.to_string())?;
    let restored =
        restore_bookmarks(profile, &snapshot, &downloads).map_err(|error| error.to_string())?;
    persist_sync_state(core, local, server_id, profile, &snapshot, &proof).await?;
    Ok(SyncFeedback {
        action: "loaded".to_owned(),
        profile_directory: profile.directory_name.clone(),
        profile_name: profile_name(local, profile).await?,
        message: format!(
            "Loaded {} bookmarks. Previous bookmarks and extension data are backed up in Downloads.",
            restored.stats.bookmarks
        ),
        stats: restored.stats,
        revision: proof.revision,
        conflicts: 0,
        backup_path: Some(restored.backup_path),
        extension_stats: Some(extensions.stats),
        extension_backup_path: extensions.backup_path,
    })
}

async fn sync_profile_with_server(
    core: &ClientCore,
    local: &LocalState,
    server_id: &str,
    profile: &DiscoveredProfile,
    backup_dir: &std::path::Path,
) -> Result<SyncFeedback, String> {
    let extensions = sync_extensions_with_server(core, local, server_id, profile, backup_dir)
        .await
        .map_err(|error| format!("Extension sync stopped before bookmark sync: {error}"))?;
    let local_snapshot = read_bookmarks(&profile.bookmarks_path, &profile.directory_name)
        .map_err(|error| error.to_string())?;
    let mapping = local
        .mapping(server_id, BOOKMARK_NAMESPACE, &profile.directory_name)
        .await
        .map_err(|error| error.to_string())?;
    let remote = match mapping {
        Some(mapping) => Some(
            core.load_bookmarks(mapping.object_id)
                .await
                .map_err(|error| error.to_string())?,
        ),
        None => core
            .discover_bookmarks(&profile.directory_name)
            .await
            .map_err(|error| error.to_string())?,
    };

    let Some((remote_snapshot, mut proof)) = remote else {
        let proof = core
            .save_bookmark_snapshot(&local_snapshot, None, None)
            .await
            .map_err(|error| error.to_string())?;
        persist_sync_state(core, local, server_id, profile, &local_snapshot, &proof).await?;
        let stats = bookmark_stats(&local_snapshot);
        return Ok(SyncFeedback {
            action: "synced".to_owned(),
            profile_directory: profile.directory_name.clone(),
            profile_name: profile_name(local, profile).await?,
            message: format!(
                "Started encrypted sync with {} bookmarks in {} folders. {}",
                stats.bookmarks, stats.folders, extensions.message
            ),
            stats,
            revision: proof.revision,
            conflicts: 0,
            backup_path: None,
            extension_stats: Some(extensions.stats),
            extension_backup_path: extensions.backup_path,
        });
    };

    let base = local
        .sync_base(server_id, BOOKMARK_NAMESPACE, &profile.directory_name)
        .await
        .map_err(|error| error.to_string())?
        .map(|bytes| {
            let plaintext = core
                .open_sync_base(&profile.directory_name, &bytes)
                .map_err(|error| format!("Stored bookmark sync base: {error}"))?;
            serde_json::from_slice(&plaintext)
                .map_err(|error| format!("Stored bookmark sync base is invalid: {error}"))
        })
        .transpose()?;
    let merged = merge_bookmarks(base.as_ref(), &local_snapshot, &remote_snapshot)
        .map_err(|error| error.to_string())?;
    let remote_changed = merged.snapshot != remote_snapshot;
    let local_changed = merged.snapshot != local_snapshot;

    if remote_changed {
        proof = core
            .save_bookmark_snapshot(
                &merged.snapshot,
                Some(proof.object_id),
                Some(proof.revision),
            )
            .await
            .map_err(|error| error.to_string())?;
    }
    let backup_path = if local_changed {
        let restored = restore_bookmarks(profile, &merged.snapshot, backup_dir)
            .map_err(|error| error.to_string())?;
        Some(restored.backup_path)
    } else {
        None
    };
    persist_sync_state(core, local, server_id, profile, &merged.snapshot, &proof).await?;
    let stats = bookmark_stats(&merged.snapshot);
    let message = match (local_changed, remote_changed) {
        (false, false) => "Bookmarks are already up to date.".to_owned(),
        (true, false) => {
            "Applied server changes locally and backed up the previous Bookmarks file.".to_owned()
        }
        (false, true) => "Uploaded local bookmark changes.".to_owned(),
        (true, true) => format!(
            "Merged local and server changes; {} concurrent edit(s) were resolved.",
            merged.conflicts
        ),
    };
    Ok(SyncFeedback {
        action: "synced".to_owned(),
        profile_directory: profile.directory_name.clone(),
        profile_name: profile_name(local, profile).await?,
        stats,
        revision: proof.revision,
        conflicts: merged.conflicts,
        backup_path,
        message: format!("{message} {}", extensions.message),
        extension_stats: Some(extensions.stats),
        extension_backup_path: extensions.backup_path,
    })
}

async fn persist_sync_state(
    core: &ClientCore,
    local: &LocalState,
    server_id: &str,
    profile: &DiscoveredProfile,
    snapshot: &helium_sync_profile::BookmarkSnapshotV1,
    proof: &helium_sync_client_core::orchestration::SyncProof,
) -> Result<(), String> {
    let snapshot_json =
        serde_json::to_vec(snapshot).map_err(|error| format!("Bookmark sync state: {error}"))?;
    let encrypted = core
        .protect_sync_base(&profile.directory_name, &snapshot_json)
        .map_err(|error| format!("Bookmark sync state: {error}"))?;
    local
        .save_sync_state(
            server_id,
            BOOKMARK_NAMESPACE,
            &profile.directory_name,
            proof.object_id,
            proof.revision,
            &encrypted,
        )
        .await
        .map_err(|error| error.to_string())
}

fn downloads_dir() -> Result<PathBuf, String> {
    let user_dirs = UserDirs::new()
        .ok_or_else(|| "The operating system did not provide a user home directory".to_owned())?;
    Ok(user_dirs
        .download_dir()
        .map(PathBuf::from)
        .unwrap_or_else(|| user_dirs.home_dir().join("Downloads")))
}

fn ensure_helium_closed() -> Result<(), String> {
    let installation =
        helium_sync_profile::discover_installation(&DiscoveryOptions::from_environment())
            .map_err(|error| error.to_string())?;
    ensure_profile_directory_unlocked(&installation.user_data_dir)?;
    let expected = installation
        .executable
        .map(|path| path.canonicalize().unwrap_or(path));
    let system = System::new_all();
    let running = system.processes().values().any(|process| {
        let executable_matches = expected.as_ref().is_some_and(|expected| {
            process
                .exe()
                .and_then(|path| {
                    path.canonicalize()
                        .ok()
                        .or_else(|| Some(path.to_path_buf()))
                })
                .is_some_and(|path| paths_equal(&path, expected))
        });
        let name = process.name().to_string_lossy();
        executable_matches
            || name.eq_ignore_ascii_case("helium")
            || name.eq_ignore_ascii_case("helium.exe")
            || name.eq_ignore_ascii_case("helium-browser")
    });
    if running {
        return Err(
            "Close every Helium window before creating, syncing, or switching profiles.".to_owned(),
        );
    }
    Ok(())
}

fn ensure_profile_directory_unlocked(user_data_dir: &std::path::Path) -> Result<(), String> {
    for name in ["SingletonLock", "SingletonSocket", "SingletonCookie"] {
        let marker = user_data_dir.join(name);
        let exists = match std::fs::symlink_metadata(&marker) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(format!(
                    "Could not inspect Helium's browser lock {}: {error}",
                    marker.display()
                ));
            }
        };
        if exists {
            return Err(format!(
                "Helium's browser lock {} is active. Close every Helium window before creating, syncing, or switching profiles. If Helium crashed, reopen it and close it normally before retrying.",
                marker.display()
            ));
        }
    }
    Ok(())
}

fn paths_equal(left: &std::path::Path, right: &std::path::Path) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

async fn forced_default_sync(
    local: &LocalState,
    core: &ClientCore,
    server_id: &str,
) -> Result<Option<SyncFeedback>, String> {
    let profiles = ensure_discovered_profiles(local).await?;
    let Some(default) = local
        .default_profile()
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    let Some(profile) = profiles
        .iter()
        .find(|profile| profile.directory_name == default.directory_name)
    else {
        return Ok(None);
    };
    if profile.bookmark_status == BookmarkStatus::Readable {
        ensure_helium_closed()?;
        sync_profile_with_server(core, local, server_id, profile, &downloads_dir()?)
            .await
            .map(Some)
    } else {
        Err("The default profile is not readable, so login sync could not complete".to_owned())
    }
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
            create_browser_profile,
            launch_profile,
            inspect_certificate,
            connect_https,
            connect_ssh,
            rename_profile,
            set_default_profile,
            set_profile_auto_sync,
            save_profile,
            load_profile,
            sync_profile,
            reveal_recovery_code,
            import_recovery_code,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Helium Sync desktop client");
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use axum::{body::Body, http::Request};
    use helium_sync_client_core::transport::{ApiTransport, TransportRequest, TransportResponse};
    use helium_sync_profile::BookmarkNode;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;

    struct RouterTransport {
        router: axum::Router,
    }

    #[test]
    fn browser_singleton_marker_blocks_profile_mutation() {
        let temp = tempfile::tempdir().unwrap();
        assert!(ensure_profile_directory_unlocked(temp.path()).is_ok());

        let marker = temp.path().join("SingletonLock");
        std::fs::write(&marker, "active").unwrap();
        let error = ensure_profile_directory_unlocked(temp.path()).unwrap_err();

        assert!(error.contains("SingletonLock"));
        assert!(error.contains("Close every Helium window"));
    }

    #[async_trait]
    impl ApiTransport for RouterTransport {
        async fn execute(
            &self,
            request: TransportRequest,
        ) -> Result<TransportResponse, helium_sync_client_core::ClientError> {
            let mut builder = Request::builder()
                .method(request.method)
                .uri(request.path_and_query);
            for (name, value) in &request.headers {
                builder = builder.header(name, value);
            }
            let response = self
                .router
                .clone()
                .oneshot(builder.body(Body::from(request.body)).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec();
            Ok(TransportResponse {
                status,
                headers,
                body,
            })
        }
    }

    fn write_profile(root: &std::path::Path, bookmarks: &[(&str, &str)]) -> DiscoveredProfile {
        std::fs::create_dir_all(root).unwrap();
        let children = bookmarks
            .iter()
            .map(|(id, name)| {
                serde_json::json!({
                    "type": "url",
                    "id": id,
                    "name": name,
                    "url": format!("https://{name}.example/")
                })
            })
            .collect::<Vec<_>>();
        std::fs::write(
            root.join("Bookmarks"),
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "roots": {
                    "bookmark_bar": {
                        "type": "folder",
                        "id": "1",
                        "name": "Bookmarks bar",
                        "children": children
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        DiscoveredProfile {
            directory_name: "Default".to_owned(),
            display_name: "Personal".to_owned(),
            path: root.to_path_buf(),
            bookmarks_path: root.join("Bookmarks"),
            bookmark_status: BookmarkStatus::Readable,
        }
    }

    fn bookmark_names(snapshot: &helium_sync_profile::BookmarkSnapshotV1) -> Vec<String> {
        let BookmarkNode::Folder { children, .. } = &snapshot.roots[0].node else {
            panic!("expected bookmark-bar folder");
        };
        children
            .iter()
            .map(|node| match node {
                BookmarkNode::Folder { name, .. } | BookmarkNode::Url { name, .. } => name.clone(),
            })
            .collect()
    }

    #[tokio::test]
    async fn two_devices_converge_independent_bookmark_additions() {
        let pool = helium_sync_server::storage::memory().await.unwrap();
        let server = helium_sync_server::api::AppState::new(
            pool,
            &SecretString::from("0123456789abcdef0123456789abcdef".to_owned()),
        );
        let router = helium_sync_server::router(server);
        let token = || SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
        let first_key = MasterKey::generate();
        let recovery_code = first_key.recovery_code();
        let first_core = ClientCore::new(
            Arc::new(ApiClient::new(
                Arc::new(RouterTransport {
                    router: router.clone(),
                }),
                token(),
            )),
            first_key,
            helium_sync_common::DeviceId::new(),
        );
        let second_core = ClientCore::new(
            Arc::new(ApiClient::new(
                Arc::new(RouterTransport { router }),
                token(),
            )),
            MasterKey::from_recovery_code(&recovery_code).unwrap(),
            helium_sync_common::DeviceId::new(),
        );
        first_core.register_device("first").await.unwrap();
        second_core.register_device("second").await.unwrap();
        let first_state = LocalState::memory().await.unwrap();
        let second_state = LocalState::memory().await.unwrap();
        first_state
            .ensure_profile("Default", "Personal")
            .await
            .unwrap();
        second_state
            .ensure_profile("Default", "Personal")
            .await
            .unwrap();
        let first_temp = tempfile::tempdir().unwrap();
        let second_temp = tempfile::tempdir().unwrap();
        let backups = tempfile::tempdir().unwrap();

        let mut first_profile = write_profile(&first_temp.path().join("Default"), &[("2", "base")]);
        let mut second_profile =
            write_profile(&second_temp.path().join("Default"), &[("2", "base")]);
        sync_profile_with_server(
            &first_core,
            &first_state,
            "server",
            &first_profile,
            backups.path(),
        )
        .await
        .unwrap();
        sync_profile_with_server(
            &second_core,
            &second_state,
            "server",
            &second_profile,
            backups.path(),
        )
        .await
        .unwrap();

        first_profile = write_profile(
            &first_temp.path().join("Default"),
            &[("2", "base"), ("3", "first")],
        );
        sync_profile_with_server(
            &first_core,
            &first_state,
            "server",
            &first_profile,
            backups.path(),
        )
        .await
        .unwrap();
        second_profile = write_profile(
            &second_temp.path().join("Default"),
            &[("2", "base"), ("4", "second")],
        );
        sync_profile_with_server(
            &second_core,
            &second_state,
            "server",
            &second_profile,
            backups.path(),
        )
        .await
        .unwrap();
        sync_profile_with_server(
            &first_core,
            &first_state,
            "server",
            &first_profile,
            backups.path(),
        )
        .await
        .unwrap();

        let first = read_bookmarks(&first_profile.bookmarks_path, "Default").unwrap();
        let second = read_bookmarks(&second_profile.bookmarks_path, "Default").unwrap();
        assert_eq!(bookmark_names(&first), vec!["base", "first", "second"]);
        assert_eq!(bookmark_names(&second), vec!["base", "first", "second"]);
    }
}
