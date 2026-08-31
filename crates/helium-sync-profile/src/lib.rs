//! Helium browser profile discovery, bookmark export, and guarded restore.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("Helium user-data directory was not found")]
    NotFound,
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("bookmark file changed while it was being read: {0}")]
    Changing(PathBuf),
    #[error("bookmark node type {0:?} is unsupported")]
    UnsupportedNodeType(String),
    #[error("temporary restore destination is not safe: {0}")]
    UnsafeRestore(PathBuf),
    #[error("could not create backup archive {path}: {details}")]
    Archive { path: PathBuf, details: String },
    #[error("could not write restored bookmarks at {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("snapshot belongs to {snapshot_profile}, not selected profile {selected_profile}")]
    ProfileMismatch {
        snapshot_profile: String,
        selected_profile: String,
    },
    #[error("bookmark snapshots cannot be merged: {0}")]
    IncompatibleSnapshot(String),
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveryOptions {
    pub executable_override: Option<PathBuf>,
    pub user_data_override: Option<PathBuf>,
}

impl DiscoveryOptions {
    #[must_use]
    pub fn from_environment() -> Self {
        Self {
            executable_override: std::env::var_os("HELIUM_SYNC_HELIUM_PATH").map(PathBuf::from),
            user_data_override: std::env::var_os("HELIUM_SYNC_USER_DATA_DIR").map(PathBuf::from),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    Override,
    Registry,
    StandardPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeliumInstallation {
    pub executable: Option<PathBuf>,
    pub user_data_dir: PathBuf,
    pub source: DiscoverySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BookmarkStatus {
    Missing,
    Readable,
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscoveredProfile {
    pub directory_name: String,
    pub display_name: String,
    pub path: PathBuf,
    pub bookmarks_path: PathBuf,
    pub bookmark_status: BookmarkStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscoveryReport {
    pub installation: HeliumInstallation,
    pub profiles: Vec<DiscoveredProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkSnapshotV1 {
    pub format: String,
    pub source_browser: String,
    pub profile_directory: String,
    pub chromium_version: u64,
    pub roots: Vec<BookmarkRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkRoot {
    pub key: String,
    pub node: BookmarkNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BookmarkStats {
    pub bookmarks: u64,
    pub folders: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestoreResult {
    pub backup_path: PathBuf,
    pub stats: BookmarkStats,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BookmarkMergeResult {
    pub snapshot: BookmarkSnapshotV1,
    pub conflicts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BookmarkNode {
    Folder {
        id: String,
        name: String,
        date_added: Option<String>,
        date_modified: Option<String>,
        children: Vec<BookmarkNode>,
    },
    Url {
        id: String,
        name: String,
        url: String,
        date_added: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
struct RawBookmarks {
    #[serde(default)]
    version: u64,
    roots: BTreeMap<String, RawNode>,
}

#[derive(Debug, Deserialize)]
struct RawNode {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    date_added: Option<String>,
    #[serde(default)]
    date_modified: Option<String>,
    #[serde(default)]
    children: Vec<RawNode>,
}

/// Discovers the installation and enumerates its profiles without modifying either.
///
/// # Errors
///
/// Returns [`ProfileError`] when no installation can be found or its profile metadata cannot be
/// read or parsed.
pub fn discover(options: &DiscoveryOptions) -> Result<DiscoveryReport, ProfileError> {
    let installation = discover_installation(options)?;
    let profiles = enumerate_profiles(&installation.user_data_dir)?;
    Ok(DiscoveryReport {
        installation,
        profiles,
    })
}

/// Locates a Helium installation using an explicit override or platform candidates.
///
/// # Errors
///
/// Returns [`ProfileError::NotFound`] when no candidate user-data directory exists.
pub fn discover_installation(
    options: &DiscoveryOptions,
) -> Result<HeliumInstallation, ProfileError> {
    if let Some(user_data_dir) = &options.user_data_override
        && user_data_dir.is_dir()
    {
        return Ok(HeliumInstallation {
            executable: options.executable_override.clone(),
            user_data_dir: user_data_dir.clone(),
            source: DiscoverySource::Override,
        });
    }

    for candidate in platform_candidates(options.executable_override.as_deref()) {
        if candidate.user_data_dir.is_dir() {
            return Ok(candidate);
        }
    }
    Err(ProfileError::NotFound)
}

/// Enumerates profile directories and independently probes their bookmark-read state.
///
/// # Errors
///
/// Returns [`ProfileError`] when the user-data directory or `Local State` cannot be read, or when
/// present profile metadata is malformed.
pub fn enumerate_profiles(user_data_dir: &Path) -> Result<Vec<DiscoveredProfile>, ProfileError> {
    let local_state_path = user_data_dir.join("Local State");
    let mut names = BTreeMap::new();
    if local_state_path.is_file() {
        let bytes = fs::read(&local_state_path).map_err(|source| ProfileError::Read {
            path: local_state_path.clone(),
            source,
        })?;
        let state: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|source| ProfileError::Parse {
                path: local_state_path,
                source,
            })?;
        if let Some(cache) = state
            .pointer("/profile/info_cache")
            .and_then(serde_json::Value::as_object)
        {
            for (directory, metadata) in cache {
                let display = metadata
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(directory);
                names.insert(directory.clone(), display.to_owned());
            }
        }
    }

    let entries = fs::read_dir(user_data_dir).map_err(|source| ProfileError::Read {
        path: user_data_dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ProfileError::Read {
            path: user_data_dir.to_path_buf(),
            source,
        })?;
        if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }
        let directory = entry.file_name().to_string_lossy().into_owned();
        if directory == "Default"
            || directory
                .strip_prefix("Profile ")
                .is_some_and(|suffix| suffix.parse::<u32>().is_ok())
        {
            names
                .entry(directory.clone())
                .or_insert_with(|| directory.clone());
        }
    }

    let profiles = names
        .into_iter()
        .filter_map(|(directory_name, display_name)| {
            let path = user_data_dir.join(&directory_name);
            path.is_dir().then(|| {
                let bookmarks_path = path.join("Bookmarks");
                let bookmark_status = if bookmarks_path.is_file() {
                    match read_bookmarks(&bookmarks_path, &directory_name) {
                        Ok(_) => BookmarkStatus::Readable,
                        Err(error) => BookmarkStatus::Invalid(error.to_string()),
                    }
                } else {
                    BookmarkStatus::Missing
                };
                DiscoveredProfile {
                    directory_name,
                    display_name,
                    path,
                    bookmarks_path,
                    bookmark_status,
                }
            })
        })
        .collect();
    Ok(profiles)
}

/// Reads and canonicalizes one Chromium-format `Bookmarks` file.
///
/// The file is read once per attempt and retried once when its metadata changes during the read.
///
/// # Errors
///
/// Returns [`ProfileError`] for I/O or JSON failures, changing-file detection, or an unsupported
/// bookmark node type.
pub fn read_bookmarks(
    path: &Path,
    profile_directory: &str,
) -> Result<BookmarkSnapshotV1, ProfileError> {
    for attempt in 0..2 {
        let before = fs::metadata(path).map_err(|source| ProfileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let bytes = fs::read(path).map_err(|source| ProfileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let after = fs::metadata(path).map_err(|source| ProfileError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            if attempt == 0 {
                continue;
            }
            return Err(ProfileError::Changing(path.to_path_buf()));
        }
        let raw: RawBookmarks =
            serde_json::from_slice(&bytes).map_err(|source| ProfileError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        let roots = raw
            .roots
            .into_iter()
            .map(|(key, node)| {
                Ok(BookmarkRoot {
                    key,
                    node: convert_node(node)?,
                })
            })
            .collect::<Result<Vec<_>, ProfileError>>()?;
        return Ok(BookmarkSnapshotV1 {
            format: "helium-bookmarks-v1".to_owned(),
            source_browser: "helium".to_owned(),
            profile_directory: profile_directory.to_owned(),
            chromium_version: raw.version,
            roots,
        });
    }
    Err(ProfileError::Changing(path.to_path_buf()))
}

#[must_use]
pub fn bookmark_stats(snapshot: &BookmarkSnapshotV1) -> BookmarkStats {
    fn count(node: &BookmarkNode, bookmarks: &mut u64, folders: &mut u64) {
        match node {
            BookmarkNode::Folder { children, .. } => {
                *folders += 1;
                for child in children {
                    count(child, bookmarks, folders);
                }
            }
            BookmarkNode::Url { .. } => *bookmarks += 1,
        }
    }

    let mut bookmarks = 0;
    let mut folders = 0;
    for root in &snapshot.roots {
        count(&root.node, &mut bookmarks, &mut folders);
    }
    BookmarkStats {
        bookmarks,
        folders,
        bytes: serde_json::to_vec(snapshot)
            .map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
    }
}

/// Reconciles local and remote bookmark snapshots against their last common state.
///
/// Independent changes are combined. When one side deletes a node while the other modifies it,
/// the modified node is retained. Concurrent edits to the same scalar field choose the remote
/// value deterministically and increment the conflict count.
///
/// # Errors
///
/// Returns [`ProfileError::IncompatibleSnapshot`] when snapshots use different formats, browser
/// sources, or profile directories.
pub fn merge_bookmarks(
    base: Option<&BookmarkSnapshotV1>,
    local: &BookmarkSnapshotV1,
    remote: &BookmarkSnapshotV1,
) -> Result<BookmarkMergeResult, ProfileError> {
    validate_merge_pair(local, remote)?;
    if let Some(base) = base {
        validate_merge_pair(base, local)?;
    }

    let base_roots = base.map_or_else(BTreeMap::new, |snapshot| {
        snapshot
            .roots
            .iter()
            .map(|root| (root.key.as_str(), &root.node))
            .collect()
    });
    let local_roots = local
        .roots
        .iter()
        .map(|root| (root.key.as_str(), &root.node))
        .collect::<BTreeMap<_, _>>();
    let remote_roots = remote
        .roots
        .iter()
        .map(|root| (root.key.as_str(), &root.node))
        .collect::<BTreeMap<_, _>>();
    let mut keys = Vec::new();
    let mut seen = BTreeSet::new();
    for root in remote
        .roots
        .iter()
        .chain(local.roots.iter())
        .chain(base.into_iter().flat_map(|snapshot| snapshot.roots.iter()))
    {
        if seen.insert(root.key.as_str()) {
            keys.push(root.key.clone());
        }
    }

    let mut conflicts = 0;
    let roots = keys
        .into_iter()
        .filter_map(|key| {
            merge_optional_node(
                base_roots.get(key.as_str()).copied(),
                local_roots.get(key.as_str()).copied(),
                remote_roots.get(key.as_str()).copied(),
                &mut conflicts,
            )
            .map(|node| BookmarkRoot { key, node })
        })
        .collect();
    Ok(BookmarkMergeResult {
        snapshot: BookmarkSnapshotV1 {
            format: remote.format.clone(),
            source_browser: remote.source_browser.clone(),
            profile_directory: remote.profile_directory.clone(),
            chromium_version: local.chromium_version.max(remote.chromium_version),
            roots,
        },
        conflicts,
    })
}

fn validate_merge_pair(
    left: &BookmarkSnapshotV1,
    right: &BookmarkSnapshotV1,
) -> Result<(), ProfileError> {
    if left.format != right.format
        || left.source_browser != right.source_browser
        || left.profile_directory != right.profile_directory
    {
        return Err(ProfileError::IncompatibleSnapshot(format!(
            "{}:{}:{} does not match {}:{}:{}",
            left.format,
            left.source_browser,
            left.profile_directory,
            right.format,
            right.source_browser,
            right.profile_directory
        )));
    }
    Ok(())
}

fn merge_optional_node(
    base: Option<&BookmarkNode>,
    local: Option<&BookmarkNode>,
    remote: Option<&BookmarkNode>,
    conflicts: &mut u64,
) -> Option<BookmarkNode> {
    if local == remote {
        return local.cloned();
    }
    if local == base {
        return remote.cloned();
    }
    if remote == base {
        return local.cloned();
    }
    match (base, local, remote) {
        (_, Some(local), Some(remote)) => Some(merge_present_node(base, local, remote, conflicts)),
        (Some(_), None, Some(remote)) => {
            *conflicts += 1;
            Some(remote.clone())
        }
        (Some(_), Some(local), None) => {
            *conflicts += 1;
            Some(local.clone())
        }
        _ => None,
    }
}

fn merge_present_node(
    base: Option<&BookmarkNode>,
    local: &BookmarkNode,
    remote: &BookmarkNode,
    conflicts: &mut u64,
) -> BookmarkNode {
    match (local, remote) {
        (
            BookmarkNode::Folder {
                id: local_id,
                name: local_name,
                date_added: local_added,
                date_modified: local_modified,
                children: local_children,
            },
            BookmarkNode::Folder {
                id: remote_id,
                name: remote_name,
                date_added: remote_added,
                date_modified: remote_modified,
                children: remote_children,
            },
        ) if local_id == remote_id => {
            let base_folder = match base {
                Some(BookmarkNode::Folder {
                    id,
                    name,
                    date_added,
                    date_modified,
                    children,
                }) if id == local_id => Some((name, date_added, date_modified, children)),
                _ => None,
            };
            BookmarkNode::Folder {
                id: local_id.clone(),
                name: merge_value(
                    base_folder.map(|value| value.0),
                    local_name,
                    remote_name,
                    conflicts,
                ),
                date_added: merge_value(
                    base_folder.map(|value| value.1),
                    local_added,
                    remote_added,
                    conflicts,
                ),
                date_modified: merge_value(
                    base_folder.map(|value| value.2),
                    local_modified,
                    remote_modified,
                    conflicts,
                ),
                children: merge_children(
                    base_folder.map(|value| value.3.as_slice()),
                    local_children,
                    remote_children,
                    conflicts,
                ),
            }
        }
        (
            BookmarkNode::Url {
                id: local_id,
                name: local_name,
                url: local_url,
                date_added: local_added,
            },
            BookmarkNode::Url {
                id: remote_id,
                name: remote_name,
                url: remote_url,
                date_added: remote_added,
            },
        ) if local_id == remote_id => {
            let base_url = match base {
                Some(BookmarkNode::Url {
                    id,
                    name,
                    url,
                    date_added,
                }) if id == local_id => Some((name, url, date_added)),
                _ => None,
            };
            BookmarkNode::Url {
                id: local_id.clone(),
                name: merge_value(
                    base_url.map(|value| value.0),
                    local_name,
                    remote_name,
                    conflicts,
                ),
                url: merge_value(
                    base_url.map(|value| value.1),
                    local_url,
                    remote_url,
                    conflicts,
                ),
                date_added: merge_value(
                    base_url.map(|value| value.2),
                    local_added,
                    remote_added,
                    conflicts,
                ),
            }
        }
        _ => {
            *conflicts += 1;
            remote.clone()
        }
    }
}

fn merge_children(
    base: Option<&[BookmarkNode]>,
    local: &[BookmarkNode],
    remote: &[BookmarkNode],
    conflicts: &mut u64,
) -> Vec<BookmarkNode> {
    let base_nodes = base.map_or_else(BTreeMap::new, |nodes| node_map(nodes));
    let local_nodes = node_map(local);
    let remote_nodes = node_map(remote);
    let mut ids = Vec::new();
    let mut seen = BTreeSet::new();
    for node in remote
        .iter()
        .chain(local.iter())
        .chain(base.into_iter().flatten())
    {
        if seen.insert(node_id(node)) {
            ids.push(node_id(node).to_owned());
        }
    }
    ids.into_iter()
        .filter_map(|id| {
            merge_optional_node(
                base_nodes.get(id.as_str()).copied(),
                local_nodes.get(id.as_str()).copied(),
                remote_nodes.get(id.as_str()).copied(),
                conflicts,
            )
        })
        .collect()
}

fn node_map(nodes: &[BookmarkNode]) -> BTreeMap<&str, &BookmarkNode> {
    nodes.iter().map(|node| (node_id(node), node)).collect()
}

fn node_id(node: &BookmarkNode) -> &str {
    match node {
        BookmarkNode::Folder { id, .. } | BookmarkNode::Url { id, .. } => id,
    }
}

fn merge_value<T: Clone + PartialEq>(
    base: Option<&T>,
    local: &T,
    remote: &T,
    conflicts: &mut u64,
) -> T {
    if local == remote {
        return local.clone();
    }
    if Some(local) == base {
        return remote.clone();
    }
    if Some(remote) == base {
        return local.clone();
    }
    *conflicts += 1;
    remote.clone()
}

/// Restores a bookmark snapshot after archiving the current local file in `downloads_dir`.
///
/// The replacement is staged beside the live file. If moving the staged file into place fails,
/// the original file is moved back before the error is returned.
///
/// # Errors
///
/// Returns an error before replacing local data if validation, backup creation, or staging fails.
/// A replacement failure is returned after attempting to restore the original file.
pub fn restore_bookmarks(
    profile: &DiscoveredProfile,
    snapshot: &BookmarkSnapshotV1,
    downloads_dir: &Path,
) -> Result<RestoreResult, ProfileError> {
    if snapshot.profile_directory != profile.directory_name {
        return Err(ProfileError::ProfileMismatch {
            snapshot_profile: snapshot.profile_directory.clone(),
            selected_profile: profile.directory_name.clone(),
        });
    }
    let restored = chromium_bookmarks_json(snapshot).map_err(|source| ProfileError::Parse {
        path: profile.bookmarks_path.clone(),
        source,
    })?;
    fs::create_dir_all(downloads_dir).map_err(|source| ProfileError::Write {
        path: downloads_dir.to_path_buf(),
        source,
    })?;
    let unique = unique_suffix();
    let safe_profile = profile
        .directory_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let backup_path = downloads_dir.join(format!(
        "Helium-Sync-{safe_profile}-before-load-{unique}.zip"
    ));
    create_backup_archive(&backup_path, profile)?;

    let staged_path = profile
        .path
        .join(format!(".Bookmarks.helium-sync-new-{unique}"));
    let mut staged = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staged_path)
        .map_err(|source| ProfileError::Write {
            path: staged_path.clone(),
            source,
        })?;
    if let Err(source) = staged.write_all(&restored).and_then(|()| staged.sync_all()) {
        drop(staged);
        let _cleanup_result = fs::remove_file(&staged_path);
        return Err(ProfileError::Write {
            path: staged_path,
            source,
        });
    }
    drop(staged);

    if profile.bookmarks_path.exists() {
        let previous_path = profile
            .path
            .join(format!(".Bookmarks.helium-sync-previous-{unique}"));
        fs::rename(&profile.bookmarks_path, &previous_path).map_err(|source| {
            let _cleanup_result = fs::remove_file(&staged_path);
            ProfileError::Write {
                path: profile.bookmarks_path.clone(),
                source,
            }
        })?;
        if let Err(source) = fs::rename(&staged_path, &profile.bookmarks_path) {
            let rollback = fs::rename(&previous_path, &profile.bookmarks_path);
            let _cleanup_result = fs::remove_file(&staged_path);
            return Err(ProfileError::Archive {
                path: profile.bookmarks_path.clone(),
                details: match rollback {
                    Ok(()) => format!("replacement failed and the original was restored: {source}"),
                    Err(rollback_error) => format!(
                        "replacement failed ({source}); restoring the original also failed ({rollback_error}); backup: {}",
                        backup_path.display()
                    ),
                },
            });
        }
        fs::remove_file(&previous_path).map_err(|source| ProfileError::Write {
            path: previous_path,
            source,
        })?;
    } else {
        fs::rename(&staged_path, &profile.bookmarks_path).map_err(|source| {
            let _cleanup_result = fs::remove_file(&staged_path);
            ProfileError::Write {
                path: profile.bookmarks_path.clone(),
                source,
            }
        })?;
    }

    Ok(RestoreResult {
        backup_path,
        stats: bookmark_stats(snapshot),
    })
}

fn create_backup_archive(
    backup_path: &Path,
    profile: &DiscoveredProfile,
) -> Result<(), ProfileError> {
    let archive_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(backup_path)
        .map_err(|error| ProfileError::Archive {
            path: backup_path.to_path_buf(),
            details: error.to_string(),
        })?;
    let mut archive = zip::ZipWriter::new(archive_file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Zstd)
        .unix_permissions(0o600);
    let entry_name = format!("{}/Bookmarks", profile.directory_name.replace('\\', "_"));
    let archive_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        if profile.bookmarks_path.is_file() {
            archive.start_file(entry_name, options)?;
            let mut source = fs::File::open(&profile.bookmarks_path)?;
            std::io::copy(&mut source, &mut archive)?;
        } else {
            archive.start_file("README.txt", options)?;
            archive.write_all(b"No local Bookmarks file existed before this load.\n")?;
        }
        let completed = archive.finish()?;
        completed.sync_all()?;
        Ok(())
    })();
    if let Err(error) = archive_result {
        let _cleanup_result = fs::remove_file(backup_path);
        return Err(ProfileError::Archive {
            path: backup_path.to_path_buf(),
            details: error.to_string(),
        });
    }
    Ok(())
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("{nanos}-{}", std::process::id())
}

fn chromium_bookmarks_json(snapshot: &BookmarkSnapshotV1) -> Result<Vec<u8>, serde_json::Error> {
    let roots = snapshot
        .roots
        .iter()
        .map(|root| Ok((root.key.clone(), serde_json::to_value(&root.node)?)))
        .collect::<Result<serde_json::Map<String, serde_json::Value>, serde_json::Error>>()?;
    serde_json::to_vec_pretty(&serde_json::json!({
        "version": snapshot.chromium_version,
        "roots": roots,
    }))
}

fn convert_node(raw: RawNode) -> Result<BookmarkNode, ProfileError> {
    match raw.kind.as_str() {
        "folder" => Ok(BookmarkNode::Folder {
            id: raw.id,
            name: raw.name,
            date_added: raw.date_added,
            date_modified: raw.date_modified,
            children: raw
                .children
                .into_iter()
                .map(convert_node)
                .collect::<Result<Vec<_>, _>>()?,
        }),
        "url" => Ok(BookmarkNode::Url {
            id: raw.id,
            name: raw.name,
            url: raw.url.ok_or_else(|| {
                ProfileError::UnsupportedNodeType("url node without URL".to_owned())
            })?,
            date_added: raw.date_added,
        }),
        other => Err(ProfileError::UnsupportedNodeType(other.to_owned())),
    }
}

#[cfg(any(test, feature = "test-restore"))]
/// Writes a canonical snapshot only beneath the operating system temporary directory.
///
/// # Errors
///
/// Returns [`ProfileError::UnsafeRestore`] outside the temporary directory, or an I/O or
/// serialization error when the test artifact cannot be produced.
pub fn write_test_bookmarks(
    destination_profile: &Path,
    snapshot: &BookmarkSnapshotV1,
) -> Result<PathBuf, ProfileError> {
    let temp = std::env::temp_dir()
        .canonicalize()
        .map_err(|source| ProfileError::Read {
            path: std::env::temp_dir(),
            source,
        })?;
    fs::create_dir_all(destination_profile).map_err(|source| ProfileError::Read {
        path: destination_profile.to_path_buf(),
        source,
    })?;
    let destination = destination_profile
        .canonicalize()
        .map_err(|source| ProfileError::Read {
            path: destination_profile.to_path_buf(),
            source,
        })?;
    if !destination.starts_with(&temp) {
        return Err(ProfileError::UnsafeRestore(destination));
    }
    let output = destination.join("Bookmarks.restored.json");
    let bytes = chromium_bookmarks_json(snapshot).map_err(|source| ProfileError::Parse {
        path: output.clone(),
        source,
    })?;
    fs::write(&output, bytes).map_err(|source| ProfileError::Read {
        path: output.clone(),
        source,
    })?;
    Ok(output)
}

fn platform_candidates(executable_override: Option<&Path>) -> Vec<HeliumInstallation> {
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |executable: Option<PathBuf>, user_data_dir: PathBuf, source| {
        if seen.insert(user_data_dir.clone()) {
            candidates.push(HeliumInstallation {
                executable: executable_override.map(Path::to_path_buf).or(executable),
                user_data_dir,
                source,
            });
        }
    };

    #[cfg(windows)]
    {
        for (executable, user_data) in windows_registry_candidates() {
            push(Some(executable), user_data, DiscoverySource::Registry);
        }
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            let root = PathBuf::from(local).join("imput").join("Helium");
            push(
                Some(root.join("Application").join("chrome.exe")),
                root.join("User Data"),
                DiscoverySource::StandardPath,
            );
        }
    }

    #[cfg(target_os = "macos")]
    if let Some(home) = directories::UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf()) {
        let data = home.join("Library/Application Support/net.imput.helium");
        push(
            Some(PathBuf::from(
                "/Applications/Helium.app/Contents/MacOS/Helium",
            )),
            data.clone(),
            DiscoverySource::StandardPath,
        );
        push(
            Some(home.join("Applications/Helium.app/Contents/MacOS/Helium")),
            data,
            DiscoverySource::StandardPath,
        );
    }

    #[cfg(target_os = "linux")]
    if let Some(base) = directories::BaseDirs::new() {
        push(
            None,
            base.config_dir().join("net.imput.helium"),
            DiscoverySource::StandardPath,
        );
    }

    candidates
}

#[cfg(windows)]
fn windows_registry_candidates() -> Vec<(PathBuf, PathBuf)> {
    use winreg::{
        RegKey,
        enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ},
    };

    let mut values = Vec::new();
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let root = RegKey::predef(hive);
        for key_path in [
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ] {
            let Ok(uninstall) = root.open_subkey_with_flags(key_path, KEY_READ) else {
                continue;
            };
            for child in uninstall.enum_keys().filter_map(Result::ok) {
                let Ok(key) = uninstall.open_subkey_with_flags(child, KEY_READ) else {
                    continue;
                };
                let name: String = key.get_value("DisplayName").unwrap_or_default();
                if name != "Helium" {
                    continue;
                }
                let location: String = key.get_value("InstallLocation").unwrap_or_default();
                if location.is_empty() {
                    continue;
                }
                let application = PathBuf::from(location);
                let root = application.parent().unwrap_or(&application);
                values.push((application.join("chrome.exe"), root.join("User Data")));
            }
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    const BOOKMARKS: &str = r#"{
      "version": 1,
      "roots": {
        "bookmark_bar": {
          "type": "folder", "id": "1", "name": "Bookmarks bar",
          "children": [{"type":"url","id":"2","name":"Example","url":"https://example.com/","date_added":"123"}]
        }
      }
    }"#;

    fn bookmark(id: &str, name: &str) -> BookmarkNode {
        BookmarkNode::Url {
            id: id.to_owned(),
            name: name.to_owned(),
            url: format!("https://{name}.example/"),
            date_added: None,
        }
    }

    fn snapshot(children: Vec<BookmarkNode>) -> BookmarkSnapshotV1 {
        BookmarkSnapshotV1 {
            format: "helium-bookmarks-v1".to_owned(),
            source_browser: "helium".to_owned(),
            profile_directory: "Default".to_owned(),
            chromium_version: 1,
            roots: vec![BookmarkRoot {
                key: "bookmark_bar".to_owned(),
                node: BookmarkNode::Folder {
                    id: "1".to_owned(),
                    name: "Bookmarks bar".to_owned(),
                    date_added: None,
                    date_modified: None,
                    children,
                },
            }],
        }
    }

    fn merged_children(result: &BookmarkMergeResult) -> &[BookmarkNode] {
        match &result.snapshot.roots[0].node {
            BookmarkNode::Folder { children, .. } => children,
            BookmarkNode::Url { .. } => panic!("expected bookmark-bar folder"),
        }
    }

    #[test]
    fn discovers_fixture_and_parses_bookmarks() {
        let temp = tempfile::tempdir().unwrap();
        let profile = temp.path().join("Default");
        fs::create_dir(&profile).unwrap();
        fs::write(profile.join("Bookmarks"), BOOKMARKS).unwrap();
        fs::write(
            temp.path().join("Local State"),
            r#"{"profile":{"info_cache":{"Default":{"name":"Person 1"}}}}"#,
        )
        .unwrap();

        let profiles = enumerate_profiles(temp.path()).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].display_name, "Person 1");
        assert_eq!(profiles[0].bookmark_status, BookmarkStatus::Readable);
        let snapshot = read_bookmarks(&profiles[0].bookmarks_path, "Default").unwrap();
        assert_eq!(snapshot.roots.len(), 1);
        assert!(matches!(
            snapshot.roots[0].node,
            BookmarkNode::Folder { .. }
        ));
    }

    #[test]
    fn rejects_unknown_bookmark_node_type() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temp.path(),
            r#"{"version":1,"roots":{"x":{"type":"mystery","id":"1","name":"x"}}}"#,
        )
        .unwrap();
        assert!(matches!(
            read_bookmarks(temp.path(), "Default"),
            Err(ProfileError::UnsupportedNodeType(_))
        ));
    }

    #[test]
    fn restore_writer_stays_in_temp_directory() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = BookmarkSnapshotV1 {
            format: "helium-bookmarks-v1".to_owned(),
            source_browser: "helium".to_owned(),
            profile_directory: "Default".to_owned(),
            chromium_version: 1,
            roots: vec![],
        };
        let output = write_test_bookmarks(&temp.path().join("restore"), &snapshot).unwrap();
        assert!(output.is_file());
    }

    #[test]
    fn counts_and_restores_bookmarks_after_zip_backup() {
        let temp = tempfile::tempdir().unwrap();
        let profile_path = temp.path().join("Default");
        let downloads = temp.path().join("Downloads");
        fs::create_dir(&profile_path).unwrap();
        fs::write(profile_path.join("Bookmarks"), BOOKMARKS).unwrap();
        let profile = DiscoveredProfile {
            directory_name: "Default".to_owned(),
            display_name: "Personal".to_owned(),
            path: profile_path.clone(),
            bookmarks_path: profile_path.join("Bookmarks"),
            bookmark_status: BookmarkStatus::Readable,
        };
        let mut snapshot = read_bookmarks(&profile.bookmarks_path, "Default").unwrap();
        if let BookmarkNode::Folder { children, .. } = &mut snapshot.roots[0].node {
            children.push(BookmarkNode::Url {
                id: "3".to_owned(),
                name: "Second".to_owned(),
                url: "https://example.org/".to_owned(),
                date_added: None,
            });
        }

        let result = restore_bookmarks(&profile, &snapshot, &downloads).unwrap();
        assert_eq!(result.stats.bookmarks, 2);
        assert_eq!(result.stats.folders, 1);
        assert!(result.backup_path.is_file());
        assert_eq!(
            read_bookmarks(&profile.bookmarks_path, "Default").unwrap(),
            snapshot
        );

        let archive_file = fs::File::open(result.backup_path).unwrap();
        let mut archive = zip::ZipArchive::new(archive_file).unwrap();
        let mut original = String::new();
        let mut archived_bookmarks = archive.by_name("Default/Bookmarks").unwrap();
        assert_eq!(
            archived_bookmarks.compression(),
            zip::CompressionMethod::Zstd
        );
        archived_bookmarks.read_to_string(&mut original).unwrap();
        assert_eq!(original, BOOKMARKS);
    }

    #[test]
    fn three_way_merge_combines_independent_additions() {
        let base = snapshot(vec![bookmark("2", "base")]);
        let local = snapshot(vec![bookmark("2", "base"), bookmark("3", "local")]);
        let remote = snapshot(vec![bookmark("2", "base"), bookmark("4", "remote")]);

        let merged = merge_bookmarks(Some(&base), &local, &remote).unwrap();
        assert_eq!(merged.conflicts, 0);
        assert_eq!(merged_children(&merged).len(), 3);
        assert!(
            merged_children(&merged)
                .iter()
                .any(|node| node_id(node) == "3")
        );
        assert!(
            merged_children(&merged)
                .iter()
                .any(|node| node_id(node) == "4")
        );
    }

    #[test]
    fn three_way_merge_propagates_deletion_when_other_side_is_unchanged() {
        let base = snapshot(vec![bookmark("2", "remove")]);
        let local = snapshot(vec![]);
        let remote = base.clone();

        let merged = merge_bookmarks(Some(&base), &local, &remote).unwrap();
        assert_eq!(merged.conflicts, 0);
        assert!(merged_children(&merged).is_empty());
    }

    #[test]
    fn three_way_merge_keeps_modification_over_concurrent_deletion() {
        let base = snapshot(vec![bookmark("2", "before")]);
        let local = snapshot(vec![bookmark("2", "after")]);
        let remote = snapshot(vec![]);

        let merged = merge_bookmarks(Some(&base), &local, &remote).unwrap();
        assert_eq!(merged.conflicts, 1);
        assert_eq!(merged_children(&merged), &[bookmark("2", "after")]);
    }
}
