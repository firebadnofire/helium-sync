//! Read-only Helium browser profile discovery and bookmark export.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
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
    let bytes = serde_json::to_vec_pretty(snapshot).map_err(|source| ProfileError::Parse {
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

    const BOOKMARKS: &str = r#"{
      "version": 1,
      "roots": {
        "bookmark_bar": {
          "type": "folder", "id": "1", "name": "Bookmarks bar",
          "children": [{"type":"url","id":"2","name":"Example","url":"https://example.com/","date_added":"123"}]
        }
      }
    }"#;

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
}
