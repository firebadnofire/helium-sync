use std::{collections::HashMap, sync::Arc};

use helium_sync_common::{DeviceId, ObjectId, PutObjectRequest, RegisterDeviceRequest, Timestamp};
use helium_sync_profile::{BookmarkSnapshotV1, DiscoveredProfile, read_bookmarks};
use serde::Serialize;

use crate::{
    ClientError,
    api::ApiClient,
    crypto::{self, MasterKey, ObjectMetadata},
};

pub const SYNTHETIC_SENTINEL: &str = "HELIUM_SYNC_TRANSPORT_TEST_PLAINTEXT_7f3a9c21";
pub const BOOKMARK_NAMESPACE: &str = "helium.bookmarks.v1";

#[derive(Debug, Clone, Serialize)]
pub struct SyncProof {
    pub object_id: ObjectId,
    pub namespace: String,
    pub revision: u64,
    pub cursor: u64,
    pub plaintext_matches: bool,
}

pub struct ClientCore {
    api: Arc<ApiClient>,
    master_key: MasterKey,
    device_id: DeviceId,
}

impl ClientCore {
    #[must_use]
    pub fn new(api: Arc<ApiClient>, master_key: MasterKey, device_id: DeviceId) -> Self {
        Self {
            api,
            master_key,
            device_id,
        }
    }

    pub async fn register_device(&self, name: &str) -> Result<(), ClientError> {
        match self
            .api
            .register_device(&RegisterDeviceRequest {
                id: self.device_id,
                name: name.to_owned(),
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(ClientError::Api { code, .. }) if code == "device_exists" => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub fn protect_sync_base(
        &self,
        profile_directory: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        crypto::encrypt_local_state(
            &self.master_key,
            &format!("{BOOKMARK_NAMESPACE}:{profile_directory}"),
            plaintext,
        )
    }

    pub fn open_sync_base(
        &self,
        profile_directory: &str,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        crypto::decrypt_local_state(
            &self.master_key,
            &format!("{BOOKMARK_NAMESPACE}:{profile_directory}"),
            encrypted,
        )
    }

    pub async fn synthetic_round_trip(&self) -> Result<SyncProof, ClientError> {
        self.round_trip("synthetic.v1", SYNTHETIC_SENTINEL.as_bytes())
            .await
    }

    pub async fn bookmark_round_trip(
        &self,
        profile: &DiscoveredProfile,
    ) -> Result<(SyncProof, BookmarkSnapshotV1), ClientError> {
        let snapshot = read_bookmarks(&profile.bookmarks_path, &profile.directory_name)?;
        let plaintext = serde_json::to_vec(&snapshot)
            .map_err(|error| ClientError::Serialization(error.to_string()))?;
        let proof = self
            .upload(BOOKMARK_NAMESPACE, &plaintext, None, None)
            .await?;
        Ok((proof, snapshot))
    }

    pub async fn save_bookmarks(
        &self,
        profile: &DiscoveredProfile,
        object_id: Option<ObjectId>,
        base_revision: Option<u64>,
    ) -> Result<(SyncProof, BookmarkSnapshotV1), ClientError> {
        let snapshot = read_bookmarks(&profile.bookmarks_path, &profile.directory_name)?;
        let proof = self
            .save_bookmark_snapshot(&snapshot, object_id, base_revision)
            .await?;
        Ok((proof, snapshot))
    }

    pub async fn save_bookmark_snapshot(
        &self,
        snapshot: &BookmarkSnapshotV1,
        object_id: Option<ObjectId>,
        base_revision: Option<u64>,
    ) -> Result<SyncProof, ClientError> {
        if object_id.is_some() != base_revision.is_some() {
            return Err(ClientError::State(
                "bookmark object ID and revision must either both exist or both be absent"
                    .to_owned(),
            ));
        }
        let plaintext = serde_json::to_vec(&snapshot)
            .map_err(|error| ClientError::Serialization(error.to_string()))?;
        self.upload(BOOKMARK_NAMESPACE, &plaintext, object_id, base_revision)
            .await
    }

    pub async fn load_bookmarks(
        &self,
        object_id: ObjectId,
    ) -> Result<(BookmarkSnapshotV1, SyncProof), ClientError> {
        let stored = self.api.get_object(object_id).await?;
        if stored.namespace != BOOKMARK_NAMESPACE {
            return Err(ClientError::Serialization(format!(
                "server object has unexpected namespace {}",
                stored.namespace
            )));
        }
        let plaintext = crypto::decrypt(&self.master_key, &stored)?;
        let snapshot = serde_json::from_slice(&plaintext)
            .map_err(|error| ClientError::Serialization(error.to_string()))?;
        Ok((
            snapshot,
            SyncProof {
                object_id,
                namespace: stored.namespace,
                revision: stored.revision,
                cursor: stored.cursor,
                plaintext_matches: true,
            },
        ))
    }

    pub async fn discover_bookmarks(
        &self,
        profile_directory: &str,
    ) -> Result<Option<(BookmarkSnapshotV1, SyncProof)>, ClientError> {
        let mut after = 0;
        let mut candidates = HashMap::new();
        loop {
            let page = self.api.changes(after).await?;
            for change in page.changes {
                if change.namespace == BOOKMARK_NAMESPACE {
                    candidates.insert(change.object_id, (change.cursor, change.deleted));
                }
            }
            if !page.has_more {
                break;
            }
            if page.next_cursor <= after {
                return Err(ClientError::Serialization(
                    "server change cursor did not advance".to_owned(),
                ));
            }
            after = page.next_cursor;
        }

        let mut candidates = candidates
            .into_iter()
            .filter_map(|(object_id, (cursor, deleted))| (!deleted).then_some((object_id, cursor)))
            .collect::<Vec<_>>();
        candidates.sort_unstable_by_key(|(_, cursor)| std::cmp::Reverse(*cursor));
        for (object_id, _) in candidates {
            let (snapshot, proof) = self.load_bookmarks(object_id).await?;
            if snapshot.profile_directory == profile_directory {
                return Ok(Some((snapshot, proof)));
            }
        }
        Ok(None)
    }

    async fn round_trip(
        &self,
        namespace: &str,
        plaintext: &[u8],
    ) -> Result<SyncProof, ClientError> {
        self.upload(namespace, plaintext, None, None).await
    }

    async fn upload(
        &self,
        namespace: &str,
        plaintext: &[u8],
        object_id: Option<ObjectId>,
        base_revision: Option<u64>,
    ) -> Result<SyncProof, ClientError> {
        let object_id = object_id.unwrap_or_default();
        let revision = base_revision.map_or(1, |revision| revision.saturating_add(1));
        let modified_at = Timestamp::now_utc();
        let metadata = ObjectMetadata {
            protocol: helium_sync_common::PROTOCOL_MAX,
            object_id,
            namespace,
            device_id: self.device_id,
            revision,
            modified_at,
        };
        let envelope = crypto::encrypt(&self.master_key, &metadata, plaintext)?;
        self.api
            .put_object(
                object_id,
                &PutObjectRequest {
                    namespace: namespace.to_owned(),
                    base_revision,
                    device_id: self.device_id,
                    modified_at,
                    envelope,
                },
            )
            .await?;
        let stored = self.api.get_object(object_id).await?;
        let decrypted = crypto::decrypt(&self.master_key, &stored)?;
        let matches = decrypted == plaintext;
        if !matches {
            return Err(ClientError::Crypto(
                "retrieved plaintext did not match the uploaded object".to_owned(),
            ));
        }
        Ok(SyncProof {
            object_id,
            namespace: namespace.to_owned(),
            revision: stored.revision,
            cursor: stored.cursor,
            plaintext_matches: matches,
        })
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use secrecy::SecretString;
    use tower::ServiceExt as _;

    use crate::transport::{ApiTransport, TransportRequest, TransportResponse};

    use super::*;

    struct RouterTransport {
        router: axum::Router,
    }

    #[async_trait]
    impl ApiTransport for RouterTransport {
        async fn execute(
            &self,
            request: TransportRequest,
        ) -> Result<TransportResponse, ClientError> {
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

    #[tokio::test]
    async fn synthetic_payload_is_encrypted_in_server_storage() {
        let pool = helium_sync_server::storage::memory().await.unwrap();
        let state = helium_sync_server::api::AppState::new(
            pool.clone(),
            &SecretString::from("0123456789abcdef0123456789abcdef".to_owned()),
        );
        let transport = Arc::new(RouterTransport {
            router: helium_sync_server::router(state),
        });
        let api = Arc::new(ApiClient::new(
            transport,
            SecretString::from("0123456789abcdef0123456789abcdef".to_owned()),
        ));
        let core = ClientCore::new(api, MasterKey::generate(), DeviceId::new());
        core.register_device("integration test").await.unwrap();
        let proof = core.synthetic_round_trip().await.unwrap();
        assert!(proof.plaintext_matches);

        let stored: String = sqlx::query_scalar("SELECT envelope_json FROM objects WHERE id = ?")
            .bind(proof.object_id.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!stored.contains(SYNTHETIC_SENTINEL));
    }

    #[tokio::test]
    async fn bookmark_save_updates_stable_object_and_loads_snapshot() {
        let pool = helium_sync_server::storage::memory().await.unwrap();
        let state = helium_sync_server::api::AppState::new(
            pool,
            &SecretString::from("0123456789abcdef0123456789abcdef".to_owned()),
        );
        let transport = Arc::new(RouterTransport {
            router: helium_sync_server::router(state),
        });
        let api = Arc::new(ApiClient::new(
            transport,
            SecretString::from("0123456789abcdef0123456789abcdef".to_owned()),
        ));
        let core = ClientCore::new(api, MasterKey::generate(), DeviceId::new());
        core.register_device("bookmark test").await.unwrap();

        let temp = tempfile::tempdir().unwrap();
        let profile_path = temp.path().join("Default");
        std::fs::create_dir(&profile_path).unwrap();
        let bookmarks_path = profile_path.join("Bookmarks");
        std::fs::write(
            &bookmarks_path,
            r#"{"version":1,"roots":{"bookmark_bar":{"type":"folder","id":"1","name":"Bookmarks bar","children":[{"type":"url","id":"2","name":"Example","url":"https://example.com/"}]}}}"#,
        )
        .unwrap();
        let profile = helium_sync_profile::DiscoveredProfile {
            directory_name: "Default".to_owned(),
            display_name: "Personal".to_owned(),
            path: profile_path,
            bookmarks_path,
            bookmark_status: helium_sync_profile::BookmarkStatus::Readable,
        };

        let (first, expected) = core.save_bookmarks(&profile, None, None).await.unwrap();
        let (loaded, loaded_proof) = core.load_bookmarks(first.object_id).await.unwrap();
        assert_eq!(loaded, expected);
        assert_eq!(loaded_proof.revision, 1);

        let (second, _) = core
            .save_bookmarks(&profile, Some(first.object_id), Some(first.revision))
            .await
            .unwrap();
        assert_eq!(second.object_id, first.object_id);
        assert_eq!(second.revision, 2);
    }

    #[tokio::test]
    async fn second_device_discovers_existing_encrypted_profile() {
        let pool = helium_sync_server::storage::memory().await.unwrap();
        let state = helium_sync_server::api::AppState::new(
            pool,
            &SecretString::from("0123456789abcdef0123456789abcdef".to_owned()),
        );
        let router = helium_sync_server::router(state);
        let token = || SecretString::from("0123456789abcdef0123456789abcdef".to_owned());
        let first_key = MasterKey::generate();
        let recovery_code = first_key.recovery_code();
        let first = ClientCore::new(
            Arc::new(ApiClient::new(
                Arc::new(RouterTransport {
                    router: router.clone(),
                }),
                token(),
            )),
            first_key,
            DeviceId::new(),
        );
        let second = ClientCore::new(
            Arc::new(ApiClient::new(
                Arc::new(RouterTransport { router }),
                token(),
            )),
            MasterKey::from_recovery_code(&recovery_code).unwrap(),
            DeviceId::new(),
        );
        first.register_device("first device").await.unwrap();
        second.register_device("second device").await.unwrap();

        let temp = tempfile::tempdir().unwrap();
        let profile_path = temp.path().join("Default");
        std::fs::create_dir(&profile_path).unwrap();
        let bookmarks_path = profile_path.join("Bookmarks");
        std::fs::write(
            &bookmarks_path,
            r#"{"version":1,"roots":{"bookmark_bar":{"type":"folder","id":"1","name":"Bookmarks bar","children":[{"type":"url","id":"2","name":"Example","url":"https://example.com/"}]}}}"#,
        )
        .unwrap();
        let profile = helium_sync_profile::DiscoveredProfile {
            directory_name: "Default".to_owned(),
            display_name: "Personal".to_owned(),
            path: profile_path,
            bookmarks_path,
            bookmark_status: helium_sync_profile::BookmarkStatus::Readable,
        };

        let (saved, expected) = first.save_bookmarks(&profile, None, None).await.unwrap();
        let (discovered, proof) = second
            .discover_bookmarks("Default")
            .await
            .unwrap()
            .expect("second device should find the first device's profile");
        assert_eq!(discovered, expected);
        assert_eq!(proof.object_id, saved.object_id);
        assert_eq!(proof.revision, saved.revision);
    }
}
