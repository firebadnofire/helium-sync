use std::sync::Arc;

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
        if object_id.is_some() != base_revision.is_some() {
            return Err(ClientError::State(
                "bookmark object ID and revision must either both exist or both be absent"
                    .to_owned(),
            ));
        }
        let snapshot = read_bookmarks(&profile.bookmarks_path, &profile.directory_name)?;
        let plaintext = serde_json::to_vec(&snapshot)
            .map_err(|error| ClientError::Serialization(error.to_string()))?;
        let proof = self
            .upload(BOOKMARK_NAMESPACE, &plaintext, object_id, base_revision)
            .await?;
        Ok((proof, snapshot))
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
        let object_id = object_id.unwrap_or_else(ObjectId::new);
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
}
