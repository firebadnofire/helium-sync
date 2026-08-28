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
        let proof = self.round_trip("helium.bookmarks.v1", &plaintext).await?;
        Ok((proof, snapshot))
    }

    async fn round_trip(
        &self,
        namespace: &str,
        plaintext: &[u8],
    ) -> Result<SyncProof, ClientError> {
        let object_id = ObjectId::new();
        let modified_at = Timestamp::now_utc();
        let metadata = ObjectMetadata {
            protocol: helium_sync_common::PROTOCOL_MAX,
            object_id,
            namespace,
            device_id: self.device_id,
            revision: 1,
            modified_at,
        };
        let envelope = crypto::encrypt(&self.master_key, &metadata, plaintext)?;
        self.api
            .put_object(
                object_id,
                &PutObjectRequest {
                    namespace: namespace.to_owned(),
                    base_revision: None,
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
}
