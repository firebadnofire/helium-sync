use std::sync::Arc;

use helium_sync_common::{
    ApiErrorBody, ChangesResponse, DeleteObjectRequest, Device, ObjectId, PROTOCOL_HEADER,
    PROTOCOL_MAX, PROTOCOL_MIN, ProtocolRange, ProtocolVersion, PutObjectRequest,
    RegisterDeviceRequest, StatusResponse, SyncObject, VersionResponse,
};
use http::{
    HeaderMap, HeaderValue, Method,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;

use crate::{
    ClientError,
    transport::{ApiTransport, TransportRequest, TransportResponse},
};

pub struct ApiClient {
    transport: Arc<dyn ApiTransport>,
    token: SecretString,
    protocol: Mutex<Option<ProtocolVersion>>,
}

impl ApiClient {
    #[must_use]
    pub fn new(transport: Arc<dyn ApiTransport>, token: SecretString) -> Self {
        Self {
            transport,
            token,
            protocol: Mutex::new(None),
        }
    }

    pub async fn negotiate(&self) -> Result<VersionResponse, ClientError> {
        let response: VersionResponse = self
            .json_request::<(), _>(Method::GET, "/v1/version", None, false)
            .await?;
        let local = ProtocolRange {
            min: PROTOCOL_MIN,
            max: PROTOCOL_MAX,
        };
        let selected =
            local
                .negotiate(response.protocol)
                .ok_or(ClientError::ProtocolIncompatible {
                    client_min: local.min.0,
                    client_max: local.max.0,
                    server_min: response.protocol.min.0,
                    server_max: response.protocol.max.0,
                })?;
        *self.protocol.lock().await = Some(selected);
        Ok(response)
    }

    pub async fn status(&self) -> Result<StatusResponse, ClientError> {
        self.ensure_negotiated().await?;
        self.json_request::<(), _>(Method::GET, "/v1/status", None, true)
            .await
    }

    pub async fn register_device(
        &self,
        request: &RegisterDeviceRequest,
    ) -> Result<Device, ClientError> {
        self.ensure_negotiated().await?;
        self.json_request(Method::POST, "/v1/devices", Some(request), true)
            .await
    }

    pub async fn put_object(
        &self,
        id: ObjectId,
        request: &PutObjectRequest,
    ) -> Result<SyncObject, ClientError> {
        self.ensure_negotiated().await?;
        self.json_request(
            Method::PUT,
            &format!("/v1/objects/{id}"),
            Some(request),
            true,
        )
        .await
    }

    pub async fn get_object(&self, id: ObjectId) -> Result<SyncObject, ClientError> {
        self.ensure_negotiated().await?;
        self.json_request::<(), _>(Method::GET, &format!("/v1/objects/{id}"), None, true)
            .await
    }

    pub async fn delete_object(
        &self,
        id: ObjectId,
        request: &DeleteObjectRequest,
    ) -> Result<SyncObject, ClientError> {
        self.ensure_negotiated().await?;
        self.json_request(
            Method::DELETE,
            &format!("/v1/objects/{id}"),
            Some(request),
            true,
        )
        .await
    }

    pub async fn changes(&self, after: u64) -> Result<ChangesResponse, ClientError> {
        self.ensure_negotiated().await?;
        self.json_request::<(), _>(
            Method::GET,
            &format!("/v1/changes?after={after}"),
            None,
            true,
        )
        .await
    }

    async fn ensure_negotiated(&self) -> Result<ProtocolVersion, ClientError> {
        if let Some(protocol) = *self.protocol.lock().await {
            return Ok(protocol);
        }
        self.negotiate().await?;
        self.protocol
            .lock()
            .await
            .ok_or_else(|| ClientError::ProtocolIncompatible {
                client_min: PROTOCOL_MIN.0,
                client_max: PROTOCOL_MAX.0,
                server_min: 0,
                server_max: 0,
            })
    }

    async fn json_request<B: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        include_protocol: bool,
    ) -> Result<R, ClientError> {
        let mut headers = HeaderMap::new();
        let authorization = HeaderValue::from_str(&format!(
            "Bearer {}",
            self.token.expose_secret()
        ))
        .map_err(|_| {
            ClientError::Configuration("API token contains invalid header characters".to_owned())
        })?;
        headers.insert(AUTHORIZATION, authorization);
        if include_protocol {
            let protocol = self.protocol.lock().await.unwrap_or(PROTOCOL_MAX);
            headers.insert(
                PROTOCOL_HEADER,
                HeaderValue::from_str(&protocol.to_string())
                    .map_err(|error| ClientError::Serialization(error.to_string()))?,
            );
        }
        let body = match body {
            Some(body) => {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                serde_json::to_vec(body)
                    .map_err(|error| ClientError::Serialization(error.to_string()))?
            }
            None => Vec::new(),
        };
        let response = self
            .transport
            .execute(TransportRequest {
                method,
                path_and_query: path.to_owned(),
                headers,
                body,
            })
            .await?;
        parse_response(response)
    }
}

fn parse_response<R: DeserializeOwned>(response: TransportResponse) -> Result<R, ClientError> {
    if response.status.is_success() {
        return serde_json::from_slice(&response.body)
            .map_err(|error| ClientError::Serialization(error.to_string()));
    }
    if response.status == http::StatusCode::UNAUTHORIZED {
        return Err(ClientError::ApiAuthentication);
    }
    let error = serde_json::from_slice::<ApiErrorBody>(&response.body).unwrap_or(ApiErrorBody {
        code: "unexpected_response".to_owned(),
        message: "server returned a non-JSON error response".to_owned(),
        request_id: response
            .headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown")
            .to_owned(),
        current_revision: None,
        current_cursor: None,
    });
    Err(ClientError::Api {
        status: response.status.as_u16(),
        code: error.code,
        message: error.message,
    })
}
