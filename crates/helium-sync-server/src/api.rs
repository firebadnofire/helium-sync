use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use helium_sync_common::{
    ApiErrorBody, BatchOperation, BatchRequest, BatchResponse, Change, ChangesResponse,
    DeleteObjectRequest, Device, DeviceId, ObjectId, PROTOCOL_HEADER, PROTOCOL_MAX, PROTOCOL_MIN,
    ProtocolRange, PutObjectRequest, RegisterDeviceRequest, StatusResponse, SyncObject, Timestamp,
    VersionResponse,
};
use secrecy::SecretString;
use serde::Deserialize;
use sqlx::{Row as _, Sqlite, SqlitePool, Transaction, sqlite::SqliteRow};
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_BATCH_OPERATIONS: usize = 100;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_CHANGES_LIMIT: u32 = 1_000;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub token_digest: [u8; 32],
}

impl AppState {
    #[must_use]
    pub fn new(pool: SqlitePool, token: &SecretString) -> Self {
        Self {
            pool,
            token_digest: crate::auth::token_digest(token),
        }
    }
}

pub struct ApiError {
    status: StatusCode,
    body: ApiErrorBody,
}

impl ApiError {
    #[must_use]
    pub fn new(status: StatusCode, code: &str, message: &str) -> Self {
        Self {
            status,
            body: ApiErrorBody {
                code: code.to_owned(),
                message: message.to_owned(),
                request_id: Uuid::new_v4().to_string(),
                current_revision: None,
                current_cursor: None,
            },
        }
    }

    #[must_use]
    fn conflict(current_revision: u64, current_cursor: u64) -> Self {
        let mut error = Self::new(
            StatusCode::CONFLICT,
            "revision_conflict",
            "the object changed since the supplied base revision",
        );
        error.body.current_revision = Some(current_revision);
        error.body.current_cursor = Some(current_cursor);
        error
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = HeaderValue::from_str(&self.body.request_id)
            .unwrap_or_else(|_| HeaderValue::from_static("invalid-request-id"));
        let mut response = (self.status, Json(self.body)).into_response();
        response.headers_mut().insert("x-request-id", request_id);
        response
    }
}

pub fn router(state: AppState) -> Router {
    let negotiated = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/devices", get(list_devices).post(register_device))
        .route("/v1/devices/{id}", delete(revoke_device))
        .route("/v1/changes", get(changes))
        .route(
            "/v1/objects/{id}",
            get(get_object).put(put_object).delete(delete_object),
        )
        .route("/v1/batch", post(batch))
        .layer(middleware::from_fn(require_protocol));

    Router::new()
        .route("/v1/version", get(version))
        .merge(negotiated)
        .layer(DefaultBodyLimit::max(MAX_PAYLOAD_BYTES + 64 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::require_auth,
        ))
        .with_state(state)
}

async fn require_protocol(request: Request, next: Next) -> Result<Response, ApiError> {
    let version = request
        .headers()
        .get(PROTOCOL_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u16>().ok());
    if version != Some(PROTOCOL_MAX.0) {
        return Err(ApiError::new(
            StatusCode::UPGRADE_REQUIRED,
            "protocol_incompatible",
            "a supported x-helium-sync-protocol header is required",
        ));
    }
    Ok(next.run(request).await)
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        server_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol: ProtocolRange {
            min: PROTOCOL_MIN,
            max: PROTOCOL_MAX,
        },
        capabilities: [
            "objects",
            "changes",
            "devices",
            "batch",
            "encrypted-envelope-v1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    })
}

async fn status(State(state): State<AppState>) -> Result<Json<StatusResponse>, ApiError> {
    sqlx::query("SELECT 1")
        .execute(&state.pool)
        .await
        .map_err(database_error)?;
    Ok(Json(StatusResponse {
        status: "ok".to_owned(),
        database: "ok".to_owned(),
        server_time: Timestamp::now_utc(),
        protocol: PROTOCOL_MAX,
    }))
}

async fn register_device(
    State(state): State<AppState>,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<Device>), ApiError> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_device_name",
            "device name must contain between 1 and 128 characters",
        ));
    }
    let existing = sqlx::query("SELECT name, created_at, revoked_at FROM devices WHERE id = ?")
        .bind(request.id.to_string())
        .fetch_optional(&state.pool)
        .await
        .map_err(database_error)?;
    if let Some(existing) = existing {
        let existing_name: String = existing.get("name");
        let revoked_at: Option<String> = existing.get("revoked_at");
        if existing_name == name && revoked_at.is_none() {
            return Ok((
                StatusCode::OK,
                Json(Device {
                    id: request.id,
                    name: existing_name,
                    created_at: parse_timestamp(&existing.get::<String, _>("created_at"))?,
                    revoked_at: None,
                }),
            ));
        }
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "device_exists",
            "a device with this ID is already registered with different or revoked metadata",
        ));
    }
    let created_at = Timestamp::now_utc();
    sqlx::query("INSERT INTO devices (id, name, created_at) VALUES (?, ?, ?)")
        .bind(request.id.to_string())
        .bind(name)
        .bind(timestamp_string(created_at)?)
        .execute(&state.pool)
        .await
        .map_err(database_error)?;
    Ok((
        StatusCode::CREATED,
        Json(Device {
            id: request.id,
            name: name.to_owned(),
            created_at,
            revoked_at: None,
        }),
    ))
}

async fn list_devices(State(state): State<AppState>) -> Result<Json<Vec<Device>>, ApiError> {
    let rows =
        sqlx::query("SELECT id, name, created_at, revoked_at FROM devices ORDER BY created_at, id")
            .fetch_all(&state.pool)
            .await
            .map_err(database_error)?;
    let devices = rows
        .into_iter()
        .map(|row| {
            Ok(Device {
                id: DeviceId(parse_uuid(row.get::<String, _>("id"), "device ID")?),
                name: row.get("name"),
                created_at: parse_timestamp(&row.get::<String, _>("created_at"))?,
                revoked_at: row
                    .get::<Option<String>, _>("revoked_at")
                    .map(|value| parse_timestamp(&value))
                    .transpose()?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(devices))
}

async fn revoke_device(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let revoked_at = timestamp_string(Timestamp::now_utc())?;
    let result =
        sqlx::query("UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(revoked_at)
            .bind(id.to_string())
            .execute(&state.pool)
            .await
            .map_err(database_error)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "device_not_found",
            "active device was not found",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn get_object(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SyncObject>, ApiError> {
    let row = sqlx::query("SELECT * FROM objects WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(&state.pool)
        .await
        .map_err(database_error)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "object_not_found",
                "sync object was not found",
            )
        })?;
    Ok(Json(row_to_object(&row)?))
}

async fn put_object(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<PutObjectRequest>,
) -> Result<Json<SyncObject>, ApiError> {
    let mut transaction = state.pool.begin().await.map_err(database_error)?;
    let object = put_object_tx(&mut transaction, ObjectId(id), request).await?;
    transaction.commit().await.map_err(database_error)?;
    Ok(Json(object))
}

async fn delete_object(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<DeleteObjectRequest>,
) -> Result<Json<SyncObject>, ApiError> {
    let mut transaction = state.pool.begin().await.map_err(database_error)?;
    let object = delete_object_tx(&mut transaction, ObjectId(id), request).await?;
    transaction.commit().await.map_err(database_error)?;
    Ok(Json(object))
}

#[derive(Debug, Deserialize)]
struct ChangesQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_changes_limit")]
    limit: u32,
}

const fn default_changes_limit() -> u32 {
    100
}

async fn changes(
    State(state): State<AppState>,
    Query(query): Query<ChangesQuery>,
) -> Result<Json<ChangesResponse>, ApiError> {
    if query.limit == 0 || query.limit > MAX_CHANGES_LIMIT {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_limit",
            "changes limit must be between 1 and 1000",
        ));
    }
    let rows = sqlx::query("SELECT * FROM changes WHERE cursor > ? ORDER BY cursor LIMIT ?")
        .bind(i64_from_u64(query.after, "after cursor")?)
        .bind(i64::from(query.limit) + 1)
        .fetch_all(&state.pool)
        .await
        .map_err(database_error)?;
    let has_more = rows.len() > query.limit as usize;
    let changes = rows
        .iter()
        .take(query.limit as usize)
        .map(row_to_change)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = changes.last().map_or(query.after, |change| change.cursor);
    Ok(Json(ChangesResponse {
        changes,
        next_cursor,
        has_more,
    }))
}

async fn batch(
    State(state): State<AppState>,
    Json(request): Json<BatchRequest>,
) -> Result<Json<BatchResponse>, ApiError> {
    if request.operations.is_empty() || request.operations.len() > MAX_BATCH_OPERATIONS {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_batch_size",
            "a batch must contain between 1 and 100 operations",
        ));
    }
    let mut transaction = state.pool.begin().await.map_err(database_error)?;
    let mut objects = Vec::with_capacity(request.operations.len());
    for operation in request.operations {
        let object = match operation {
            BatchOperation::Put { id, request } => {
                put_object_tx(&mut transaction, id, request).await?
            }
            BatchOperation::Delete { id, request } => {
                delete_object_tx(&mut transaction, id, request).await?
            }
        };
        objects.push(object);
    }
    transaction.commit().await.map_err(database_error)?;
    Ok(Json(BatchResponse { objects }))
}

async fn put_object_tx(
    transaction: &mut Transaction<'_, Sqlite>,
    id: ObjectId,
    request: PutObjectRequest,
) -> Result<SyncObject, ApiError> {
    validate_put(&request)?;
    ensure_active_device(transaction, request.device_id).await?;
    let current = sqlx::query("SELECT revision, cursor FROM objects WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .map(|row| (row.get::<i64, _>("revision"), row.get::<i64, _>("cursor")));
    let new_revision = match (current, request.base_revision) {
        (None, None) => 1,
        (Some((current, _)), Some(base)) if u64_from_i64(current, "revision")? == base => {
            base.checked_add(1).ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "revision_exhausted",
                    "object revision cannot be incremented",
                )
            })?
        }
        (Some((current, cursor)), _) => {
            return Err(ApiError::conflict(
                u64_from_i64(current, "revision")?,
                u64_from_i64(cursor, "cursor")?,
            ));
        }
        (None, Some(_)) => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "object_missing",
                "an update base revision was supplied for a missing object",
            ));
        }
    };
    let modified_at = timestamp_string(request.modified_at)?;
    let revision_i64 = i64_from_u64(new_revision, "revision")?;
    let result = sqlx::query(
        "INSERT INTO changes (object_id, namespace, revision, device_id, modified_at, deleted) VALUES (?, ?, ?, ?, ?, 0)",
    )
    .bind(id.to_string())
    .bind(&request.namespace)
    .bind(revision_i64)
    .bind(request.device_id.to_string())
    .bind(&modified_at)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    let cursor = u64_from_i64(result.last_insert_rowid(), "cursor")?;
    let envelope_json = serde_json::to_string(&request.envelope).map_err(serialization_error)?;
    sqlx::query(
        "INSERT INTO objects (id, namespace, revision, cursor, device_id, modified_at, deleted, envelope_json) VALUES (?, ?, ?, ?, ?, ?, 0, ?) ON CONFLICT(id) DO UPDATE SET namespace=excluded.namespace, revision=excluded.revision, cursor=excluded.cursor, device_id=excluded.device_id, modified_at=excluded.modified_at, deleted=0, envelope_json=excluded.envelope_json",
    )
    .bind(id.to_string())
    .bind(&request.namespace)
    .bind(revision_i64)
    .bind(i64_from_u64(cursor, "cursor")?)
    .bind(request.device_id.to_string())
    .bind(modified_at)
    .bind(envelope_json)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(SyncObject {
        id,
        namespace: request.namespace,
        revision: new_revision,
        cursor,
        device_id: request.device_id,
        modified_at: request.modified_at,
        deleted: false,
        envelope: Some(request.envelope),
    })
}

async fn delete_object_tx(
    transaction: &mut Transaction<'_, Sqlite>,
    id: ObjectId,
    request: DeleteObjectRequest,
) -> Result<SyncObject, ApiError> {
    ensure_active_device(transaction, request.device_id).await?;
    let row = sqlx::query("SELECT namespace, revision, cursor FROM objects WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "object_not_found",
                "sync object was not found",
            )
        })?;
    let namespace: String = row.get("namespace");
    let current = u64_from_i64(row.get("revision"), "revision")?;
    if current != request.base_revision {
        return Err(ApiError::conflict(
            current,
            u64_from_i64(row.get("cursor"), "cursor")?,
        ));
    }
    let new_revision = current.checked_add(1).ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "revision_exhausted",
            "object revision cannot be incremented",
        )
    })?;
    let modified_at = timestamp_string(request.modified_at)?;
    let result = sqlx::query(
        "INSERT INTO changes (object_id, namespace, revision, device_id, modified_at, deleted) VALUES (?, ?, ?, ?, ?, 1)",
    )
    .bind(id.to_string())
    .bind(&namespace)
    .bind(i64_from_u64(new_revision, "revision")?)
    .bind(request.device_id.to_string())
    .bind(&modified_at)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    let cursor = u64_from_i64(result.last_insert_rowid(), "cursor")?;
    sqlx::query("UPDATE objects SET revision=?, cursor=?, device_id=?, modified_at=?, deleted=1, envelope_json=NULL WHERE id=?")
        .bind(i64_from_u64(new_revision, "revision")?)
        .bind(i64_from_u64(cursor, "cursor")?)
        .bind(request.device_id.to_string())
        .bind(modified_at)
        .bind(id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    Ok(SyncObject {
        id,
        namespace,
        revision: new_revision,
        cursor,
        device_id: request.device_id,
        modified_at: request.modified_at,
        deleted: true,
        envelope: None,
    })
}

async fn ensure_active_device(
    transaction: &mut Transaction<'_, Sqlite>,
    id: DeviceId,
) -> Result<(), ApiError> {
    let row = sqlx::query("SELECT revoked_at FROM devices WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?;
    match row {
        Some(row) if row.get::<Option<String>, _>("revoked_at").is_none() => Ok(()),
        Some(_) => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "device_revoked",
            "the writing device is revoked",
        )),
        None => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "device_unregistered",
            "the writing device is not registered",
        )),
    }
}

fn validate_put(request: &PutObjectRequest) -> Result<(), ApiError> {
    if request.namespace.is_empty() || request.namespace.len() > 128 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_namespace",
            "namespace must contain between 1 and 128 characters",
        ));
    }
    if request.envelope.version != 1
        || request.envelope.algorithm != "XCHACHA20-POLY1305"
        || request.envelope.nonce.0.len() != 24
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_envelope",
            "encrypted envelope must use version 1 XChaCha20-Poly1305 with a 24-byte nonce",
        ));
    }
    if request.envelope.ciphertext.0.len() > MAX_PAYLOAD_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "encrypted payload exceeds the configured 4 MiB limit",
        ));
    }
    Ok(())
}

fn row_to_object(row: &SqliteRow) -> Result<SyncObject, ApiError> {
    let envelope_json: Option<String> = row.get("envelope_json");
    Ok(SyncObject {
        id: ObjectId(parse_uuid(row.get("id"), "object ID")?),
        namespace: row.get("namespace"),
        revision: u64_from_i64(row.get("revision"), "revision")?,
        cursor: u64_from_i64(row.get("cursor"), "cursor")?,
        device_id: DeviceId(parse_uuid(row.get("device_id"), "device ID")?),
        modified_at: parse_timestamp(&row.get::<String, _>("modified_at"))?,
        deleted: row.get::<i64, _>("deleted") != 0,
        envelope: envelope_json
            .map(|value| serde_json::from_str(&value).map_err(serialization_error))
            .transpose()?,
    })
}

fn row_to_change(row: &SqliteRow) -> Result<Change, ApiError> {
    Ok(Change {
        cursor: u64_from_i64(row.get("cursor"), "cursor")?,
        object_id: ObjectId(parse_uuid(row.get("object_id"), "object ID")?),
        namespace: row.get("namespace"),
        revision: u64_from_i64(row.get("revision"), "revision")?,
        device_id: DeviceId(parse_uuid(row.get("device_id"), "device ID")?),
        modified_at: parse_timestamp(&row.get::<String, _>("modified_at"))?,
        deleted: row.get::<i64, _>("deleted") != 0,
    })
}

fn timestamp_string(timestamp: Timestamp) -> Result<String, ApiError> {
    timestamp
        .0
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| serialization_error(error.to_string()))
}

fn parse_timestamp(value: &str) -> Result<Timestamp, ApiError> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(Timestamp)
        .map_err(|error| serialization_error(error.to_string()))
}

fn parse_uuid(value: String, label: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(&value)
        .map_err(|error| serialization_error(format!("invalid {label}: {error}")))
}

fn i64_from_u64(value: u64, label: &str) -> Result<i64, ApiError> {
    i64::try_from(value).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "numeric_range",
            &format!("{label} exceeds the supported range"),
        )
    })
}

fn u64_from_i64(value: i64, label: &str) -> Result<u64, ApiError> {
    u64::try_from(value).map_err(|_| serialization_error(format!("negative {label} in database")))
}

fn database_error(error: sqlx::Error) -> ApiError {
    tracing::error!(error = %error, "database operation failed");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "database_unavailable",
        "the server database operation failed",
    )
}

fn serialization_error(error: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %error, "stored protocol data was invalid");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "stored_data_invalid",
        "stored synchronization metadata was invalid",
    )
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Method, Request};
    use helium_sync_common::{Base64UrlBytes, EncryptedEnvelopeV1, ProtocolVersion};
    use http_body_util::BodyExt as _;
    use secrecy::SecretString;
    use tower::ServiceExt as _;

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    async fn call(
        app: &Router,
        method: Method,
        path: &str,
        body: Option<String>,
        token: Option<&str>,
        protocol: bool,
    ) -> Response {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if protocol {
            builder = builder.header(PROTOCOL_HEADER, ProtocolVersion(1).to_string());
        }
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        app.clone()
            .oneshot(builder.body(Body::from(body.unwrap_or_default())).unwrap())
            .await
            .unwrap()
    }

    async fn body_json<T: serde::de::DeserializeOwned>(response: Response) -> T {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn sample_put(device_id: DeviceId, base_revision: Option<u64>) -> PutObjectRequest {
        PutObjectRequest {
            namespace: "synthetic.v1".to_owned(),
            base_revision,
            device_id,
            modified_at: Timestamp::now_utc(),
            envelope: EncryptedEnvelopeV1 {
                version: 1,
                algorithm: "XCHACHA20-POLY1305".to_owned(),
                key_version: 1,
                nonce: Base64UrlBytes(vec![7; 24]),
                ciphertext: Base64UrlBytes(vec![9; 32]),
            },
        }
    }

    async fn register(app: &Router, device_id: DeviceId) {
        let request = RegisterDeviceRequest {
            id: device_id,
            name: "test device".to_owned(),
        };
        let response = call(
            app,
            Method::POST,
            "/v1/devices",
            Some(serde_json::to_string(&request).unwrap()),
            Some(TOKEN),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn authenticated_object_flow_and_conflict() {
        let pool = crate::storage::memory().await.unwrap();
        let app = router(AppState::new(pool, &SecretString::from(TOKEN.to_owned())));

        let response = call(&app, Method::GET, "/v1/version", None, None, false).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = call(&app, Method::GET, "/v1/version", None, Some(TOKEN), false).await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = call(&app, Method::GET, "/v1/status", None, Some(TOKEN), false).await;
        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);

        let device_id = DeviceId::new();
        register(&app, device_id).await;
        let repeated = RegisterDeviceRequest {
            id: device_id,
            name: "test device".to_owned(),
        };
        let response = call(
            &app,
            Method::POST,
            "/v1/devices",
            Some(serde_json::to_string(&repeated).unwrap()),
            Some(TOKEN),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let object_id = ObjectId::new();
        let put = sample_put(device_id, None);
        let path = format!("/v1/objects/{object_id}");
        let response = call(
            &app,
            Method::PUT,
            &path,
            Some(serde_json::to_string(&put).unwrap()),
            Some(TOKEN),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let stored: SyncObject = body_json(response).await;
        assert_eq!(stored.revision, 1);

        let response = call(&app, Method::GET, &path, None, Some(TOKEN), true).await;
        assert_eq!(response.status(), StatusCode::OK);
        let fetched: SyncObject = body_json(response).await;
        assert_eq!(fetched, stored);

        let response = call(
            &app,
            Method::PUT,
            &path,
            Some(serde_json::to_string(&put).unwrap()),
            Some(TOKEN),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let error: ApiErrorBody = body_json(response).await;
        assert_eq!(error.current_revision, Some(1));
        assert_eq!(error.current_cursor, Some(stored.cursor));

        let response = call(
            &app,
            Method::GET,
            "/v1/changes?after=0",
            None,
            Some(TOKEN),
            true,
        )
        .await;
        let changes: ChangesResponse = body_json(response).await;
        assert_eq!(changes.changes.len(), 1);
        assert_eq!(changes.changes[0].object_id, object_id);
    }

    #[tokio::test]
    async fn batch_is_atomic_and_revoked_devices_cannot_write() {
        let pool = crate::storage::memory().await.unwrap();
        let app = router(AppState::new(pool, &SecretString::from(TOKEN.to_owned())));
        let device_id = DeviceId::new();
        register(&app, device_id).await;

        let rolled_back_id = ObjectId::new();
        let missing_id = ObjectId::new();
        let batch = BatchRequest {
            operations: vec![
                BatchOperation::Put {
                    id: rolled_back_id,
                    request: sample_put(device_id, None),
                },
                BatchOperation::Delete {
                    id: missing_id,
                    request: DeleteObjectRequest {
                        base_revision: 1,
                        device_id,
                        modified_at: Timestamp::now_utc(),
                    },
                },
            ],
        };
        let response = call(
            &app,
            Method::POST,
            "/v1/batch",
            Some(serde_json::to_string(&batch).unwrap()),
            Some(TOKEN),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let rolled_back_path = format!("/v1/objects/{rolled_back_id}");
        let response = call(
            &app,
            Method::GET,
            &rolled_back_path,
            None,
            Some(TOKEN),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let retained_id = ObjectId::new();
        let retained_path = format!("/v1/objects/{retained_id}");
        let response = call(
            &app,
            Method::PUT,
            &retained_path,
            Some(serde_json::to_string(&sample_put(device_id, None)).unwrap()),
            Some(TOKEN),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let revoke_path = format!("/v1/devices/{device_id}");
        let response = call(&app, Method::DELETE, &revoke_path, None, Some(TOKEN), true).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = call(
            &app,
            Method::PUT,
            &retained_path,
            Some(serde_json::to_string(&sample_put(device_id, Some(1))).unwrap()),
            Some(TOKEN),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = call(&app, Method::GET, &retained_path, None, Some(TOKEN), true).await;
        let retained: SyncObject = body_json(response).await;
        assert_eq!(retained.revision, 1);
        assert!(!retained.deleted);
    }
}
