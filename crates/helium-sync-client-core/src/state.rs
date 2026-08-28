use std::{path::Path, str::FromStr as _};

use helium_sync_common::{DeviceId, ObjectId};
use sqlx::{
    Row as _, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

use crate::ClientError;

pub struct LocalState {
    pool: SqlitePool,
}

impl LocalState {
    pub async fn open(path: &Path) -> Result<Self, ClientError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|error| ClientError::State(error.to_string()))?;
        }
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .map_err(|error| ClientError::State(error.to_string()))?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        Ok(Self { pool })
    }

    pub async fn memory() -> Result<Self, ClientError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        Ok(Self { pool })
    }

    pub async fn device_id(&self) -> Result<DeviceId, ClientError> {
        if let Some(row) = sqlx::query("SELECT value FROM client_metadata WHERE key='device_id'")
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?
        {
            let value: String = row.get("value");
            return uuid::Uuid::parse_str(&value)
                .map(DeviceId)
                .map_err(|error| ClientError::State(error.to_string()));
        }
        let id = DeviceId::new();
        sqlx::query("INSERT INTO client_metadata (key, value) VALUES ('device_id', ?)")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        Ok(id)
    }

    pub async fn cursor(&self, server_id: &str) -> Result<u64, ClientError> {
        let row = sqlx::query("SELECT cursor FROM server_cursors WHERE server_id=?")
            .bind(server_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        row.map_or(Ok(0), |row| {
            u64::try_from(row.get::<i64, _>("cursor"))
                .map_err(|error| ClientError::State(error.to_string()))
        })
    }

    pub async fn set_cursor(&self, server_id: &str, cursor: u64) -> Result<(), ClientError> {
        let cursor =
            i64::try_from(cursor).map_err(|error| ClientError::State(error.to_string()))?;
        sqlx::query("INSERT INTO server_cursors (server_id, cursor) VALUES (?, ?) ON CONFLICT(server_id) DO UPDATE SET cursor=excluded.cursor")
            .bind(server_id)
            .bind(cursor)
            .execute(&self.pool)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        Ok(())
    }

    pub async fn save_connection(
        &self,
        server_id: &str,
        transport: &str,
        endpoint: &str,
    ) -> Result<(), ClientError> {
        sqlx::query("INSERT INTO server_connections (server_id, transport, endpoint) VALUES (?, ?, ?) ON CONFLICT(server_id) DO UPDATE SET transport=excluded.transport, endpoint=excluded.endpoint, updated_at=CURRENT_TIMESTAMP")
            .bind(server_id)
            .bind(transport)
            .bind(endpoint)
            .execute(&self.pool)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        Ok(())
    }

    pub async fn save_mapping(
        &self,
        server_id: &str,
        namespace: &str,
        local_key: &str,
        object_id: ObjectId,
        revision: u64,
    ) -> Result<(), ClientError> {
        let revision =
            i64::try_from(revision).map_err(|error| ClientError::State(error.to_string()))?;
        sqlx::query("INSERT INTO object_mappings (server_id, namespace, local_key, object_id, revision) VALUES (?, ?, ?, ?, ?) ON CONFLICT(server_id, namespace, local_key) DO UPDATE SET object_id=excluded.object_id, revision=excluded.revision")
            .bind(server_id).bind(namespace).bind(local_key).bind(object_id.to_string()).bind(revision)
            .execute(&self.pool).await.map_err(|error| ClientError::State(error.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn persists_identity_and_cursor() {
        let state = LocalState::memory().await.unwrap();
        let first = state.device_id().await.unwrap();
        assert_eq!(state.device_id().await.unwrap(), first);
        assert_eq!(state.cursor("server").await.unwrap(), 0);
        state.set_cursor("server", 42).await.unwrap();
        assert_eq!(state.cursor("server").await.unwrap(), 42);
        state
            .save_connection("server", "https", "https://example.test:7500")
            .await
            .unwrap();
        let row =
            sqlx::query("SELECT transport, endpoint FROM server_connections WHERE server_id=?")
                .bind("server")
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(row.get::<String, _>("transport"), "https");
        assert_eq!(
            row.get::<String, _>("endpoint"),
            "https://example.test:7500"
        );
    }
}
