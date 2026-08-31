use std::{path::Path, str::FromStr as _};

use helium_sync_common::{DeviceId, ObjectId};
use sqlx::{
    Row as _, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

use crate::ClientError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePreference {
    pub directory_name: String,
    pub display_name: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMapping {
    pub object_id: ObjectId,
    pub revision: u64,
}

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

    pub async fn mapping(
        &self,
        server_id: &str,
        namespace: &str,
        local_key: &str,
    ) -> Result<Option<ObjectMapping>, ClientError> {
        let row = sqlx::query(
            "SELECT object_id, revision FROM object_mappings WHERE server_id=? AND namespace=? AND local_key=?",
        )
        .bind(server_id)
        .bind(namespace)
        .bind(local_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| ClientError::State(error.to_string()))?;
        row.map(|row| {
            let object_id = uuid::Uuid::parse_str(&row.get::<String, _>("object_id"))
                .map(ObjectId)
                .map_err(|error| ClientError::State(error.to_string()))?;
            let revision = u64::try_from(row.get::<i64, _>("revision"))
                .map_err(|error| ClientError::State(error.to_string()))?;
            Ok(ObjectMapping {
                object_id,
                revision,
            })
        })
        .transpose()
    }

    pub async fn ensure_profile(
        &self,
        directory_name: &str,
        display_name: &str,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "INSERT INTO profile_preferences (directory_name, display_name) VALUES (?, ?) ON CONFLICT(directory_name) DO NOTHING",
        )
        .bind(directory_name)
        .bind(display_name)
        .execute(&self.pool)
        .await
        .map_err(|error| ClientError::State(error.to_string()))?;
        Ok(())
    }

    pub async fn profile_preferences(&self) -> Result<Vec<ProfilePreference>, ClientError> {
        let rows = sqlx::query(
            "SELECT directory_name, display_name, is_default FROM profile_preferences ORDER BY display_name COLLATE NOCASE, directory_name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| ClientError::State(error.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|row| ProfilePreference {
                directory_name: row.get("directory_name"),
                display_name: row.get("display_name"),
                is_default: row.get::<i64, _>("is_default") == 1,
            })
            .collect())
    }

    pub async fn rename_profile(
        &self,
        directory_name: &str,
        display_name: &str,
    ) -> Result<(), ClientError> {
        let display_name = display_name.trim();
        if display_name.is_empty() || display_name.chars().count() > 128 {
            return Err(ClientError::State(
                "profile name must contain 1 to 128 characters".to_owned(),
            ));
        }
        let result = sqlx::query(
            "UPDATE profile_preferences SET display_name=?, updated_at=CURRENT_TIMESTAMP WHERE directory_name=?",
        )
        .bind(display_name)
        .bind(directory_name)
        .execute(&self.pool)
        .await
        .map_err(|error| ClientError::State(error.to_string()))?;
        if result.rows_affected() != 1 {
            return Err(ClientError::State("profile is not registered".to_owned()));
        }
        Ok(())
    }

    pub async fn set_default_profile(&self, directory_name: &str) -> Result<(), ClientError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        let exists = sqlx::query("SELECT 1 FROM profile_preferences WHERE directory_name=?")
            .bind(directory_name)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?
            .is_some();
        if !exists {
            return Err(ClientError::State("profile is not registered".to_owned()));
        }
        sqlx::query("UPDATE profile_preferences SET is_default=0 WHERE is_default=1")
            .execute(&mut *transaction)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        sqlx::query("UPDATE profile_preferences SET is_default=1, updated_at=CURRENT_TIMESTAMP WHERE directory_name=?")
            .bind(directory_name)
            .execute(&mut *transaction)
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        transaction
            .commit()
            .await
            .map_err(|error| ClientError::State(error.to_string()))?;
        Ok(())
    }

    pub async fn default_profile(&self) -> Result<Option<ProfilePreference>, ClientError> {
        Ok(self
            .profile_preferences()
            .await?
            .into_iter()
            .find(|profile| profile.is_default))
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

    #[tokio::test]
    async fn persists_profile_names_default_and_object_mapping() {
        let state = LocalState::memory().await.unwrap();
        state.ensure_profile("Default", "Person 1").await.unwrap();
        state.ensure_profile("Profile 2", "Work").await.unwrap();
        state.rename_profile("Default", "Personal").await.unwrap();
        state.set_default_profile("Default").await.unwrap();

        let profiles = state.profile_preferences().await.unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(
            state.default_profile().await.unwrap().unwrap().display_name,
            "Personal"
        );

        state.set_default_profile("Profile 2").await.unwrap();
        assert_eq!(
            state
                .default_profile()
                .await
                .unwrap()
                .unwrap()
                .directory_name,
            "Profile 2"
        );

        let object_id = ObjectId::new();
        state
            .save_mapping("server", "helium.bookmarks.v1", "Profile 2", object_id, 4)
            .await
            .unwrap();
        assert_eq!(
            state
                .mapping("server", "helium.bookmarks.v1", "Profile 2")
                .await
                .unwrap(),
            Some(ObjectMapping {
                object_id,
                revision: 4
            })
        );
    }
}
