use std::{collections::HashMap, sync::Mutex};

use secrecy::{ExposeSecret as _, SecretString};

use crate::ClientError;

pub trait SecretStore: Send + Sync {
    fn set(&self, key: &str, value: &SecretString) -> Result<(), ClientError>;
    fn get(&self, key: &str) -> Result<Option<SecretString>, ClientError>;
    fn delete(&self, key: &str) -> Result<(), ClientError>;
}

pub struct NativeSecretStore {
    service: String,
}

impl NativeSecretStore {
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry, ClientError> {
        keyring::Entry::new(&self.service, key)
            .map_err(|error| ClientError::SecretStore(error.to_string()))
    }
}

impl SecretStore for NativeSecretStore {
    fn set(&self, key: &str, value: &SecretString) -> Result<(), ClientError> {
        self.entry(key)?
            .set_password(value.expose_secret())
            .map_err(|error| ClientError::SecretStore(error.to_string()))
    }

    fn get(&self, key: &str) -> Result<Option<SecretString>, ClientError> {
        match self.entry(key)?.get_password() {
            Ok(value) => Ok(Some(SecretString::from(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(ClientError::SecretStore(error.to_string())),
        }
    }

    fn delete(&self, key: &str) -> Result<(), ClientError> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(ClientError::SecretStore(error.to_string())),
        }
    }
}

#[derive(Default)]
pub struct MemorySecretStore {
    values: Mutex<HashMap<String, String>>,
}

impl SecretStore for MemorySecretStore {
    fn set(&self, key: &str, value: &SecretString) -> Result<(), ClientError> {
        self.values
            .lock()
            .map_err(|_| ClientError::SecretStore("in-memory secret store lock failed".to_owned()))?
            .insert(key.to_owned(), value.expose_secret().to_owned());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<SecretString>, ClientError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| ClientError::SecretStore("in-memory secret store lock failed".to_owned()))?
            .get(key)
            .cloned()
            .map(SecretString::from))
    }

    fn delete(&self, key: &str) -> Result<(), ClientError> {
        self.values
            .lock()
            .map_err(|_| ClientError::SecretStore("in-memory secret store lock failed".to_owned()))?
            .remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trip_and_delete() {
        let store = MemorySecretStore::default();
        store
            .set("token", &SecretString::from("secret".to_owned()))
            .unwrap();
        assert_eq!(
            store.get("token").unwrap().unwrap().expose_secret(),
            "secret"
        );
        store.delete("token").unwrap();
        assert!(store.get("token").unwrap().is_none());
    }
}
