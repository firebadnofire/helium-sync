//! Transport-neutral Helium Sync protocol types.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use time::OffsetDateTime;
use uuid::Uuid;

pub const PROTOCOL_MIN: ProtocolVersion = ProtocolVersion(1);
pub const PROTOCOL_MAX: ProtocolVersion = ProtocolVersion(1);
pub const PROTOCOL_HEADER: &str = "x-helium-sync-protocol";

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(ObjectId);
uuid_id!(DeviceId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolVersion(pub u16);

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolRange {
    pub min: ProtocolVersion,
    pub max: ProtocolVersion,
}

impl ProtocolRange {
    #[must_use]
    pub fn negotiate(self, peer: Self) -> Option<ProtocolVersion> {
        let lowest_max = self.max.min(peer.max);
        (lowest_max >= self.min.max(peer.min)).then_some(lowest_max)
    }
}

impl Default for ProtocolRange {
    fn default() -> Self {
        Self {
            min: PROTOCOL_MIN,
            max: PROTOCOL_MAX,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub OffsetDateTime);

impl Timestamp {
    #[must_use]
    pub fn now_utc() -> Self {
        Self(OffsetDateTime::now_utc())
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self
            .0
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&value)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339)
            .map(Self)
            .map_err(D::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Base64UrlBytes(pub Vec<u8>);

impl fmt::Debug for Base64UrlBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Base64UrlBytes")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Serialize for Base64UrlBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64UrlBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map(Self)
            .map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelopeV1 {
    pub version: u8,
    pub algorithm: String,
    pub key_version: u32,
    pub nonce: Base64UrlBytes,
    pub ciphertext: Base64UrlBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncObject {
    pub id: ObjectId,
    pub namespace: String,
    pub revision: u64,
    pub cursor: u64,
    pub device_id: DeviceId,
    pub modified_at: Timestamp,
    pub deleted: bool,
    pub envelope: Option<EncryptedEnvelopeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutObjectRequest {
    pub namespace: String,
    pub base_revision: Option<u64>,
    pub device_id: DeviceId,
    pub modified_at: Timestamp,
    pub envelope: EncryptedEnvelopeV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteObjectRequest {
    pub base_revision: u64,
    pub device_id: DeviceId,
    pub modified_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum BatchOperation {
    Put {
        id: ObjectId,
        request: PutObjectRequest,
    },
    Delete {
        id: ObjectId,
        request: DeleteObjectRequest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRequest {
    pub operations: Vec<BatchOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchResponse {
    pub objects: Vec<SyncObject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub cursor: u64,
    pub object_id: ObjectId,
    pub namespace: String,
    pub revision: u64,
    pub device_id: DeviceId,
    pub modified_at: Timestamp,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesResponse {
    pub changes: Vec<Change>,
    pub next_cursor: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub name: String,
    pub created_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub id: DeviceId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionResponse {
    pub server_version: String,
    pub protocol: ProtocolRange,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub database: String,
    pub server_time: Timestamp,
    pub protocol: ProtocolVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_cursor: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiates_highest_overlapping_version() {
        let local = ProtocolRange {
            min: ProtocolVersion(1),
            max: ProtocolVersion(3),
        };
        let peer = ProtocolRange {
            min: ProtocolVersion(2),
            max: ProtocolVersion(4),
        };
        assert_eq!(local.negotiate(peer), Some(ProtocolVersion(3)));
    }

    #[test]
    fn rejects_non_overlapping_protocols() {
        let local = ProtocolRange::default();
        let peer = ProtocolRange {
            min: ProtocolVersion(2),
            max: ProtocolVersion(2),
        };
        assert_eq!(local.negotiate(peer), None);
    }

    #[test]
    fn binary_json_is_base64url_and_round_trips() {
        let bytes = Base64UrlBytes(vec![0, 1, 2, 250, 255]);
        let json = serde_json::to_string(&bytes).expect("serialize bytes");
        assert_eq!(json, "\"AAEC-v8\"");
        assert_eq!(
            serde_json::from_str::<Base64UrlBytes>(&json).unwrap(),
            bytes
        );
    }

    #[test]
    fn timestamp_round_trips_as_rfc3339() {
        let timestamp = Timestamp(OffsetDateTime::UNIX_EPOCH);
        let json = serde_json::to_string(&timestamp).expect("serialize timestamp");
        assert_eq!(json, "\"1970-01-01T00:00:00Z\"");
        assert_eq!(serde_json::from_str::<Timestamp>(&json).unwrap(), timestamp);
    }
}
