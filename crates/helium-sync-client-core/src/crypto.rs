use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use helium_sync_common::{
    Base64UrlBytes, DeviceId, EncryptedEnvelopeV1, ObjectId, ProtocolVersion, SyncObject, Timestamp,
};
use hkdf::Hkdf;
use rand::Rng as _;
use secrecy::{ExposeSecret as _, SecretBox};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

use crate::ClientError;

const RECOVERY_PREFIX: &str = "hsync1:";
const MASTER_KEY_LENGTH: usize = 32;

pub struct MasterKey(SecretBox<[u8; MASTER_KEY_LENGTH]>);

impl MasterKey {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; MASTER_KEY_LENGTH];
        rand::rng().fill_bytes(&mut bytes);
        Self(SecretBox::new(Box::new(bytes)))
    }

    pub fn from_recovery_code(code: &str) -> Result<Self, ClientError> {
        let encoded = code.strip_prefix(RECOVERY_PREFIX).ok_or_else(|| {
            ClientError::Crypto("recovery code must start with hsync1:".to_owned())
        })?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ClientError::Crypto("recovery code is not valid base64url".to_owned()))?;
        if decoded.len() != MASTER_KEY_LENGTH + 4 {
            return Err(ClientError::Crypto(
                "recovery code has an invalid length".to_owned(),
            ));
        }
        let (key, checksum) = decoded.split_at(MASTER_KEY_LENGTH);
        let expected = Sha256::digest(key);
        if checksum != &expected[..4] {
            return Err(ClientError::Crypto(
                "recovery code checksum did not match".to_owned(),
            ));
        }
        let mut bytes = [0_u8; MASTER_KEY_LENGTH];
        bytes.copy_from_slice(key);
        Ok(Self(SecretBox::new(Box::new(bytes))))
    }

    #[must_use]
    pub fn recovery_code(&self) -> String {
        let key = self.0.expose_secret();
        let checksum = Sha256::digest(key);
        let mut encoded = Vec::with_capacity(MASTER_KEY_LENGTH + 4);
        encoded.extend_from_slice(key);
        encoded.extend_from_slice(&checksum[..4]);
        format!("{RECOVERY_PREFIX}{}", URL_SAFE_NO_PAD.encode(encoded))
    }
}

pub struct ObjectMetadata<'a> {
    pub protocol: ProtocolVersion,
    pub object_id: ObjectId,
    pub namespace: &'a str,
    pub device_id: DeviceId,
    pub revision: u64,
    pub modified_at: Timestamp,
}

pub fn encrypt(
    master_key: &MasterKey,
    metadata: &ObjectMetadata<'_>,
    plaintext: &[u8],
) -> Result<EncryptedEnvelopeV1, ClientError> {
    let mut key = derive_key(master_key, metadata.object_id, metadata.namespace, 1)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    let aad = associated_data(metadata, 1)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ClientError::Crypto("payload encryption failed".to_owned()))?;
    key.zeroize();
    Ok(EncryptedEnvelopeV1 {
        version: 1,
        algorithm: "XCHACHA20-POLY1305".to_owned(),
        key_version: 1,
        nonce: Base64UrlBytes(nonce.to_vec()),
        ciphertext: Base64UrlBytes(ciphertext),
    })
}

pub fn decrypt(master_key: &MasterKey, object: &SyncObject) -> Result<Vec<u8>, ClientError> {
    let envelope = object.envelope.as_ref().ok_or_else(|| {
        ClientError::Crypto("deleted object does not contain an encrypted payload".to_owned())
    })?;
    if envelope.version != 1
        || envelope.key_version != 1
        || envelope.algorithm != "XCHACHA20-POLY1305"
        || envelope.nonce.0.len() != 24
    {
        return Err(ClientError::Crypto(
            "encrypted envelope algorithm or version is unsupported".to_owned(),
        ));
    }
    let metadata = ObjectMetadata {
        protocol: helium_sync_common::PROTOCOL_MAX,
        object_id: object.id,
        namespace: &object.namespace,
        device_id: object.device_id,
        revision: object.revision,
        modified_at: object.modified_at,
    };
    let mut key = derive_key(
        master_key,
        object.id,
        &object.namespace,
        envelope.key_version,
    )?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let aad = associated_data(&metadata, envelope.version)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&envelope.nonce.0),
            Payload {
                msg: &envelope.ciphertext.0,
                aad: &aad,
            },
        )
        .map_err(|_| {
            ClientError::Crypto(
                "ciphertext authentication failed; payload or metadata was changed".to_owned(),
            )
        })?;
    key.zeroize();
    Ok(plaintext)
}

fn derive_key(
    master_key: &MasterKey,
    object_id: ObjectId,
    namespace: &str,
    key_version: u32,
) -> Result<[u8; 32], ClientError> {
    let hkdf = Hkdf::<Sha256>::new(Some(object_id.0.as_bytes()), master_key.0.expose_secret());
    let mut info = b"helium-sync/object-key/".to_vec();
    append_field(&mut info, namespace.as_bytes())?;
    info.extend_from_slice(&key_version.to_be_bytes());
    let mut key = [0_u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| ClientError::Crypto("object key derivation failed".to_owned()))?;
    Ok(key)
}

fn associated_data(
    metadata: &ObjectMetadata<'_>,
    envelope_version: u8,
) -> Result<Vec<u8>, ClientError> {
    let mut aad = b"helium-sync/aad/v1".to_vec();
    aad.extend_from_slice(&metadata.protocol.0.to_be_bytes());
    append_field(&mut aad, metadata.object_id.0.as_bytes())?;
    append_field(&mut aad, metadata.namespace.as_bytes())?;
    append_field(&mut aad, metadata.device_id.0.as_bytes())?;
    aad.extend_from_slice(&metadata.revision.to_be_bytes());
    let timestamp = metadata
        .modified_at
        .0
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| ClientError::Serialization(error.to_string()))?;
    append_field(&mut aad, timestamp.as_bytes())?;
    aad.push(envelope_version);
    Ok(aad)
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) -> Result<(), ClientError> {
    let length = u32::try_from(field.len())
        .map_err(|_| ClientError::Crypto("authenticated metadata is too large".to_owned()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(object_id: ObjectId, device_id: DeviceId) -> ObjectMetadata<'static> {
        ObjectMetadata {
            protocol: ProtocolVersion(1),
            object_id,
            namespace: "synthetic.v1",
            device_id,
            revision: 1,
            modified_at: Timestamp(time::macros::datetime!(2026-01-01 0:00 UTC)),
        }
    }

    #[test]
    fn encrypted_round_trip_and_no_plaintext() {
        let key = MasterKey::generate();
        let object_id = ObjectId::new();
        let device_id = DeviceId::new();
        let metadata = metadata(object_id, device_id);
        let plaintext = b"HELIUM_SYNC_TRANSPORT_TEST_PLAINTEXT_7f3a";
        let envelope = encrypt(&key, &metadata, plaintext).unwrap();
        let encoded = serde_json::to_vec(&envelope).unwrap();
        assert!(
            !encoded
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
        let object = SyncObject {
            id: object_id,
            namespace: metadata.namespace.to_owned(),
            revision: 1,
            cursor: 1,
            device_id,
            modified_at: metadata.modified_at,
            deleted: false,
            envelope: Some(envelope),
        };
        assert_eq!(decrypt(&key, &object).unwrap(), plaintext);
    }

    #[test]
    fn malformed_ciphertext_is_rejected() {
        let key = MasterKey::generate();
        let object_id = ObjectId::new();
        let device_id = DeviceId::new();
        let metadata = metadata(object_id, device_id);
        let mut envelope = encrypt(&key, &metadata, b"secret").unwrap();
        envelope.ciphertext.0[0] ^= 1;
        let object = SyncObject {
            id: object_id,
            namespace: metadata.namespace.to_owned(),
            revision: 1,
            cursor: 1,
            device_id,
            modified_at: metadata.modified_at,
            deleted: false,
            envelope: Some(envelope),
        };
        assert!(decrypt(&key, &object).is_err());
    }

    #[test]
    fn recovery_code_round_trips_and_detects_typo() {
        let key = MasterKey::generate();
        let code = key.recovery_code();
        let recovered = MasterKey::from_recovery_code(&code).unwrap();
        assert_eq!(recovered.recovery_code(), code);
        let mut invalid = code;
        invalid.push('A');
        assert!(MasterKey::from_recovery_code(&invalid).is_err());
    }
}
