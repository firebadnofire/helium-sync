# Security model

Helium Sync protects bookmark and extension-profile content from the storage server and observers in transit. The client generates the master key and derives a distinct per-object key using HKDF-SHA-256 over object ID, namespace, and key version. XChaCha20-Poly1305 uses a fresh 192-bit nonce and authenticates deterministic length-prefixed protocol/object/device/revision/timestamp/envelope metadata.

HTTPS uses TLS 1.3 certificate validation. SSH uses strict known-host verification and encrypted direct-streamlocal forwarding. The bearer token is required on every `/v1` route, hashed before constant-time comparison, and is not logged. Client tokens, key passphrases, and master keys go only to the native OS secret store; production has no plaintext fallback. After authentication succeeds, one versioned keyring record stores the complete connection form. Invalid attempts do not replace the last working record.

Three-way reconciliation retains the last synchronized bookmark snapshot in client SQLite. That merge base is encrypted with XChaCha20-Poly1305 under a separate HKDF-derived, purpose-bound local-state key; plaintext bookmark bases are not stored in the database.

Extension data is captured only while Helium is closed, compressed with Zstandard, split below the server object limit, encrypted per chunk, and referenced by an encrypted manifest. SHA-256 hashes authenticate the expected chunk sequence in addition to each object's AEAD authentication. Copy-on-write publication keeps the previous manifest valid until all new chunks have uploaded and round-trip verified. Extension base hashes are purpose-bound and encrypted in local state; simultaneous local and remote changes require an explicit recovery choice.

Profile archives remain local and are moved atomically into a UUID-named directory under the Helium user-data directory so the move stays on the same volume. Restore refuses a destination collision. Permanent deletion is available only for a registered archive, validates that the UUID directory resolves directly beneath the managed archive root, and requires UI confirmation.

The server can observe object IDs, revisions, device IDs, ciphertext sizes, timing, change cursors, and tombstones. It cannot decrypt payloads without a recovery code or compromised client. The single v1 bearer token authorizes the whole self-hosted account; it is not multi-user isolation.

Threats outside this slice include a compromised client/OS secret store, malicious browser bookmark content later rendered elsewhere, traffic analysis, availability attacks, and loss of every recovery-code copy. Revoking a device blocks its future writes but intentionally retains existing objects.
