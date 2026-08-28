# Helium Sync

Helium Sync is an initial encrypted bookmark export proof for the Helium browser. The desktop client discovers local Helium profiles, canonicalizes the selected profile's `Bookmarks` JSON, encrypts it locally, and verifies upload/retrieval against a self-hosted Linux server. The server stores only opaque ciphertext.

This release is deliberately not continuous synchronization and never writes retrieved data into a live Helium profile.

## What is included

- A Rust workspace with shared protocol, profile discovery, client core, Tauri 2 desktop client, and Linux server crates.
- Authenticated TLS 1.3 HTTPS and SSH-to-Unix-socket transports with the same versioned API.
- XChaCha20-Poly1305 object encryption using client-held key material.
- SQLite state, atomic batches, conflict detection, change cursors, and tombstones.
- Docker Compose and hardened systemd deployment examples.

## Start here

- [Quick start](docs/quick-start.md)
- [Docker deployment](docs/docker.md)
- [Binary installation](docs/binary-install.md)
- [Desktop client](docs/client.md)
- [Configuration](docs/configuration.md)
- [TLS](docs/tls.md) and [SSH](docs/ssh.md)
- [Backup and restore](docs/backup-restore.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security model](docs/security-model.md)
- [Protocol](docs/protocol.md)
- [Development](docs/development.md)

## Workspace

| Package | Purpose |
| --- | --- |
| `helium-sync-common` | Versioned wire DTOs and validated IDs/timestamps/binary fields |
| `helium-sync-profile` | Read-only Helium discovery and bookmark canonicalization |
| `helium-sync-client-core` | Transports, key storage, encryption, state, and workflows |
| `helium-sync-client` | Thin Tauri 2 adapters and vanilla TypeScript UI |
| `helium-sync-server` | Linux HTTPS/Unix-socket API and SQLite storage |

The server accepts one account-wide bearer token in protocol v1. Use a random token of at least 32 characters and keep the client recovery code secret.
