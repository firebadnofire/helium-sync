# Helium Sync

Helium Sync is an encrypted profile launcher and multi-device synchronizer for the Helium browser. The desktop client creates and launches isolated Helium profiles, reconciles bookmarks, copies installed extensions and extension-owned data, encrypts everything locally, and stores only opaque ciphertext on a self-hosted Linux server.

The first profile is presented as **You**. Add named profiles and launch any one with a click, similar to choosing an instance in MultiMC. Helium must be closed before creating, syncing, restoring, or switching profiles so Chromium cannot rewrite profile databases during the operation.

Independent bookmark additions, edits, and deletions are reconciled against an encrypted local merge base. Extension snapshots use conflict detection because their databases cannot be safely three-way merged. Every local replacement is backed up with Zstandard compression first. Open tabs, browsing history, passwords, website storage, and live in-browser synchronization are not synchronized.

> **New operator?** Start with the complete [download, build, deployment, client, backup, upgrade, and troubleshooting guide](op-guide.md).

## What is included

- A Rust workspace with shared protocol, profile discovery, client core, Tauri 2 desktop client, and Linux server crates.
- Authenticated TLS 1.3 HTTPS and SSH-to-Unix-socket transports with the same versioned API.
- XChaCha20-Poly1305 object encryption using client-held key material.
- SQLite state, atomic batches, conflict detection, change cursors, and tombstones.
- Cross-device encrypted profile discovery, three-way bookmark reconciliation, and chunked extension snapshots.
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
| `helium-sync-profile` | Helium discovery, profile allocation, bookmark canonicalization, and Zstandard ZIP-backed guarded restores |
| `helium-sync-client-core` | Transports, key storage, encryption, state, and workflows |
| `helium-sync-client` | Thin Tauri 2 adapters and vanilla TypeScript UI |
| `helium-sync-server` | Linux HTTPS/Unix-socket API and SQLite storage |

The server accepts one account-wide bearer token in protocol v1. Use a random token of at least 32 characters and keep the client recovery code secret.
