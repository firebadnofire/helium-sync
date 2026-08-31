# Helium Sync

Helium Sync provides encrypted multi-device bookmark synchronization for the Helium browser. The desktop client discovers local Helium profiles, reconciles local and server changes, encrypts them locally, and stores only opaque ciphertext on a self-hosted Linux server.

While the desktop client is open and signed in, enabled profiles are checked every 30 seconds. Independent bookmark additions, edits, and deletions are reconciled against an encrypted local merge base. Any local replacement is backed up with Zstandard compression first. Helium must be closed before server changes can be applied locally; the client detects the installed Helium executable and refuses to race it.

This is bookmark continuity, not full Chrome/Firefox parity. Open tabs, browsing history, passwords, extensions, preferences, and live in-browser synchronization are not yet synchronized.

> **New operator?** Start with the complete [download, build, deployment, client, backup, upgrade, and troubleshooting guide](op-guide.md).

## What is included

- A Rust workspace with shared protocol, profile discovery, client core, Tauri 2 desktop client, and Linux server crates.
- Authenticated TLS 1.3 HTTPS and SSH-to-Unix-socket transports with the same versioned API.
- XChaCha20-Poly1305 object encryption using client-held key material.
- SQLite state, atomic batches, conflict detection, change cursors, and tombstones.
- Cross-device encrypted profile discovery and three-way bookmark reconciliation.
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
| `helium-sync-profile` | Helium discovery, bookmark canonicalization, and ZIP-backed guarded restore |
| `helium-sync-client-core` | Transports, key storage, encryption, state, and workflows |
| `helium-sync-client` | Thin Tauri 2 adapters and vanilla TypeScript UI |
| `helium-sync-server` | Linux HTTPS/Unix-socket API and SQLite storage |

The server accepts one account-wide bearer token in protocol v1. Use a random token of at least 32 characters and keep the client recovery code secret.
