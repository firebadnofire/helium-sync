# Server configuration

Values resolve in this order: command line, environment, TOML, then defaults. A bearer token is intentionally not accepted as a command-line value because process listings can expose arguments; use `--token-file` for the command-line-precedence override.

| Setting | CLI / environment | Default |
| --- | --- | --- |
| Listen | `--listen` / `HELIUM_SYNC_LISTEN` | `0.0.0.0:7500` |
| Data | `--data-dir` / `HELIUM_SYNC_DATA_DIR` | `/var/lib/helium-sync` |
| Database | `--database` / `HELIUM_SYNC_DATABASE` | data directory + `server.sqlite3` |
| Socket | `--unix-socket` / `HELIUM_SYNC_UNIX_SOCKET` | `/run/helium-sync/server.sock` |
| Socket mode | TOML / `HELIUM_SYNC_UNIX_SOCKET_MODE` | `0660` |
| Socket group | `--unix-socket-group` / `HELIUM_SYNC_UNIX_SOCKET_GROUP` | unchanged |
| Certificate | `--tls-certificate` / `HELIUM_SYNC_TLS_CERTIFICATE` | required |
| Private key | `--tls-private-key` / `HELIUM_SYNC_TLS_PRIVATE_KEY` | required |
| Token | `--token-file` / `HELIUM_SYNC_TOKEN` / TOML | required, 32+ characters |
| Logging | `--log-level` / `HELIUM_SYNC_LOG_LEVEL` | `info` |

Use [server.example.toml](../config/server.example.toml) as the schema. `check` validates paths, permissions visible to the current user, token strength, PEM parsing, certificate dates, and key consistency without starting listeners.
