# Development

The workspace uses Rust 2024, a committed `Cargo.lock`, centralized dependency versions, embedded immutable SQL migrations, and LF-enforced migration/scripts through `.gitattributes`.

Run the full repeatable check with `scripts/check.ps1` or `scripts/check.sh`. The sequence is formatting, Clippy with warnings denied, workspace tests, workspace build, clean frontend install, and frontend production build. `scripts/check-external.*` reports `READY` or explicit `SKIP` for Docker, OpenSSH server, and packet-capture tools.

Focused commands:

```sh
cargo test -p helium-sync-common
cargo test -p helium-sync-profile
cargo test -p helium-sync-server
cargo test -p helium-sync-client-core
cargo check -p helium-sync-client
```

Integration tests use temporary directories, in-memory secrets, a real rustls HTTPS socket, a controlled pure-Rust SSH server, and recording proxies below encryption. They assert that sentinel plaintext and bearer tokens are absent from captured outer bytes. Linux Unix-socket behavior, Docker, external OpenSSH, and packet capture remain host-dependent checks and must be reported as skipped when their prerequisites are absent.

Do not test restoration against a live profile. The only restore writer is test-only and rejects known live Helium user-data paths.
