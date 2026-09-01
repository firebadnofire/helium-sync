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

## Release preparation

Rust workspace, npm client, and Tauri versions must match exactly. The release workflow accepts only a matching SemVer tag such as `v0.5.0` and fails before building when any source version differs. First-party release archives are `.tar.zst`; gzip and deflate archives are not produced.

Before creating a tag, run the full check, parse `.forgejo/workflows/release.yml` as YAML, validate every embedded `run` block with Linux `bash -n`, and build the platform release bundle. Local success does not prove hosted runners, configured signing secrets, detached-signature publication, or mirrored releases.

Integration tests use temporary directories, in-memory secrets, a real rustls HTTPS socket, a controlled pure-Rust SSH server, and recording proxies below encryption. They assert that sentinel plaintext and bearer tokens are absent from captured outer bytes. Linux Unix-socket behavior, Docker, external OpenSSH, and packet capture remain host-dependent checks and must be reported as skipped when their prerequisites are absent.

The ignored `remote_smoke` test exercises an explicitly configured live server over both HTTPS and real OpenSSH without embedding secrets or host-specific paths. Set `HELIUM_SYNC_TEST_URL`, `HELIUM_SYNC_TEST_TOKEN_FILE`, `HELIUM_SYNC_TEST_CA`, `HELIUM_SYNC_TEST_SSH_HOST`, `HELIUM_SYNC_TEST_SSH_USER`, `HELIUM_SYNC_TEST_SSH_KEY`, and `HELIUM_SYNC_TEST_SSH_SOCKET`, then run:

```sh
cargo test -p helium-sync-client-core --test remote_smoke -- --ignored
```

Do not test restoration against a live profile. The only restore writer is test-only and rejects known live Helium user-data paths.
