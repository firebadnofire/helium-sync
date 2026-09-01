# Quick start

## Build and test

Install Rust 1.94 or newer and Node.js 24 or a current LTS release. On Windows, install the Tauri 2 prerequisites: Microsoft C++ Build Tools and WebView2.

```powershell
./scripts/check.ps1
```

On Linux or macOS:

```sh
./scripts/check.sh
```

## Start a development server

The server runtime is Linux-only. Generate a strong token and an explicitly local development certificate:

```sh
install -d -m 0700 .local/tls .local/data .local/run
openssl rand -base64 48 > .local/token
cargo run -p helium-sync-server -- generate-dev-cert --output-dir .local/tls
cargo run -p helium-sync-server -- check \
  --listen 127.0.0.1:7500 \
  --data-dir .local/data \
  --unix-socket .local/run/server.sock \
  --tls-certificate .local/tls/server.crt \
  --tls-private-key .local/tls/server.key \
  --token-file .local/token
cargo run -p helium-sync-server -- serve \
  --listen 127.0.0.1:7500 \
  --data-dir .local/data \
  --unix-socket .local/run/server.sock \
  --tls-certificate .local/tls/server.crt \
  --tls-private-key .local/tls/server.key \
  --token-file .local/token
```

The certificate generator is idempotent: it preserves a complete existing pair and refuses a partial pair.

## Start the desktop client

```sh
cd crates/helium-sync-client
npm ci
npm run tauri dev
```

For the generated certificate, select custom CA and choose `server.crt`. Close Helium, create or select a profile, choose a default, and use **Sync now** or leave **Automatic** enabled. Import the first device's `hsync1:` recovery code on every additional trusted device. **Launch** starts Helium with the selected profile directory. Keep Helium closed during every create, sync, restore, or switch operation; Zstandard-compressed ZIP backups are created in Downloads before local bookmark or extension replacement.

Linux native packages expose the `helium` launcher on `PATH`. For an AppImage, extracted archive, or another nonstandard installation, set `HELIUM_SYNC_HELIUM_PATH` to the Helium executable before starting Helium Sync.
