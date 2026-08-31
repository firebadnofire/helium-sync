# Helium Sync Operator Guide

This guide takes a new operator from an empty machine to a working Helium Sync
server and desktop client. It also covers verification, routine operation,
upgrades, backup, restore, rollback, and the failures most likely to occur.

Helium Sync provides encrypted multi-device bookmark synchronization while the
desktop client is open and signed in. It does not yet synchronize open tabs,
history, passwords, extensions, or browser preferences.

## Contents

1. [Architecture and deployment choice](#1-architecture-and-deployment-choice)
2. [Download the source](#2-download-the-source)
3. [Install build prerequisites](#3-install-build-prerequisites)
4. [Build and validate the source](#4-build-and-validate-the-source)
5. [Recommended Linux systemd server](#5-recommended-linux-systemd-server)
6. [Optional Docker server](#6-optional-docker-server)
7. [Build the desktop client](#7-build-the-desktop-client)
8. [Configure the client](#8-configure-the-client)
9. [First connection and recovery code](#9-first-connection-and-recovery-code)
10. [Routine operations](#10-routine-operations)
11. [Backup and restore](#11-backup-and-restore)
12. [Upgrade and rollback](#12-upgrade-and-rollback)
13. [Token and certificate rotation](#13-token-and-certificate-rotation)
14. [Troubleshooting](#14-troubleshooting)
15. [Security checklist](#15-security-checklist)

## 1. Architecture and deployment choice

The desktop client encrypts bookmark data locally. The Linux server stores
opaque ciphertext in SQLite and cannot decrypt it without a client recovery
code.

The server exposes the same authenticated API through:

- TLS 1.3 HTTPS on TCP port `7500` by default.
- Plain HTTP inside the local Unix socket `/run/helium-sync/server.sock`. This
  socket is intended for SSH `direct-streamlocal` forwarding; it is not exposed
  as plaintext TCP.

Protocol v1 uses one bearer token for the whole self-hosted installation.

### Choose exactly one server deployment

Do not run Docker and systemd Helium Sync servers on the same host. They have
independent databases, token sources, certificates, and socket locations. A
Docker token used with a systemd-owned Unix socket will be rejected even when
SSH authentication succeeds.

| Requirement | Recommended deployment |
| --- | --- |
| HTTPS and SSH through `/run/helium-sync/server.sock` | systemd |
| Standard Linux service management and host backups | systemd |
| Container-only evaluation over HTTPS | Docker Compose |
| Host SSH access to a Docker socket | Advanced custom bind mount; not provided by the default Compose file |

For a first real installation, use the systemd path in this guide.

## 2. Download the source

Install Git and clone the requested repository:

```sh
git clone https://github.com/firebadnofire/helium-sync.git
cd helium-sync
```

If the repository is private, authenticate first or use an SSH clone:

```sh
gh auth login
gh repo clone firebadnofire/helium-sync
cd helium-sync
```

or:

```sh
git clone git@github.com:firebadnofire/helium-sync.git
cd helium-sync
```

A GitHub `404` can mean the repository is private or has not been published at
that path. Confirm the URL and the signed-in GitHub account before using a
mirror or an untrusted archive.

Record the exact source revision used for the installation:

```sh
git status --short
git log -1 --oneline
git rev-parse HEAD
```

The checkout should be clean before an operator build. Prefer a reviewed
release tag when one is available. Otherwise record the reviewed commit from
`main`.

## 3. Install build prerequisites

### Common server requirements

- 64-bit glibc Linux for the supplied GNU/Linux build script.
- Rust `1.94` or newer with Cargo.
- Git, a C/C++ build toolchain, `pkg-config`, CA certificates, OpenSSL CLI, and
  SQLite CLI.
- At least 2 GiB free memory and several GiB of build/storage space.
- systemd and OpenSSH server for the recommended deployment.

Example for Ubuntu or Debian:

```sh
sudo apt-get update
sudo apt-get install -y \
  build-essential ca-certificates curl file git openssl pkg-config sqlite3
```

Example for openSUSE:

```sh
sudo zypper --non-interactive install \
  ca-certificates curl file gcc gcc-c++ git make openssl pkg-config sqlite3
```

Install Rust through the distribution package manager or `rustup`. If using
`rustup`, review the installer at <https://rustup.rs/> before running it:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
sh /tmp/rustup-init.sh
rm -f /tmp/rustup-init.sh
. "$HOME/.cargo/env"
rustc --version
cargo --version
```

### Desktop client requirements

All client builds require Rust, Node.js 24 or a current supported LTS release,
and npm.

Install Node.js from <https://nodejs.org/en/download> or a maintained operating
system package, then verify the tools selected by the build:

```sh
node --version
npm --version
```

Windows additionally requires:

- Microsoft C++ Build Tools with the Desktop development with C++ workload.
- WebView2 Runtime.
- Windows 10 or newer.

See the official [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/).

macOS additionally requires Xcode Command Line Tools:

```sh
xcode-select --install
```

Ubuntu/Debian glibc Linux client builds require WebKitGTK and Tauri packages:

```sh
sudo apt-get update
sudo apt-get install -y \
  build-essential curl file libayatana-appindicator3-dev libssl-dev \
  librsvg2-dev libwebkit2gtk-4.1-dev libxdo-dev pkg-config wget
```

## 4. Build and validate the source

The lockfiles are committed. Keep `--locked` behavior and do not update
dependencies during an operator build.

Run the full repository check on Linux or macOS:

```sh
sh scripts/check.sh
```

On Windows PowerShell:

```powershell
& .\scripts\check.ps1
```

These checks run formatting, Clippy with warnings denied, workspace tests,
workspace build, a clean frontend dependency install, TypeScript checking, and
the frontend production build. Stop and diagnose any failure before installing
artifacts.

Build the release Linux server:

```sh
bash build-scripts/build-server-gnuLinux.sh
```

Find the artifact without guessing the Rust host triple:

```sh
rust_target=$(rustc -vV | sed -n 's/^host: //p')
server_artifact="target/${rust_target}/release/helium-sync-server"
test -x "$server_artifact"
file "$server_artifact"
```

The server runtime is Linux-only.

## 5. Recommended Linux systemd server

The commands in this section are designed to preserve existing secrets and
data. Read each command before running it and replace the example host values.

### 5.1 Stop any competing deployment

Check port and container ownership:

```sh
sudo ss -ltnp 'sport = :7500'
sudo ss -lxnp | grep /run/helium-sync/server.sock || true
sudo docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -i helium || true
```

If a Docker Helium Sync container is running, stop it without deleting its
volumes before installing systemd:

```sh
sudo docker compose --env-file docker/.env -f docker/compose.yml stop helium-sync-server
```

Do not use `docker compose down -v`; `-v` deletes persistent volumes.

### 5.2 Create the service account

```sh
if ! getent group helium-sync >/dev/null; then
  sudo groupadd --system helium-sync
fi

if ! id helium-sync >/dev/null 2>&1; then
  sudo useradd --system \
    --gid helium-sync \
    --home-dir /var/lib/helium-sync \
    --shell /usr/sbin/nologin \
    helium-sync
fi

sudo install -d -o helium-sync -g helium-sync -m 0750 /var/lib/helium-sync
sudo install -d -o root -g helium-sync -m 0750 /etc/helium-sync
sudo install -d -o helium-sync -g helium-sync -m 0750 /etc/helium-sync/tls
```

### 5.3 Install the binary and configuration

Using `server_artifact` from the build section:

```sh
rust_target=$(rustc -vV | sed -n 's/^host: //p')
server_artifact="target/${rust_target}/release/helium-sync-server"
test -x "$server_artifact"

sudo install -m 0755 -o root -g root \
  "$server_artifact" /usr/local/bin/helium-sync-server

sudo install -m 0640 -o root -g helium-sync \
  config/server.example.toml /etc/helium-sync/server.toml
```

Review `/etc/helium-sync/server.toml`. At minimum, verify:

```toml
[server]
listen = "0.0.0.0:7500"
unix_socket = "/run/helium-sync/server.sock"
unix_socket_mode = "0660"
unix_socket_group = "helium-sync"
data_dir = "/var/lib/helium-sync"

[tls]
certificate = "/etc/helium-sync/tls/server.crt"
private_key = "/etc/helium-sync/tls/server.key"

[storage]
database = "/var/lib/helium-sync/server.sqlite3"
```

### 5.4 Create the bearer token

Do not place the token in a command-line argument, Git, shell history, or chat.
The token must be at least 32 characters. The following creates a 256-bit token
only when the target does not already exist:

```sh
if ! sudo test -e /etc/helium-sync/token; then
  token_tmp=$(mktemp /tmp/helium-sync-token.XXXXXX)
  umask 077
  openssl rand -hex 32 >"$token_tmp"
  sudo install -m 0400 -o helium-sync -g helium-sync \
    "$token_tmp" /etc/helium-sync/token
  rm -f "$token_tmp"
else
  echo 'Keeping existing /etc/helium-sync/token'
fi
```

Every client for this installation must use the exact contents of this file.
Do not substitute `docker/.env` unless Docker is the authoritative server.

### 5.5 Install TLS material

Production installations should use a certificate issued by a trusted public
or private CA. It must be currently valid, match its private key, and contain
every DNS name or IP address clients use. Install the full certificate chain
and key:

```sh
sudo install -m 0444 -o root -g root /secure/source/server.crt \
  /etc/helium-sync/tls/server.crt
sudo install -m 0400 -o helium-sync -g helium-sync /secure/source/server.key \
  /etc/helium-sync/tls/server.key
```

For a LAN bootstrap only, the server can generate an explicitly insecure
self-signed certificate. Set the real values first:

```sh
export HELIUM_SYNC_SERVER_NAME='sync.example.lan'
export HELIUM_SYNC_SERVER_IP='192.0.2.10'

sudo -u helium-sync /usr/local/bin/helium-sync-server generate-dev-cert \
  --output-dir /etc/helium-sync/tls \
  --hostname localhost \
  --hostname "$HELIUM_SYNC_SERVER_NAME" \
  --hostname "$HELIUM_SYNC_SERVER_IP"

sudo chmod 0444 /etc/helium-sync/tls/server.crt
sudo chmod 0400 /etc/helium-sync/tls/server.key
```

The generator preserves an existing complete pair and refuses to replace a
partial pair. Never expose this development certificate to the public
Internet. Copy `server.crt`, never `server.key`, to clients that use Custom CA
trust.

Inspect the certificate without exposing the key:

```sh
openssl x509 -in /etc/helium-sync/tls/server.crt \
  -noout -subject -issuer -dates -ext subjectAltName
```

### 5.6 Validate before startup

Run validation as the service account with the same files used in production:

```sh
sudo -u helium-sync /usr/local/bin/helium-sync-server check \
  --config /etc/helium-sync/server.toml \
  --token-file /etc/helium-sync/token
```

This validates token strength, writable paths, certificate dates and PEM,
certificate/key consistency, configuration, and database migrations. It must
pass before installation continues.

### 5.7 Install and start the unit

```sh
sudo install -m 0644 -o root -g root \
  contrib/systemd/helium-sync-server.service \
  /etc/systemd/system/helium-sync-server.service

sudo systemctl daemon-reload
sudo systemctl enable --now helium-sync-server
```

Check status and logs:

```sh
systemctl status helium-sync-server --no-pager
sudo journalctl -u helium-sync-server -n 100 --no-pager
```

Logs must not contain the bearer token, private key, recovery code, plaintext
bookmarks, or ciphertext bodies.

### 5.8 Verify one process owns both listeners

```sh
systemctl show helium-sync-server -p MainPID
sudo ss -ltnp 'sport = :7500'
sudo ss -lxnp | grep /run/helium-sync/server.sock
sudo stat -c 'type=%F mode=%a owner=%U group=%G' \
  /run/helium-sync/server.sock
```

Expected results:

- One systemd PID owns TCP 7500 and the Unix socket.
- The socket is a socket, not a regular file.
- The socket mode is `660` and group is `helium-sync`.

If different processes own the two listeners, stop immediately and follow the
split-deployment troubleshooting section below.

Run the authenticated binary health check. Use a URL whose hostname is in the
certificate SAN list:

```sh
sudo -u helium-sync /usr/local/bin/helium-sync-server healthcheck \
  --config /etc/helium-sync/server.toml \
  --token-file /etc/helium-sync/token \
  --url 'https://sync.example.lan:7500/v1/status'
```

### 5.9 Firewall

Open only the transports clients need. SSH normally uses TCP 22. HTTPS uses
TCP 7500 unless remapped.

For firewalld:

```sh
sudo firewall-cmd --permanent --add-port=7500/tcp
sudo firewall-cmd --reload
```

For UFW:

```sh
sudo ufw allow 7500/tcp
```

Restrict the rule to the trusted LAN or VPN when possible. If all clients use
SSH, do not expose TCP 7500 beyond localhost or the host firewall.

### 5.10 Permit the SSH login user to reach the socket

Add only the intended SSH account to the socket group:

```sh
sudo usermod -aG helium-sync operator
```

Replace `operator` with the actual SSH username. End every session for that
user and sign in again; existing sessions do not gain new supplementary groups.
Then verify:

```sh
id operator
sudo -u operator test -r /run/helium-sync/server.sock
sudo -u operator test -w /run/helium-sync/server.sock
```

Confirm OpenSSH permits stream-local forwarding:

```sh
sudo sshd -T | grep '^allowstreamlocalforwarding '
```

The expected value is `yes`. If it is disabled, set
`AllowStreamLocalForwarding yes` in the applicable `sshd_config` or drop-in,
run `sudo sshd -t`, then reload SSH. Never weaken host-key or public-key
authentication to solve a socket problem.

Record the server host-key fingerprint over a trusted administrative channel:

```sh
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

## 6. Optional Docker server

Docker is a separate alternative deployment. Stop and disable the systemd
server before starting Compose:

```sh
sudo systemctl disable --now helium-sync-server
```

Install Docker Engine with Compose v2, then verify:

```sh
docker version
docker compose version
```

Create `docker/.env` without overwriting an existing token:

```sh
if ! test -e docker/.env; then
  umask 077
  {
    printf 'HELIUM_SYNC_TOKEN='
    openssl rand -hex 32
    printf 'HELIUM_SYNC_PORT=7500\n'
  } >docker/.env
else
  echo 'Keeping existing docker/.env'
fi
```

Build and start:

```sh
bash build-scripts/build-server-docker.sh
docker compose --env-file docker/.env -f docker/compose.yml up -d
docker compose --env-file docker/.env -f docker/compose.yml ps
```

The default Compose configuration:

- Runs as unprivileged UID/GID 65532.
- Uses a read-only root filesystem and drops all capabilities.
- Persists data in `docker_helium-sync-data`.
- Keeps the Unix socket in a Docker named volume. The host path
  `/run/helium-sync/server.sock` is therefore not the Docker socket.
- Uses an explicitly insecure development certificate valid only for
  `localhost`, `127.0.0.1`, and `helium-sync-server`.

Because normal hostname validation is mandatory, a remote client connecting to
the server's LAN IP will reject that default certificate. For remote use,
mount certificate/key material containing the actual DNS name or IP, update
`HELIUM_SYNC_TLS_CERTIFICATE` and `HELIUM_SYNC_TLS_PRIVATE_KEY`, and ensure the
container health URL uses a SAN hostname. Use `:Z` private relabeling on bind
mounts when SELinux is enforcing.

Check container health and logs:

```sh
container_id=$(docker compose --env-file docker/.env -f docker/compose.yml \
  ps -q helium-sync-server)
docker inspect --format '{{.State.Health.Status}}' "$container_id"
docker logs --tail 100 "$container_id"
```

The default named runtime volume is suitable for HTTPS or another container.
For host SSH access, use the systemd deployment unless you deliberately design
a host bind mount with mode `0660`, compatible numeric group ownership,
SELinux labeling, and SSH-user membership. Never make the socket
world-writable.

Do not take the token from `docker/.env` and use it with a socket owned by a
systemd service.

## 7. Build the desktop client

### Windows native development build

Open PowerShell in the repository root:

```powershell
& .\build-scripts\build-client-windows.ps1
```

Artifact:

```text
target\debug\helium-sync-client.exe
```

Start it with:

```powershell
& .\target\debug\helium-sync-client.exe
```

This is a development executable, not a signed installer.

### GNU/Linux glibc client

Run on the target Linux architecture after installing WebKitGTK prerequisites:

```sh
bash build-scripts/build-client-gnuLinux.sh
```

Artifact:

```sh
rust_target=$(rustc -vV | sed -n 's/^host: //p')
printf '%s\n' "target/${rust_target}/release/helium-sync-client"
```

Linux production secret storage requires a working Secret Service provider and
an unlocked user session, such as GNOME Keyring or another compatible desktop
keyring. The client intentionally has no plaintext secret fallback.

### macOS client

Run on macOS:

```sh
bash build-scripts/build-client-mac.sh
```

Set `HELIUM_SYNC_MAC_TARGET` to `aarch64-apple-darwin`,
`x86_64-apple-darwin`, or `universal-apple-darwin` when needed.

### Windows cross-build from Ubuntu

The cross-build script supports Ubuntu runners only and uses `cargo-xwin`:

```sh
HELIUM_SYNC_INSTALL_DEPS=1 bash build-scripts/build-client-windows.sh
```

Portable executable:

```text
target/x86_64-pc-windows-msvc/release/helium-sync-client.exe
```

NSIS installer:

```text
target/x86_64-pc-windows-msvc/release/bundle/nsis/*-setup.exe
```

Cross-building does not replace testing on a real Windows machine with
WebView2.

## 8. Configure the client

The server bearer token, client recovery code, and SSH-key passphrase are
different secrets. Do not interchange them.

### Obtain connection material safely

For a private/self-signed CA, transfer only the public certificate to the
client. For example on Linux or macOS:

```sh
scp operator@sync.example.lan:/etc/helium-sync/tls/server.crt \
  ./helium-sync-server.crt
```

On Windows PowerShell with the OpenSSH client:

```powershell
scp operator@sync.example.lan:/etc/helium-sync/tls/server.crt `
  "$env:USERPROFILE\Downloads\helium-sync-server.crt"
```

Never transfer `server.key` to a client.

Move the bearer token from the protected server file into a trusted password
manager or directly into the client on a private administrative console. If it
must be displayed, use `sudo cat /etc/helium-sync/token` only in a trusted
terminal and clear protected clipboard/terminal history afterward. Do not put
the token in a URL, shell command argument, screenshot, or support log.

### HTTPS connection

Enter:

- Server URL: `https://sync.example.lan:7500` using a hostname or IP present in
  the certificate SAN list.
- Trust mode:
  - **System trust** for a normal trusted CA.
  - **Custom CA** for a private CA or the generated self-signed `server.crt`.
  - **Pinned certificate/SPKI** only after independently verifying the pin.
- API token: the exact authoritative server token.
- Device name: a recognizable unique name.

The client rejects `http://`, invalid/expired certificates, wrong hostnames,
untrusted chains, and bad pins. Do not disable validation.

### SSH connection

Enter:

- SSH host: the server DNS name or IP.
- SSH port: normally `22`.
- Username: the account added to the `helium-sync` socket group.
- Private key: OpenSSH, PEM, or PuTTY `.ppk` v2/v3.
- Passphrase: only if the private key is encrypted.
- Remote socket: `/run/helium-sync/server.sock` for systemd.
- API token: `/etc/helium-sync/token` from the same systemd installation.
- Confirmed host-key fingerprint: only after comparing it with the trusted
  `ssh-keygen -lf` output.
- Device name: a recognizable unique name.

An SSH login can succeed while the API token fails. A message saying the
Helium Sync API token was rejected means the SSH key and socket connection got
far enough to receive an authenticated HTTP rejection; verify the server token
source rather than changing host-key policy.

## 9. First connection and recovery code

Use this sequence:

1. Connect and review every diagnostic stage.
2. Select a readable Helium profile and choose **Use at sign-in**.
3. Reveal the `hsync1:` recovery code from the security and recovery section.
4. Store the recovery code offline in a password manager or another protected
   backup. Do not store it on the server.
5. Choose **Sync now**, or leave **Automatic** enabled for 30-second checks
   while the desktop client remains open and signed in.
6. On every additional trusted device, import the exact recovery code before
   signing in. The client discovers the encrypted server object for a matching
   profile-directory name and reconciles it with local bookmarks.

The first client creates a random 256-bit master key. The recovery code is the
only supported way to put the same master key on another trusted client. A
server database backup cannot decrypt data without it.

Local changes can upload while Helium is open. Close Helium before a device
needs to apply server changes locally. The client refuses to replace the
`Bookmarks` file while the installed Helium executable is running and creates
a Zstandard-compressed ZIP backup in Downloads before every replacement.

## 10. Routine operations

### systemd health

```sh
systemctl is-active helium-sync-server
systemctl is-enabled helium-sync-server
sudo journalctl -u helium-sync-server --since today --no-pager
sudo ss -ltnp 'sport = :7500'
sudo ss -lxnp | grep /run/helium-sync/server.sock
```

Run the authenticated health check after certificate, token, configuration, or
binary changes:

```sh
sudo -u helium-sync /usr/local/bin/helium-sync-server healthcheck \
  --config /etc/helium-sync/server.toml \
  --token-file /etc/helium-sync/token \
  --url 'https://sync.example.lan:7500/v1/status'
```

### Capacity

```sh
sudo du -h /var/lib/helium-sync/server.sqlite3
df -h /var/lib/helium-sync
sudo sqlite3 /var/lib/helium-sync/server.sqlite3 'PRAGMA integrity_check;'
```

`PRAGMA integrity_check` can be resource-intensive on a large database; run it
during a maintenance window.

### Graceful restart

```sh
sudo -u helium-sync /usr/local/bin/helium-sync-server check \
  --config /etc/helium-sync/server.toml \
  --token-file /etc/helium-sync/token
sudo systemctl restart helium-sync-server
```

The server handles SIGTERM and Ctrl-C gracefully and removes only the Unix
socket it created.

## 11. Backup and restore

### What must be backed up

- `/var/lib/helium-sync/server.sqlite3`: encrypted objects and sync metadata.
- `/etc/helium-sync/server.toml`: server configuration.
- `/etc/helium-sync/token`: bearer token, through protected secret backup.
- `/etc/helium-sync/tls`: certificate and private key, through protected secret
  backup.
- Every client's `hsync1:` recovery code, stored separately from the server.

### Online SQLite backup

Create the destination on encrypted or otherwise protected storage:

```sh
sudo install -d -m 0700 /secure-backup/helium-sync
sudo sqlite3 /var/lib/helium-sync/server.sqlite3 \
  ".backup '/secure-backup/helium-sync/server.sqlite3'"
sudo chmod 0600 /secure-backup/helium-sync/server.sqlite3
```

Do not back up a live SQLite database with a plain file copy while WAL is
active. Use SQLite's online backup command or stop the service first.

### Restore

1. Verify the backup and available disk space.
2. Stop Helium Sync.
3. Preserve the current database as a rollback copy.
4. Remove no data until the restored service and client round trip pass.

```sh
sudo systemctl stop helium-sync-server

restore_stamp=$(date -u +%Y%m%dT%H%M%SZ)
sudo cp --preserve=all /var/lib/helium-sync/server.sqlite3 \
  "/var/lib/helium-sync/server.sqlite3.pre-restore-${restore_stamp}"

sudo install -m 0600 -o helium-sync -g helium-sync \
  /secure-backup/helium-sync/server.sqlite3 \
  /var/lib/helium-sync/server.sqlite3

sudo rm -f /var/lib/helium-sync/server.sqlite3-wal \
  /var/lib/helium-sync/server.sqlite3-shm

sudo -u helium-sync /usr/local/bin/helium-sync-server check \
  --config /etc/helium-sync/server.toml \
  --token-file /etc/helium-sync/token
sudo systemctl start helium-sync-server
```

Then run the binary health check and a client synthetic round trip. Keep the
pre-restore database until the restored system has been verified.

For Docker, back up `docker_helium-sync-data` through a controlled helper
container or stop Compose and back up the volume directory using the host's
documented Docker backup process. Never delete the volume as part of an
upgrade.

## 12. Upgrade and rollback

### systemd upgrade

Do not build over an unreviewed dirty checkout:

```sh
git status --short
git fetch --tags origin
git log --oneline --decorate -10
```

Check out the reviewed release or commit, run the full checks, and build the
new binary before stopping the service.

```sh
sh scripts/check.sh
bash build-scripts/build-server-gnuLinux.sh
rust_target=$(rustc -vV | sed -n 's/^host: //p')
new_server="target/${rust_target}/release/helium-sync-server"
```

Validate and install with rollback preserved:

```sh
sudo -u helium-sync "$new_server" check \
  --config /etc/helium-sync/server.toml \
  --token-file /etc/helium-sync/token

upgrade_stamp=$(date -u +%Y%m%dT%H%M%SZ)
sudo cp --preserve=all /usr/local/bin/helium-sync-server \
  "/usr/local/bin/helium-sync-server.pre-upgrade-${upgrade_stamp}"

sudo install -m 0755 -o root -g root "$new_server" \
  /usr/local/bin/helium-sync-server.next
sudo mv -f /usr/local/bin/helium-sync-server.next \
  /usr/local/bin/helium-sync-server
sudo systemctl restart helium-sync-server
```

Verify the health check, both listener owners, logs, and a client synthetic
round trip.

To roll back, stop the service, atomically restore the preserved binary, and
restart. If the release changed the database schema, restore the matching
pre-upgrade database backup as well; do not assume binary-only rollback is
safe across migrations.

### Docker upgrade

Back up the data volume first, then:

```sh
docker compose --env-file docker/.env -f docker/compose.yml build --pull
docker compose --env-file docker/.env -f docker/compose.yml up -d
docker compose --env-file docker/.env -f docker/compose.yml ps
```

Keep the prior image tag until health and client checks pass.

## 13. Token and certificate rotation

### Rotate the bearer token

Rotation disconnects every client until it receives the new token.

```sh
token_tmp=$(mktemp /tmp/helium-sync-token.XXXXXX)
umask 077
openssl rand -hex 32 >"$token_tmp"

rotate_stamp=$(date -u +%Y%m%dT%H%M%SZ)
sudo cp --preserve=all /etc/helium-sync/token \
  "/etc/helium-sync/token.pre-rotation-${rotate_stamp}"
sudo install -m 0400 -o helium-sync -g helium-sync \
  "$token_tmp" /etc/helium-sync/token.next
rm -f "$token_tmp"
sudo mv -f /etc/helium-sync/token.next /etc/helium-sync/token

sudo -u helium-sync /usr/local/bin/helium-sync-server check \
  --config /etc/helium-sync/server.toml \
  --token-file /etc/helium-sync/token
sudo systemctl restart helium-sync-server
```

Update every client through its normal secret-storage form. Do not send tokens
through public chat, issue trackers, or command-line arguments.

### Rotate TLS material

Install the new certificate/key pair to temporary paths, run `check` against a
temporary config or after an atomic file replacement, then restart. Confirm:

- The certificate and key match.
- The certificate is currently valid.
- Every client DNS name or IP is in the SAN list.
- The issuer is trusted by the selected client mode.
- TLS 1.3 health succeeds after restart.

Never solve renewal problems by disabling certificate validation.

## 14. Troubleshooting

### API token rejected after SSH succeeds

This normally means transport authentication worked but the bearer token did
not match the process serving the socket.

Without printing either token, identify ownership:

```sh
sudo ss -lxnp | grep /run/helium-sync/server.sock
systemctl show helium-sync-server -p MainPID
sudo docker ps --format '{{.Names}} {{.Ports}}' | grep -i helium || true
```

For systemd, use `/etc/helium-sync/token`. For Compose, use
`HELIUM_SYNC_TOKEN` from `docker/.env`. Never mix them.

### TCP and Unix socket have different owners

Two deployments are running. Preserve both databases, then choose one:

```sh
sudo ss -ltnp 'sport = :7500'
sudo ss -lxnp | grep /run/helium-sync/server.sock
```

For the recommended systemd choice, stop Compose without deleting volumes,
validate `/etc/helium-sync/token`, and restart systemd. One PID must then own
both listeners.

### Unknown SSH host key

Compare the fingerprint shown by the client with:

```sh
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Confirm only over a trusted channel. A changed key fails closed and requires an
investigation; deleting known-host data is not an explanation.

### SSH authentication failed

- Confirm the username, port, and private-key path.
- Confirm the public key is in the intended account's `authorized_keys`.
- Confirm the `.ppk` passphrase if encrypted.
- Inspect SSH server logs without exposing the private key.

### Remote Unix socket unavailable

```sh
sudo stat /run/helium-sync/server.sock
id operator
sudo sshd -T | grep '^allowstreamlocalforwarding '
systemctl status helium-sync-server --no-pager
```

The SSH user must be in the socket group and must start a new login session
after group membership changes.

### HTTPS certificate rejected

```sh
openssl x509 -in /etc/helium-sync/tls/server.crt \
  -noout -subject -issuer -dates -ext subjectAltName
sudo -u helium-sync /usr/local/bin/helium-sync-server check \
  --config /etc/helium-sync/server.toml \
  --token-file /etc/helium-sync/token
```

Use a URL matching a SAN entry and the correct CA or pin. Do not select an
insecure-ignore option; none is provided intentionally.

### Server will not start

```sh
sudo -u helium-sync /usr/local/bin/helium-sync-server check \
  --config /etc/helium-sync/server.toml \
  --token-file /etc/helium-sync/token
sudo journalctl -u helium-sync-server -n 200 --no-pager
sudo ss -ltnp 'sport = :7500'
sudo ls -ld /var/lib/helium-sync /run/helium-sync /etc/helium-sync
```

Correct configuration, ownership, occupied ports, certificate, token, disk
space, or migration errors. Do not delete the database to make startup pass.

### Bookmarks unavailable or busy

- Verify Helium is installed and its `Local State` lists the profile.
- Bookmark synchronization reads and may guardedly replace only the `Bookmarks`
  JSON file.
- If metadata changes during the read, pause bookmark edits or close Helium and
  retry.
- Never copy or edit the live browser SQLite/LevelDB stores as a workaround.

### Docker SELinux permission denied

Use a private `:Z` relabel on intended bind mounts, verify numeric UID/GID
compatibility, and keep secrets mode `0400`. Do not make token, private key, or
socket files world-readable/writable.

### Collect safe diagnostics

Useful outputs:

```sh
git rev-parse HEAD
rustc --version
/usr/local/bin/helium-sync-server --version
systemctl status helium-sync-server --no-pager
sudo journalctl -u helium-sync-server -n 200 --no-pager
sudo ss -ltnp 'sport = :7500'
sudo ss -lxnp | grep /run/helium-sync/server.sock
```

Before sharing diagnostics, remove tokens, Authorization headers, private
keys, recovery codes, bookmark contents, and sensitive filesystem paths.

## 15. Security checklist

- [ ] Exactly one Helium Sync server deployment runs on the host.
- [ ] One PID owns both HTTPS and the Unix socket.
- [ ] TLS 1.3 certificate validation succeeds for the actual client hostname.
- [ ] No plaintext TCP listener exists.
- [ ] The bearer token is random, 32+ characters, mode `0400`, and absent from
      Git, shell arguments, and logs.
- [ ] The TLS private key is mode `0400` and never copied to clients.
- [ ] The Unix socket is mode `0660` with a dedicated group.
- [ ] Only intended SSH users belong to the socket group.
- [ ] The SSH host-key fingerprint was verified independently.
- [ ] Firewall exposure is limited to trusted networks and required ports.
- [ ] The server database, token, and TLS keys have protected backups.
- [ ] Every client recovery code has a separate protected offline backup.
- [ ] An encrypted bookmark round trip passes after every deployment change.
- [ ] Helium is closed before applying server bookmark changes locally.
- [ ] Zstandard backup archives are created before local bookmark replacement.

Additional focused documentation is available under [`docs/`](docs/),
including [TLS](docs/tls.md), [SSH](docs/ssh.md),
[configuration](docs/configuration.md), [security](docs/security-model.md), and
[protocol](docs/protocol.md).
