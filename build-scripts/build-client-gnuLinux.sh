#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
client_dir="$repo_root/crates/helium-sync-client"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required and was not found in PATH."
}

[[ "$(uname -s)" == "Linux" ]] || fail "This script must run on Linux."
require_command cargo
require_command rustc
require_command npm
require_command pkg-config

host_target="$(rustc -vV | sed -n 's/^host: //p')"
target="${HELIUM_SYNC_LINUX_TARGET:-$host_target}"
[[ "$target" == *-linux-gnu* ]] || fail "Target '$target' is not a glibc Linux target. Set HELIUM_SYNC_LINUX_TARGET to a *-linux-gnu Rust target."
[[ "$target" == "$host_target" ]] || fail "Tauri Linux cross-compilation needs a target sysroot and linker. Run this script natively on '$target' instead."

if ! pkg-config --exists webkit2gtk-4.1; then
  fail "Tauri's WebKitGTK development files are missing. On Ubuntu/Debian install: libwebkit2gtk-4.1-dev build-essential curl wget file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev."
fi

printf 'Installing locked frontend dependencies\n'
cd "$client_dir"
npm ci

printf 'Building Helium Sync client for glibc target %s\n' "$target"
npm run tauri -- build --ci --no-bundle --target "$target"

artifact="$repo_root/target/$target/release/helium-sync-client"
[[ -x "$artifact" ]] || fail "Build completed without the expected executable: $artifact"
printf 'Built %s\n' "$artifact"
