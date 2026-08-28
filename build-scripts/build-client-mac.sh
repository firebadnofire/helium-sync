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

[[ "$(uname -s)" == "Darwin" ]] || fail "This script must run on macOS."
require_command cargo
require_command rustc
require_command rustup
require_command npm
require_command xcode-select
xcode-select -p >/dev/null 2>&1 || fail "Xcode Command Line Tools are required. Install them with: xcode-select --install"

host_target="$(rustc -vV | sed -n 's/^host: //p')"
target="${HELIUM_SYNC_MAC_TARGET:-$host_target}"
case "$target" in
  universal-apple-darwin)
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    ;;
  aarch64-apple-darwin|x86_64-apple-darwin)
    rustup target add "$target"
    ;;
  *)
    fail "Unsupported macOS target '$target'. Use aarch64-apple-darwin, x86_64-apple-darwin, or universal-apple-darwin."
    ;;
esac

printf 'Installing locked frontend dependencies\n'
cd "$client_dir"
npm ci

printf 'Building Helium Sync client for macOS target %s\n' "$target"
npm run tauri -- build --ci --no-bundle --target "$target"

artifact="$repo_root/target/$target/release/helium-sync-client"
[[ -x "$artifact" ]] || fail "Build completed without the expected executable: $artifact"
printf 'Built %s\n' "$artifact"
