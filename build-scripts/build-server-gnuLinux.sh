#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required and was not found in PATH."
}

require_command cargo
require_command rustc

host_target="$(rustc -vV | sed -n 's/^host: //p')"
target="${HELIUM_SYNC_LINUX_TARGET:-$host_target}"
[[ "$(uname -s)" == "Linux" ]] || fail "This script must run on Linux."
[[ "$target" == *-linux-gnu* ]] || fail "Target '$target' is not a glibc Linux target. Set HELIUM_SYNC_LINUX_TARGET to a *-linux-gnu Rust target."

if [[ "$target" != "$host_target" ]]; then
  command -v rustup >/dev/null 2>&1 || fail "Cross-target '$target' requires rustup and an appropriate cross linker."
  rustup target add "$target"
fi

printf 'Building helium-sync-server for glibc target %s\n' "$target"
cd "$repo_root"
cargo build --locked --release --package helium-sync-server --target "$target"

artifact="$repo_root/target/$target/release/helium-sync-server"
[[ -x "$artifact" ]] || fail "Build completed without the expected executable: $artifact"
printf 'Built %s\n' "$artifact"
