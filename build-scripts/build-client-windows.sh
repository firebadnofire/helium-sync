#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
client_dir="$repo_root/crates/helium-sync-client"
target="x86_64-pc-windows-msvc"
shim_dir="$repo_root/target/build-tools/windows-llvm/bin"
installer_dir="$repo_root/target/$target/release/bundle/nsis"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required and was not found in PATH."
}

find_llvm_tool() {
  local tool="$1"
  local candidate
  local search_root
  if command -v "$tool" >/dev/null 2>&1; then
    command -v "$tool"
    return 0
  fi
  for search_root in /usr/bin /usr/lib/llvm-*/bin; do
    [[ -d "$search_root" ]] || continue
    candidate="$(find "$search_root" -maxdepth 1 \( -type f -o -type l \) \
      \( -name "$tool" -o -name "$tool-[0-9]*" \) -print 2>/dev/null | sort -V | tail -n 1)"
    if [[ -n "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

install_ubuntu_dependencies() {
  [[ "${HELIUM_SYNC_INSTALL_DEPS:-0}" == "1" ]] || return 0
  printf 'Installing Ubuntu cross-compilation packages\n'
  if command -v sudo >/dev/null 2>&1; then
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ca-certificates clang clang-tools curl lld llvm libssl-dev nsis pkg-config
  else
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential ca-certificates clang clang-tools curl lld llvm libssl-dev nsis pkg-config
  fi
}

[[ "$(uname -s)" == "Linux" ]] || fail "This script must run on an Ubuntu Linux runner."
[[ -r /etc/os-release ]] || fail "Cannot identify the Linux distribution because /etc/os-release is missing."
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || fail "This script supports Ubuntu runners; detected '${ID:-unknown}'."

install_ubuntu_dependencies
require_command cargo
require_command rustup
require_command npm

if ! command -v cargo-xwin >/dev/null 2>&1; then
  if [[ "${HELIUM_SYNC_INSTALL_DEPS:-0}" == "1" ]]; then
    printf 'Installing cargo-xwin from its locked crate dependencies\n'
    cargo install --locked cargo-xwin
  else
    fail "cargo-xwin is required. Install it with 'cargo install --locked cargo-xwin' or rerun with HELIUM_SYNC_INSTALL_DEPS=1."
  fi
fi

mkdir -p "$shim_dir"
for tool in clang-cl lld-link llvm-lib llvm-rc; do
  tool_path="$(find_llvm_tool "$tool")" || fail "LLVM tool '$tool' is missing. Install Ubuntu packages clang, clang-tools, lld, and llvm."
  ln -sfn "$tool_path" "$shim_dir/$tool"
done
export PATH="$shim_dir:$PATH"

export CC_x86_64_pc_windows_msvc="clang-cl"
export CXX_x86_64_pc_windows_msvc="clang-cl"
export AR_x86_64_pc_windows_msvc="llvm-lib"
export RC_x86_64_pc_windows_msvc="llvm-rc"
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="lld-link"

rustup target add "$target"

printf 'Installing locked frontend dependencies\n'
cd "$client_dir"
npm ci

mkdir -p "$installer_dir"
find "$installer_dir" -maxdepth 1 -type f -name '*-setup.exe' -delete
printf 'Cross-compiling Helium Sync client for %s\n' "$target"
npm run tauri -- build --ci --bundles nsis --runner cargo-xwin --target "$target"

artifact="$repo_root/target/$target/release/helium-sync-client.exe"
[[ -f "$artifact" ]] || fail "Build completed without the expected executable: $artifact"
shopt -s nullglob
installers=("$installer_dir"/*-setup.exe)
shopt -u nullglob
[[ "${#installers[@]}" -eq 1 ]] || fail "Build completed with ${#installers[@]} NSIS installers; expected exactly one in $installer_dir."
printf 'Built portable executable %s\n' "$artifact"
printf 'Built NSIS installer %s\n' "${installers[0]}"
