$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = Split-Path -Parent $PSScriptRoot
Push-Location $repository
try {
    cargo fmt --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace
    cargo build --workspace

    Push-Location 'crates/helium-sync-client'
    try {
        npm ci
        npm run build
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
