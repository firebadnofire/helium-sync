[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ClientDirectory = Join-Path $RepoRoot 'crates\helium-sync-client'
$Artifact = Join-Path $RepoRoot 'target\debug\helium-sync-client.exe'

function Assert-Command {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required and was not found in PATH."
    }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter()][string[]]$CommandArguments = @()
    )

    & $Command @CommandArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $Command $($CommandArguments -join ' ')"
    }
}

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'This script must run on Windows.'
}

Assert-Command cargo
Assert-Command npm.cmd

Push-Location $ClientDirectory
try {
    Write-Host 'Installing locked frontend dependencies'
    Invoke-Checked -Command 'npm.cmd' -CommandArguments @('ci')

    Write-Host 'Building the Helium Sync Windows development executable'
    Invoke-Checked -Command 'npm.cmd' -CommandArguments @('run', 'tauri', '--', 'build', '--ci', '--debug', '--no-bundle')
}
finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) {
    throw "Build completed without the expected executable: $Artifact"
}

Write-Host "Built $Artifact"
