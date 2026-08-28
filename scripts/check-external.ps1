$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Report-Tool([string] $Name) {
    if (Get-Command $Name -ErrorAction SilentlyContinue) {
        Write-Host "READY: $Name"
    } else {
        Write-Host "SKIP: $Name is not installed"
    }
}

Report-Tool 'docker'
Report-Tool 'ssh'
Report-Tool 'sshd'
Report-Tool 'tshark'
Report-Tool 'tcpdump'
