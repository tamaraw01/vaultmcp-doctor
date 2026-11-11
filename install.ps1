param(
    [string]$VaultPath = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3.10+ is required on PATH."
    exit 2
}

$env:PYTHONPATH = Join-Path $RootDir "src"
& python -m vaultmcp_doctor --vault $VaultPath
exit $LASTEXITCODE
