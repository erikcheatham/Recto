# One-shot state migration: host directory -> Docker named volume.
#
# PowerShell port of migrate-state.sh, for Windows operators.
# Copies an existing host-mode bootloader's state directory
# (typically C:\Users\<operator>\.recto\bootloader\) into a Docker
# named volume, preserving operator pubkey + paired phones + pending
# capability requests + vault_root.json + master_identity.json + all
# other state files atomically.
#
# Used during the Blue-Green cutover from launcher-supervised
# bootloader to docker-supervised bootloader.
#
# Usage:
#   .\migrate-state.ps1 -SourcePath <path> -VolumeName <name>
#
# Example (typical Windows host):
#   .\migrate-state.ps1 `
#       -SourcePath "C:\Users\<username>\.recto\bootloader" `
#       -VolumeName "myapp_bootloader-data"
#
# Idempotency: re-running on a populated volume is SAFE (existing
# content preserved via cp -n semantics).
#
# Safety: source directory is mounted read-only; migration never
# modifies the host-mode state. Rollback to host-mode bootloader
# stays available throughout.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Source host directory containing existing bootloader state")]
    [string]$SourcePath,

    [Parameter(Mandatory = $true, HelpMessage = "Docker named volume to seed (e.g. 'myapp_bootloader-data')")]
    [string]$VolumeName
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false  # G-001: native stderr (docker progress) isn't a terminating error

function Write-Step {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "      WARNING: $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "ERROR: $Message" -ForegroundColor Red
}

# Pre-flight checks.

if (-not (Test-Path -Path $SourcePath -PathType Container)) {
    Write-Err "source path $SourcePath does not exist or is not a directory."
    exit 1
}

$sourceItems = Get-ChildItem -Path $SourcePath -Force -ErrorAction SilentlyContinue
if (-not $sourceItems) {
    Write-Err "source path $SourcePath is empty. Nothing to migrate."
    Write-Host "If you intended a fresh start, just start the bootloader container without migration." -ForegroundColor Yellow
    exit 1
}

try {
    $null = & docker --version 2>&1
}
catch {
    Write-Err "docker CLI not found in PATH."
    exit 1
}

try {
    $null = & docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "docker daemon unreachable"
    }
}
catch {
    Write-Err "docker daemon not reachable. Is Docker Desktop running?"
    exit 1
}

# Convert Windows path to Docker-compatible form. Docker Desktop on
# Windows accepts native Windows paths in -v mounts and translates
# them under the hood, but normalizing forward-slashes avoids
# variant-quoting bugs in different shells.
$normalizedSource = $SourcePath -replace '\\', '/'

# Ensure the destination volume exists. `docker volume create` is
# idempotent.
Write-Step "1/4" "Ensuring Docker volume $VolumeName exists..."
& docker volume create $VolumeName | Out-Null

# Inspect the volume for the operator's diagnostic comfort.
Write-Step "2/4" "Volume inspection:"
$inspect = & docker volume inspect $VolumeName | ConvertFrom-Json
Write-Host ("      Name:       {0}" -f $inspect.Name)
Write-Host ("      Mountpoint: {0}" -f $inspect.Mountpoint)
Write-Host ("      Driver:     {0}" -f $inspect.Driver)

# Optional: check if the volume already has content.
Write-Step "3/4" "Checking existing volume content..."
$existing = & docker run --rm -v "${VolumeName}:/v" alpine:latest ls -A /v 2>$null
if ($existing -and $existing.Length -gt 0) {
    Write-Warn "volume $VolumeName already contains:"
    $existing | ForEach-Object { Write-Host "        - $_" }
    Write-Warn "migration will preserve existing files (cp -n semantics)."
    Write-Warn "to force fresh migration, run: docker volume rm $VolumeName"
    Write-Warn "and then re-run this script."
    Write-Host ""
}

# Run the migration in a transient Alpine container. Source path
# bind-mounted read-only at /src; destination volume mounted at /dst.
# `cp -an /src/. /dst/` copies CONTENTS (note trailing /. and slash)
# in archive mode with no-overwrite-existing semantics.
Write-Step "4/4" "Copying state from $SourcePath to volume $VolumeName..."
& docker run --rm `
    -v "${normalizedSource}:/src:ro" `
    -v "${VolumeName}:/dst" `
    alpine:latest `
    sh -c 'cp -an /src/. /dst/ && echo "Migration complete. Volume contents:" && ls -la /dst/'

if ($LASTEXITCODE -ne 0) {
    Write-Err "docker run for migration exited with code $LASTEXITCODE."
    Write-Host "Source directory $SourcePath is UNCHANGED. Host-mode bootloader can resume canonical traffic." -ForegroundColor Yellow
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Migration complete. The dockerized bootloader can now start" -ForegroundColor Green
Write-Host "against volume $VolumeName with state matching $SourcePath." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Bring up the bootloader container: docker compose up -d bootloader"
Write-Host "  2. Confirm 'operator pubkey loaded' appears in the startup banner:"
Write-Host "     docker compose logs bootloader | Select-Object -First 30"
Write-Host "  3. Run a side-by-side capability_request smoke against the new"
Write-Host "     bootloader from your consumer's compose stack."
Write-Host "  4. If the smoke is clean, you can confidently promote the dockerized"
Write-Host "     bootloader to canonical hostname via Cloudflare Tunnel ingress flip."
Write-Host ""
Write-Host "Rollback insurance: $SourcePath remains UNCHANGED -- host-mode" -ForegroundColor Yellow
Write-Host "bootloader can resume canonical traffic by restarting the service." -ForegroundColor Yellow
Write-Host "Both state stores are valid; pick the one you want canonical." -ForegroundColor Yellow
