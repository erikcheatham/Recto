# 03-bootstrap-vault.ps1 — Initialize dpapi-machine vault + install operator pubkey.
#
# Creates the dpapi-machine vault directory at C:\ProgramData\recto\<service>\
# and runs `recto vault bootstrap <pubkey>` to install the operator's
# secp256k1 public key for capability-JWS verification (Wave C part 4
# ceremony). The pubkey lets the bootloader verify capability JWSes signed
# by the operator's phone enclave WITHOUT trusting the network — even a
# compromised bootloader can't accept a forged capability if it lacks the
# operator's pubkey.
#
# Usage:
#   .\03-bootstrap-vault.ps1 -ServiceName MyConsumer -OperatorPubkeyHex "<128-hex-chars>"
#
# Parameters:
#   -ServiceName            Logical service name. Vault path becomes
#                           C:\ProgramData\recto\<ServiceName>\.
#   -OperatorPubkeyHex      The operator's secp256k1 public key as 128 hex
#                           chars (64 bytes uncompressed X || Y, no 0x04
#                           prefix). Paste from the phone enclave's export
#                           ceremony.
#   -InstallPath            Where the Recto venv lives. Default: C:\opt\recto
#                           (matches 02-create-venv.ps1's default).
#   -Force                  Overwrite an existing operator pubkey. Defaults to
#                           false — `recto vault bootstrap` refuses to clobber
#                           a previously-bootstrapped vault without explicit
#                           -Force, defending against accidental key rotation.
#
# Exit codes:
#   0 — vault directory created (or already present) + operator pubkey
#       installed (or already present + matches input)
#   1 — invalid pubkey format, ProgramData write failure, or `recto vault
#       bootstrap` exit non-zero

param(
    [Parameter(Mandatory = $true)][string]$ServiceName,
    [Parameter(Mandatory = $true)][string]$OperatorPubkeyHex,
    [string]$InstallPath = "C:\opt\recto",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "Recto orchestrator-windows-deploy — vault bootstrap" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# ── Validate pubkey shape ─────────────────────────────────────────────
$cleaned = $OperatorPubkeyHex.Trim()
if ($cleaned.StartsWith("0x", [StringComparison]::OrdinalIgnoreCase)) {
    $cleaned = $cleaned.Substring(2)
}
# Accept the 65-byte uncompressed-point form (0x04 prefix + X || Y) by
# stripping the leading 04. Matches the Es256kCapabilityVerifier.FromHexPubkey
# factory's flexibility.
if ($cleaned.Length -eq 130 -and $cleaned.StartsWith("04", [StringComparison]::OrdinalIgnoreCase)) {
    $cleaned = $cleaned.Substring(2)
}
if ($cleaned.Length -ne 128) {
    Write-Host "ERROR: -OperatorPubkeyHex must be exactly 128 hex chars (64 bytes uncompressed X||Y)." -ForegroundColor Red
    Write-Host "       Got $($cleaned.Length) chars after trimming whitespace + optional 0x / 0x04 prefix." -ForegroundColor Yellow
    Write-Host "       Example shape: aabbccdd...112233445566 (no spaces, no 0x prefix)." -ForegroundColor Yellow
    exit 1
}
if ($cleaned -notmatch "^[0-9a-fA-F]{128}$") {
    Write-Host "ERROR: -OperatorPubkeyHex contains non-hex characters." -ForegroundColor Red
    Write-Host "       Expected: 128 chars from [0-9a-fA-F]." -ForegroundColor Yellow
    exit 1
}
Write-Host "Pubkey validated: 128 hex chars (64 bytes X||Y form)." -ForegroundColor Green
$pubkeyFingerprint = $cleaned.Substring(0, 8) + "..." + $cleaned.Substring(120, 8)
Write-Host "Pubkey fingerprint: $pubkeyFingerprint" -ForegroundColor DarkGray

# ── Create vault directory ────────────────────────────────────────────
# Recto's dpapi-machine backend looks for blobs at
# C:\ProgramData\recto\<ServiceName>\<SecretName>.dpapi.
$vaultRoot = Join-Path "$env:ProgramData" "recto"
$vaultDir  = Join-Path $vaultRoot $ServiceName
if (-not (Test-Path $vaultRoot)) {
    New-Item -ItemType Directory -Path $vaultRoot -Force | Out-Null
    Write-Host "Created vault root: $vaultRoot" -ForegroundColor Green
}
if (-not (Test-Path $vaultDir)) {
    New-Item -ItemType Directory -Path $vaultDir -Force | Out-Null
    Write-Host "Created service vault: $vaultDir" -ForegroundColor Green
} else {
    Write-Host "Service vault exists: $vaultDir" -ForegroundColor DarkGray
}

# ── ACL: LocalSystem readable + admins writable ───────────────────────
# Recto's launcher runs as the service's ObjectName (LocalSystem by default
# on production hosts) and needs read access to decrypt vault blobs. Admin
# accounts need write access for rotation. Other users get no access.
try {
    $acl = Get-Acl -Path $vaultDir
    # Disable inheritance so the explicit rules below are the only ones.
    $acl.SetAccessRuleProtection($true, $false)
    # Clear existing rules (start clean).
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    # SYSTEM: full control (read at child-spawn for the launcher).
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "SYSTEM", "FullControl",
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
         [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        "Allow")
    $acl.AddAccessRule($systemRule)
    # Administrators: full control (rotation via `recto vault` CLI commands).
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Administrators", "FullControl",
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
         [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        "Allow")
    $acl.AddAccessRule($adminRule)
    Set-Acl -Path $vaultDir -AclObject $acl
    Write-Host "ACLs set: SYSTEM + Administrators full control, inheritance disabled." -ForegroundColor Green
} catch {
    Write-Host "WARNING: ACL configuration failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         The vault directory exists but inherits default ProgramData ACLs." -ForegroundColor Yellow
    Write-Host "         This is functional but less hardened. Fix manually if needed via:" -ForegroundColor Yellow
    Write-Host "         icacls `"$vaultDir`" /inheritance:r /grant:r SYSTEM:F Administrators:F" -ForegroundColor Yellow
}

# ── Run `recto vault bootstrap` ───────────────────────────────────────
$venvPython = Join-Path $InstallPath ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "ERROR: Recto venv not found at $venvPython. Run 02-create-venv.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Running 'recto vault bootstrap'..." -ForegroundColor Cyan
$bootstrapArgs = @("-m", "recto", "vault", "bootstrap", $cleaned)
if ($Force) {
    $bootstrapArgs += "--force"
}
& $venvPython @bootstrapArgs 2>&1 | ForEach-Object {
    if ($_ -match "already bootstrapped|already configured") {
        Write-Host "  $_" -ForegroundColor Yellow
    } elseif ($_ -match "bootstrap complete|installed|success") {
        Write-Host "  $_" -ForegroundColor Green
    } elseif ($_ -match "error|Error|ERROR|refuse") {
        Write-Host "  $_" -ForegroundColor Red
    } else {
        Write-Host "  $_" -ForegroundColor DarkGray
    }
}
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: 'recto vault bootstrap' returned exit code $LASTEXITCODE." -ForegroundColor Red
    Write-Host "       If the vault is already bootstrapped with a different pubkey, re-run with -Force to rotate." -ForegroundColor Yellow
    exit 1
}

# ── Verify via `recto vault status` ───────────────────────────────────
Write-Host ""
Write-Host "Verifying via 'recto vault status'..." -ForegroundColor Cyan
$statusOutput = & $venvPython -m recto vault status 2>&1
$statusOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: 'recto vault status' returned exit code $LASTEXITCODE." -ForegroundColor Yellow
    Write-Host "         Bootstrap succeeded but status verification failed; investigate." -ForegroundColor Yellow
}

# ── Report ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Vault root:           $vaultDir" -ForegroundColor Green
Write-Host "Operator pubkey:      $pubkeyFingerprint (128-hex form, 64 bytes X||Y)" -ForegroundColor Green
Write-Host "ACL posture:          SYSTEM + Administrators full control" -ForegroundColor Green
Write-Host ""
Write-Host "Vault is ready to hold dpapi-machine-encrypted secret blobs for" -ForegroundColor Green
Write-Host "service '$ServiceName'. Operator can add secrets via:" -ForegroundColor Green
Write-Host "  python -m recto secrets set $ServiceName <name>" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Next: 04-register-service.ps1 -ServiceName $ServiceName -ServiceYaml <path-to-yaml>" -ForegroundColor Cyan
Write-Host ""
exit 0
