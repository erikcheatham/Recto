# 05-smoke-test.ps1 — End-to-end deployment verification.
#
# Starts the registered NSSM service, waits for child spawn, verifies the
# launcher is supervising correctly, hits the bootloader's health endpoint
# (if the service.yaml exposes one), confirms the dpapi-machine vault is
# decryptable. Each check produces a structured PASS/FAIL line with
# diagnostic hints; exit code reflects overall pass/fail.
#
# Usage:
#   .\05-smoke-test.ps1 -ServiceName MyConsumer
#
# Parameters:
#   -ServiceName            Match what 04-register-service.ps1 used.
#   -InstallPath            Where the Recto venv lives. Default: C:\opt\recto.
#   -BootloaderHealthUrl    HTTP URL of the bootloader's health endpoint
#                           (if the supervised service exposes one). Default:
#                           empty — skip the health-check probe. Common values:
#                           "http://localhost:8765/v0.4/health".
#   -StartupGraceSeconds    Seconds to wait after Start-Service before probing
#                           child process + health. Default: 15. Increase
#                           for services with slow boot (Docker Compose
#                           supervised stacks, etc.).
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed (see remediation hints)

param(
    [Parameter(Mandatory = $true)][string]$ServiceName,
    [string]$InstallPath = "C:\opt\recto",
    [string]$BootloaderHealthUrl = "",
    [int]$StartupGraceSeconds = 15
)

$ErrorActionPreference = "Continue"

$results = @()
$global:failCount = 0

function Add-Check {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Passed,
        [string]$Detail = "",
        [string]$Remediation = ""
    )
    $script:results += [PSCustomObject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
        Remediation = $Remediation
    }
    if (-not $Passed) { $global:failCount++ }
}

Write-Host ""
Write-Host "Recto orchestrator-windows-deploy — smoke test" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# ── Check 1: NSSM service exists ──────────────────────────────────────
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
Add-Check `
    -Name "Service '$ServiceName' is registered" `
    -Passed ($null -ne $service) `
    -Detail $(if ($service) { "Status: $($service.Status); StartType: $($service.StartType)" } else { "Get-Service returned nothing" }) `
    -Remediation "Run 04-register-service.ps1 first to register the NSSM service."
if (-not $service) {
    # Bail early — every subsequent check depends on the service existing.
    Write-Host ""
    foreach ($r in $results) {
        Write-Host ("[FAIL] {0}" -f $r.Name) -ForegroundColor Red
        if ($r.Detail) { Write-Host ("       {0}" -f $r.Detail) -ForegroundColor Yellow }
        if ($r.Remediation) { Write-Host ("       Remediation: {0}" -f $r.Remediation) -ForegroundColor Yellow }
    }
    exit 1
}

# ── Check 2: Start the service ────────────────────────────────────────
$startSucceeded = $false
$startDetail = ""
if ($service.Status -eq "Running") {
    $startSucceeded = $true
    $startDetail = "service was already Running; not restarting"
} else {
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds $StartupGraceSeconds
        $service = Get-Service -Name $ServiceName
        $startSucceeded = ($service.Status -eq "Running")
        $startDetail = "post-start status: $($service.Status) (waited $StartupGraceSeconds s)"
    } catch {
        $startDetail = "Start-Service threw: $($_.Exception.Message)"
    }
}
Add-Check `
    -Name "Service started" `
    -Passed $startSucceeded `
    -Detail $startDetail `
    -Remediation "Check NSSM stderr log at C:\opt\recto\logs\$ServiceName\stderr.log for spawn errors. Common causes: bad ServiceYaml path, missing vault entries referenced by YAML's secrets: block, missing Python deps."

# ── Check 3: Child process is running ─────────────────────────────────
# NSSM forks the wrapped process; the supervised python.exe should appear
# as a child of the NSSM service process. We can verify by finding the
# python.exe whose command line includes "-m recto launch".
$pythonChildFound = $false
$pythonChildDetail = ""
try {
    $pythonProcs = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue
    foreach ($p in $pythonProcs) {
        if ($p.CommandLine -and $p.CommandLine -match "-m\s+recto\s+launch") {
            $pythonChildFound = $true
            $pythonChildDetail = "PID $($p.ProcessId); cmdline: $($p.CommandLine.Substring(0, [Math]::Min(150, $p.CommandLine.Length)))..."
            break
        }
    }
    if (-not $pythonChildFound) {
        $pythonChildDetail = "no python.exe with '-m recto launch' in cmdline found"
    }
} catch {
    $pythonChildDetail = "Win32_Process query threw: $($_.Exception.Message)"
}
Add-Check `
    -Name "Recto launcher child process running" `
    -Passed $pythonChildFound `
    -Detail $pythonChildDetail `
    -Remediation "The NSSM service may have started the wrapper but the launcher exited. Inspect C:\opt\recto\logs\$ServiceName\stderr.log for the exit reason. If the launcher exits cleanly with code 0 immediately, the YAML's exec: block may be malformed (the wrapped command isn't blocking)."

# ── Check 4: Vault is decryptable ─────────────────────────────────────
# Best-effort: run `recto vault status` and parse the output. A successful
# status confirms the operator pubkey is installed AND the dpapi-machine
# backend can decrypt the existing blob.
$venvPython = Join-Path $InstallPath ".venv\Scripts\python.exe"
$vaultOk = $false
$vaultDetail = ""
if (Test-Path $venvPython) {
    try {
        $vaultOutput = & $venvPython -m recto vault status 2>&1 | Out-String
        if ($vaultOutput -match "bootstrapped|operator pubkey:") {
            $vaultOk = $true
            # Strip ANSI codes if present + trim to first 200 chars for the report.
            $cleaned = ($vaultOutput -replace "`e\[[0-9;]*m", "").Trim()
            $vaultDetail = $cleaned.Substring(0, [Math]::Min(200, $cleaned.Length))
        } else {
            $vaultDetail = "vault status output did not contain expected 'bootstrapped' marker; output: $vaultOutput"
        }
    } catch {
        $vaultDetail = "recto vault status threw: $($_.Exception.Message)"
    }
} else {
    $vaultDetail = "venv python not found at $venvPython"
}
Add-Check `
    -Name "Vault is decryptable (operator pubkey installed)" `
    -Passed $vaultOk `
    -Detail $vaultDetail `
    -Remediation "Re-run 03-bootstrap-vault.ps1 to install the operator pubkey. If the vault was bootstrapped under a different user account, the dpapi-machine backend won't be able to decrypt it under the current user — repeat the bootstrap from an admin session."

# ── Check 5: Bootloader health endpoint (optional) ────────────────────
if ($BootloaderHealthUrl) {
    $healthOk = $false
    $healthDetail = ""
    try {
        $response = Invoke-WebRequest -Uri $BootloaderHealthUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $healthOk = $true
            $healthDetail = "HTTP 200 from $BootloaderHealthUrl"
        } else {
            $healthDetail = "HTTP $($response.StatusCode) from $BootloaderHealthUrl"
        }
    } catch {
        $healthDetail = "request to $BootloaderHealthUrl failed: $($_.Exception.Message)"
    }
    Add-Check `
        -Name "Bootloader health endpoint reachable" `
        -Passed $healthOk `
        -Detail $healthDetail `
        -Remediation "Verify the supervised service exposes a health endpoint at the URL passed via -BootloaderHealthUrl. Check the service.yaml's exec: + healthz: blocks. If the service binds to a non-localhost interface, adjust the URL accordingly."
} else {
    Write-Host "(Skipping bootloader health check — -BootloaderHealthUrl not provided)" -ForegroundColor DarkGray
}

# ── Report ────────────────────────────────────────────────────────────
Write-Host ""
foreach ($r in $results) {
    if ($r.Passed) {
        Write-Host ("[PASS] {0}" -f $r.Name) -ForegroundColor Green
        if ($r.Detail) { Write-Host ("       {0}" -f $r.Detail) -ForegroundColor DarkGray }
    } else {
        Write-Host ("[FAIL] {0}" -f $r.Name) -ForegroundColor Red
        if ($r.Detail) { Write-Host ("       {0}" -f $r.Detail) -ForegroundColor Yellow }
        if ($r.Remediation) { Write-Host ("       Remediation: {0}" -f $r.Remediation) -ForegroundColor Yellow }
    }
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
if ($failCount -eq 0) {
    Write-Host "All $($results.Count) smoke checks passed. Recto-supervised service '$ServiceName' is live." -ForegroundColor Green
    Write-Host ""
    Write-Host "Operator's next moves:" -ForegroundColor Cyan
    Write-Host "  - Pair an iPhone/Android via the Recto Phone app to this bootloader" -ForegroundColor Cyan
    Write-Host "  - Add secrets to the vault: python -m recto secrets set $ServiceName <name>" -ForegroundColor Cyan
    Write-Host "  - Tail logs: Get-Content C:\opt\recto\logs\$ServiceName\stderr.log -Wait" -ForegroundColor Cyan
    Write-Host ""
    exit 0
} else {
    Write-Host "$failCount of $($results.Count) checks FAILED. Address remediation hints + re-run." -ForegroundColor Red
    Write-Host ""
    exit 1
}
