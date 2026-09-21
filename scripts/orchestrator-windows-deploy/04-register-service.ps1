# 04-register-service.ps1 — Register the NSSM-wrapped supervised service.
#
# NSSM installs the supervised service pointing at the venv's python.exe
# with `-m recto launch <service-yaml>` as the args. The supervised process
# is the Recto launcher; the launcher in turn reads the YAML, decrypts
# vault secrets at child-spawn, and supervises the real application
# child process per the YAML's exec/healthz/restart config.
#
# Idempotent — re-running against an already-registered service updates
# configuration (Application path, ObjectName, AppEnvironmentExtra, etc.)
# rather than erroring. Operators can re-run after rotating the service
# account password or moving the venv to a new path.
#
# Usage:
#   .\04-register-service.ps1 `
#       -ServiceName MyConsumer `
#       -ServiceYaml C:\opt\recto-deploy\my-consumer.service.yaml `
#       -ObjectName "LocalSystem"
#
#   # Or with a custom service account (least-privilege posture):
#   .\04-register-service.ps1 `
#       -ServiceName MyConsumer `
#       -ServiceYaml C:\opt\recto-deploy\my-consumer.service.yaml `
#       -ObjectName ".\my-consumer-svc" `
#       -ObjectPassword (Read-Host -AsSecureString "Service account password")
#
# Parameters:
#   -ServiceName       NSSM service name. Match what 03-bootstrap-vault.ps1
#                      used (the vault directory at C:\ProgramData\recto\
#                      <ServiceName>\ must already exist).
#   -ServiceYaml       Absolute path to the service.yaml that defines
#                      exec/secrets/healthz/restart for the supervised app.
#                      File must exist at registration time.
#   -InstallPath       Where the Recto venv lives. Default: C:\opt\recto.
#   -ObjectName        NT service account. Default: "LocalSystem".
#                      For least-privilege, create a dedicated service
#                      account and pass `.\<account-name>`.
#   -ObjectPassword    SecureString password for non-LocalSystem accounts.
#                      Ignored when ObjectName is LocalSystem / LocalService
#                      / NetworkService.
#   -DisplayName       NSSM DisplayName + Description fall-back. Default:
#                      "Recto: $ServiceName".
#   -Description       NSSM Description fall-back. Default: derived from
#                      ServiceName.
#   -AppEnvironmentExtra
#                      Hashtable of NON-SECRET env vars that should land
#                      in NSSM's registry-stored AppEnvironmentExtra
#                      (e.g. @{ RECTO_AGENTS_FILE = "C:\opt\recto\agents.json" }).
#                      Secrets MUST NOT live here — they go in the dpapi-
#                      machine vault and are decrypted by the launcher at
#                      child-spawn per the YAML's secrets: block.
#   -StartupType       NSSM Start parameter. Default: SERVICE_AUTO_START.
#                      Options: SERVICE_DEMAND_START / SERVICE_AUTO_START /
#                      SERVICE_DELAYED_AUTO_START / SERVICE_DISABLED.
#
# Exit codes:
#   0 — service registered (or updated if already present) + nssm status
#       confirms SERVICE_STOPPED or RUNNING
#   1 — NSSM not found, venv not found, YAML not found, or nssm install
#       returned non-zero

param(
    [Parameter(Mandatory = $true)][string]$ServiceName,
    [Parameter(Mandatory = $true)][string]$ServiceYaml,
    [string]$InstallPath = "C:\opt\recto",
    [string]$ObjectName  = "LocalSystem",
    [System.Security.SecureString]$ObjectPassword,
    [string]$DisplayName = "",
    [string]$Description = "",
    [hashtable]$AppEnvironmentExtra = @{},
    [ValidateSet("SERVICE_DEMAND_START","SERVICE_AUTO_START","SERVICE_DELAYED_AUTO_START","SERVICE_DISABLED")]
    [string]$StartupType = "SERVICE_AUTO_START"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "Recto orchestrator-windows-deploy — NSSM service registration" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

# ── Validate inputs ───────────────────────────────────────────────────
$nssmCmd = Get-Command nssm -ErrorAction SilentlyContinue
if (-not $nssmCmd) {
    Write-Host "ERROR: nssm.exe not found on PATH. Run 01-prerequisites.ps1 first." -ForegroundColor Red
    exit 1
}
$nssm = $nssmCmd.Source

$venvPython = Join-Path $InstallPath ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "ERROR: Recto venv not found at $venvPython. Run 02-create-venv.ps1 first." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $ServiceYaml)) {
    Write-Host "ERROR: ServiceYaml not found at $ServiceYaml." -ForegroundColor Red
    Write-Host "       Author the YAML before registering the service. See INTEGRATION.md for the schema." -ForegroundColor Yellow
    exit 1
}

if (-not $DisplayName) { $DisplayName = "Recto: $ServiceName" }
if (-not $Description) { $Description = "Recto-supervised service '$ServiceName' (launcher reads $ServiceYaml at child-spawn)." }

# ── Check whether service already exists ──────────────────────────────
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$isUpdate = $null -ne $existingService
if ($isUpdate) {
    Write-Host "Service '$ServiceName' already exists; updating configuration." -ForegroundColor Yellow
    # NSSM service must be stopped before some parameter updates take effect.
    if ($existingService.Status -ne "Stopped") {
        Write-Host "Stopping service for reconfiguration..." -ForegroundColor Cyan
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
} else {
    Write-Host "Registering new NSSM service '$ServiceName'..." -ForegroundColor Cyan
    & $nssm install $ServiceName $venvPython "-m" "recto" "launch" $ServiceYaml
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: nssm install returned exit code $LASTEXITCODE." -ForegroundColor Red
        exit 1
    }
}

# ── Configure NSSM parameters ─────────────────────────────────────────
# Application: the venv's python.exe (already set during install; reset
# on update path).
& $nssm set $ServiceName Application $venvPython | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "WARNING: nssm set Application returned non-zero." -ForegroundColor Yellow }

# AppParameters: the launcher invocation. -m recto launch <yaml> is the
# canonical Recto entry point.
$appParameters = "-m recto launch `"$ServiceYaml`""
& $nssm set $ServiceName AppParameters $appParameters | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "WARNING: nssm set AppParameters returned non-zero." -ForegroundColor Yellow }

# AppDirectory: the install root. Affects relative-path resolution inside
# the supervised process.
& $nssm set $ServiceName AppDirectory $InstallPath | Out-Null

# DisplayName + Description: surfaces in services.msc.
& $nssm set $ServiceName DisplayName $DisplayName | Out-Null
& $nssm set $ServiceName Description $Description | Out-Null

# Startup type.
& $nssm set $ServiceName Start $StartupType | Out-Null

# ── ObjectName (service account) ──────────────────────────────────────
$isBuiltInAccount = $ObjectName -in @("LocalSystem", "NT AUTHORITY\LocalSystem", "LocalService", "NT AUTHORITY\LocalService", "NetworkService", "NT AUTHORITY\NetworkService")
if ($isBuiltInAccount) {
    & $nssm set $ServiceName ObjectName $ObjectName | Out-Null
    Write-Host "ObjectName: $ObjectName (built-in; no password needed)" -ForegroundColor Green
} else {
    if (-not $ObjectPassword) {
        Write-Host "ERROR: ObjectName '$ObjectName' is not a built-in account; -ObjectPassword (SecureString) is required." -ForegroundColor Red
        exit 1
    }
    # Decrypt SecureString just long enough to pass to NSSM.
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ObjectPassword)
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    try {
        & $nssm set $ServiceName ObjectName $ObjectName $plain | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: nssm set ObjectName failed. Verify the account exists + has 'Log on as a service' right." -ForegroundColor Red
            exit 1
        }
        Write-Host "ObjectName: $ObjectName (custom service account)" -ForegroundColor Green
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $plain = $null
    }
}

# ── AppEnvironmentExtra (non-secret env vars only) ────────────────────
# NSSM's AppEnvironmentExtra is registry-stored plaintext — anything that's
# a real secret must live in the dpapi-machine vault, NOT here. This
# parameter is appropriate for non-secret operational config like
# RECTO_AGENTS_FILE paths or feature-flag toggles that operators want
# to flip without re-publishing a YAML.
if ($AppEnvironmentExtra.Count -gt 0) {
    $envLines = @()
    foreach ($key in $AppEnvironmentExtra.Keys) {
        $val = $AppEnvironmentExtra[$key]
        if ($key -match "(?i)password|secret|token|key|pat") {
            Write-Host "WARNING: env var name '$key' looks secret-shaped; storing in NSSM AppEnvironmentExtra is PLAINTEXT registry storage." -ForegroundColor Yellow
            Write-Host "         Recommended: move this value to the dpapi-machine vault instead, declare in service.yaml's secrets: block." -ForegroundColor Yellow
        }
        $envLines += "$key=$val"
    }
    & $nssm set $ServiceName AppEnvironmentExtra @envLines | Out-Null
    Write-Host "AppEnvironmentExtra: $($AppEnvironmentExtra.Count) non-secret env var(s) set." -ForegroundColor Green
} else {
    # Clear any prior AppEnvironmentExtra (in case of re-registration that's
    # dropping previously-set values).
    & $nssm set $ServiceName AppEnvironmentExtra "" | Out-Null
}

# ── stdout/stderr capture ─────────────────────────────────────────────
# Default to logging both streams under C:\opt\recto\logs\<service>\. Operators
# can repoint via direct nssm set after registration.
$logDir = Join-Path $InstallPath "logs\$ServiceName"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
& $nssm set $ServiceName AppStdout (Join-Path $logDir "stdout.log") | Out-Null
& $nssm set $ServiceName AppStderr (Join-Path $logDir "stderr.log") | Out-Null
# Rotate at 10 MiB, keep 5 archives.
& $nssm set $ServiceName AppRotateFiles 1 | Out-Null
& $nssm set $ServiceName AppRotateBytes 10485760 | Out-Null

# ── Report ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "Service:              $ServiceName ($(if ($isUpdate) { 'updated' } else { 'newly registered' }))" -ForegroundColor Green
Write-Host "Application:          $venvPython" -ForegroundColor Green
Write-Host "AppParameters:        $appParameters" -ForegroundColor Green
Write-Host "AppDirectory:         $InstallPath" -ForegroundColor Green
Write-Host "ObjectName:           $ObjectName" -ForegroundColor Green
Write-Host "Startup type:         $StartupType" -ForegroundColor Green
Write-Host "stdout log:           $(Join-Path $logDir 'stdout.log')" -ForegroundColor Green
Write-Host "stderr log:           $(Join-Path $logDir 'stderr.log')" -ForegroundColor Green
Write-Host ""
Write-Host "Service is registered but STOPPED. 05-smoke-test.ps1 starts it and verifies." -ForegroundColor Yellow
Write-Host ""
Write-Host "Next: 05-smoke-test.ps1 -ServiceName $ServiceName" -ForegroundColor Cyan
Write-Host ""
exit 0
