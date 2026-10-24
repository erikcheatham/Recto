# 01-prerequisites.ps1 — Host readiness check for Recto orchestrator deployment.
#
# Verifies the Windows host can support a Recto-supervised orchestrator:
# admin privileges, Windows version, Python 3.10+, NSSM installation,
# network access to PyPI. Each check produces a structured PASS/FAIL line
# with a remediation hint on failure. Idempotent — safe to re-run.
#
# Usage:
#   .\01-prerequisites.ps1
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed (see remediation hints in output)
#
# Reference: see README.md in this folder for the full deployment sequence.

$ErrorActionPreference = "Continue"  # We want to run ALL checks, not bail on first failure

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
Write-Host "Recto orchestrator-windows-deploy — prerequisites check" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# ── Check 1: Admin privileges ─────────────────────────────────────────
$currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Check `
    -Name "Administrator privileges" `
    -Passed $isAdmin `
    -Detail $(if ($isAdmin) { "running as $($currentUser.Identity.Name)" } else { "current process is NOT elevated" }) `
    -Remediation "Right-click PowerShell, choose 'Run as Administrator', and re-run this script."

# ── Check 2: Windows version ──────────────────────────────────────────
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($osInfo) {
    $osVersion = [Version]$osInfo.Version
    $osIsModern = $osVersion -ge [Version]"10.0"
    Add-Check `
        -Name "Windows version" `
        -Passed $osIsModern `
        -Detail "$($osInfo.Caption) (build $($osInfo.BuildNumber))" `
        -Remediation "Recto targets Windows 10 / Server 2019 or newer. Older Windows versions may work but are untested."
} else {
    Add-Check `
        -Name "Windows version" `
        -Passed $false `
        -Detail "Get-CimInstance Win32_OperatingSystem returned nothing" `
        -Remediation "WMI query failed. Verify the WMI service is running: Get-Service Winmgmt."
}

# ── Check 3: Python 3.10+ ─────────────────────────────────────────────
$pythonExe = $null
$pythonVersionOk = $false
$pythonDetail = ""
$candidates = @("python", "python3", "py")
foreach ($cand in $candidates) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) {
        try {
            $verOutput = & $cmd --version 2>&1
            if ($verOutput -match "Python (\d+)\.(\d+)") {
                $major = [int]$Matches[1]
                $minor = [int]$Matches[2]
                if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 10)) {
                    $pythonExe = $cmd.Source
                    $pythonVersionOk = $true
                    $pythonDetail = "$verOutput at $pythonExe"
                    break
                } else {
                    $pythonDetail = "$verOutput is below 3.10 (at $($cmd.Source))"
                }
            }
        } catch {
            # try next candidate
        }
    }
}
if (-not $pythonExe -and -not $pythonDetail) {
    $pythonDetail = "no python / python3 / py found on PATH"
}
Add-Check `
    -Name "Python 3.10+" `
    -Passed $pythonVersionOk `
    -Detail $pythonDetail `
    -Remediation "Install Python 3.10 or newer from https://www.python.org/downloads/. During install, check 'Add python.exe to PATH'. Restart PowerShell after install."

# ── Check 4: NSSM installed ───────────────────────────────────────────
$nssmCmd = Get-Command nssm -ErrorAction SilentlyContinue
$nssmVersion = ""
if ($nssmCmd) {
    try {
        # NSSM prints version on stderr to a specific channel; --version isn't standard.
        # `nssm` with no args prints usage including version. Best-effort parse.
        $nssmOutput = & $nssmCmd 2>&1 | Out-String
        if ($nssmOutput -match "NSSM\s+(\d+\.\d+)") {
            $nssmVersion = "version $($Matches[1])"
        } else {
            $nssmVersion = "version unknown (binary present at $($nssmCmd.Source))"
        }
    } catch {
        $nssmVersion = "binary present at $($nssmCmd.Source) but version-probe failed"
    }
}
Add-Check `
    -Name "NSSM installed" `
    -Passed ($null -ne $nssmCmd) `
    -Detail $(if ($nssmCmd) { $nssmVersion } else { "no nssm.exe on PATH" }) `
    -Remediation "Download NSSM from https://nssm.cc/download (recommended: 2.24-101-g897c7ad or newer). Extract nssm.exe to a folder on PATH (C:\Windows\System32\ is the easiest)."

# ── Check 5: PyPI reachability ────────────────────────────────────────
$pypiReachable = $false
$pypiDetail = ""
try {
    $response = Invoke-WebRequest -Uri "https://pypi.org/simple/" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        $pypiReachable = $true
        $pypiDetail = "https://pypi.org/simple/ returned HTTP 200"
    } else {
        $pypiDetail = "https://pypi.org/simple/ returned HTTP $($response.StatusCode)"
    }
} catch {
    $pypiDetail = "request failed: $($_.Exception.Message)"
}
Add-Check `
    -Name "PyPI reachable" `
    -Passed $pypiReachable `
    -Detail $pypiDetail `
    -Remediation "Verify outbound HTTPS on port 443. If behind a proxy, set HTTP_PROXY + HTTPS_PROXY env vars before running 02-create-venv.ps1."

# ── Check 6: ProgramData write access ─────────────────────────────────
# The dpapi-machine vault lives at C:\ProgramData\recto\<service>\. Need write
# access to C:\ProgramData\ to create the recto subdirectory in step 03.
$programDataPath = "$env:ProgramData"
$canWrite = $false
$writeDetail = ""
try {
    $testFile = Join-Path $programDataPath ".recto-prereq-write-test-$(Get-Random).tmp"
    [System.IO.File]::WriteAllText($testFile, "test")
    Remove-Item $testFile -ErrorAction SilentlyContinue
    $canWrite = $true
    $writeDetail = "$programDataPath is writable"
} catch {
    $writeDetail = "$programDataPath write failed: $($_.Exception.Message)"
}
Add-Check `
    -Name "ProgramData write access" `
    -Passed $canWrite `
    -Detail $writeDetail `
    -Remediation "Verify the current process is elevated (admin). The dpapi-machine vault directory at C:\ProgramData\recto\<service>\ requires admin write access."

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
Write-Host "========================================================" -ForegroundColor Cyan
if ($failCount -eq 0) {
    Write-Host "All $($results.Count) prerequisite checks passed. Ready for 02-create-venv.ps1." -ForegroundColor Green
    Write-Host ""
    exit 0
} else {
    Write-Host "$failCount of $($results.Count) checks FAILED. Address remediation hints before proceeding." -ForegroundColor Red
    Write-Host ""
    exit 1
}
