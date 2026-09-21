# 99-uninstall.ps1 — Clean teardown of a Recto-supervised service.
#
# Stops the service, removes the NSSM registration, optionally removes the
# dpapi-machine vault directory (default KEEP — vault contents may be
# precious + may hold operator pubkey + service secrets), always removes
# the venv (re-creation via 02-create-venv.ps1 is cheap). For dev iteration
# + host repurposing; production uninstall is rare but the path needs to
# exist + be reversible.
#
# Usage:
#   .\99-uninstall.ps1 -ServiceName MyConsumer
#   .\99-uninstall.ps1 -ServiceName MyConsumer -RemoveVault
#   .\99-uninstall.ps1 -ServiceName MyConsumer -KeepVenv -KeepLogs
#
# Parameters:
#   -ServiceName    NSSM service name to remove.
#   -InstallPath    Where the Recto venv lives. Default: C:\opt\recto.
#   -RemoveVault    Also delete C:\ProgramData\recto\<ServiceName>\.
#                   DEFAULT IS FALSE — vault contents may be precious.
#                   Explicit opt-in only. Operator pubkey + service secrets
#                   are stored here; deletion is irreversible without backup.
#   -KeepVenv       Keep the venv at C:\opt\recto\.venv\ intact. Default:
#                   the venv is removed (re-creation is cheap). Set this
#                   flag if the same install hosts multiple services and
#                   only this service is being torn down.
#   -KeepLogs       Keep the NSSM stdout/stderr logs at
#                   C:\opt\recto\logs\<ServiceName>\. Default: logs are
#                   removed alongside the service.
#   -Force          Skip the confirmation prompt. Default: prompt the
#                   operator before any destructive action.
#
# Exit codes:
#   0 — teardown completed (with structured report of what was removed vs kept)
#   1 — service not found, NSSM not on PATH, or removal failed at some step

param(
    [Parameter(Mandatory = $true)][string]$ServiceName,
    [string]$InstallPath = "C:\opt\recto",
    [switch]$RemoveVault,
    [switch]$KeepVenv,
    [switch]$KeepLogs,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "Recto orchestrator-windows-deploy — uninstall '$ServiceName'" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

# ── Pre-flight summary + confirmation ─────────────────────────────────
$vaultDir = Join-Path "$env:ProgramData" "recto\$ServiceName"
$venvPath = Join-Path $InstallPath ".venv"
$logDir   = Join-Path $InstallPath "logs\$ServiceName"

$plannedActions = @()
$plannedActions += "- Stop + remove NSSM service '$ServiceName'"
if ($RemoveVault) {
    $plannedActions += "- DELETE vault directory $vaultDir (-RemoveVault flag set)"
} else {
    $plannedActions += "- KEEP vault directory $vaultDir (use -RemoveVault to remove)"
}
if ($KeepVenv) {
    $plannedActions += "- KEEP venv at $venvPath (-KeepVenv flag set)"
} else {
    $plannedActions += "- DELETE venv at $venvPath"
}
if ($KeepLogs) {
    $plannedActions += "- KEEP logs at $logDir (-KeepLogs flag set)"
} else {
    $plannedActions += "- DELETE logs at $logDir"
}

Write-Host "Planned actions:" -ForegroundColor Yellow
$plannedActions | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
Write-Host ""

if (-not $Force) {
    $response = Read-Host "Proceed? Type 'yes' to confirm, anything else to abort"
    if ($response -ne "yes") {
        Write-Host "Aborted. No changes made." -ForegroundColor Cyan
        exit 0
    }
    Write-Host ""
}

$removed = @()
$kept    = @()
$failed  = @()

# ── Step 1: Stop + remove NSSM service ────────────────────────────────
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Host "Service '$ServiceName' not registered; skipping NSSM removal." -ForegroundColor DarkGray
    $kept += "NSSM service '$ServiceName' (not registered)"
} else {
    if ($service.Status -ne "Stopped") {
        Write-Host "Stopping service '$ServiceName'..." -ForegroundColor Cyan
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 3
        } catch {
            Write-Host "WARNING: Stop-Service threw: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    # Confirm stopped before NSSM remove (NSSM remove fails on running services).
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Stopped") {
        Write-Host "ERROR: service still $($service.Status) after Stop-Service. Manual intervention needed." -ForegroundColor Red
        Write-Host "       Try: sc.exe stop $ServiceName; if that fails, sc.exe queryex $ServiceName + taskkill /F /PID <pid>" -ForegroundColor Yellow
        $failed += "Stop service '$ServiceName' (still $($service.Status))"
    } else {
        # NSSM remove with -confirm flag for non-interactive removal.
        $nssmCmd = Get-Command nssm -ErrorAction SilentlyContinue
        if ($nssmCmd) {
            Write-Host "Removing NSSM service '$ServiceName'..." -ForegroundColor Cyan
            & $nssmCmd.Source remove $ServiceName confirm 2>&1 | ForEach-Object {
                Write-Host "  $_" -ForegroundColor DarkGray
            }
            if ($LASTEXITCODE -eq 0) {
                $removed += "NSSM service '$ServiceName'"
            } else {
                $failed += "nssm remove '$ServiceName' (exit code $LASTEXITCODE)"
            }
        } else {
            Write-Host "WARNING: nssm.exe not found; service is stopped but NSSM registration remains." -ForegroundColor Yellow
            Write-Host "         Install NSSM + re-run 99-uninstall.ps1 to complete cleanup." -ForegroundColor Yellow
            $failed += "NSSM removal (nssm.exe not on PATH)"
        }
    }
}

# ── Step 2: Vault directory ───────────────────────────────────────────
if ($RemoveVault) {
    if (Test-Path $vaultDir) {
        try {
            Remove-Item -Path $vaultDir -Recurse -Force -ErrorAction Stop
            $removed += "Vault directory $vaultDir"
            Write-Host "Removed vault directory: $vaultDir" -ForegroundColor Green
        } catch {
            $failed += "Vault directory removal ($vaultDir): $($_.Exception.Message)"
            Write-Host "ERROR: vault directory removal failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        $kept += "Vault directory (not present at $vaultDir)"
    }
} else {
    if (Test-Path $vaultDir) {
        $kept += "Vault directory $vaultDir (use -RemoveVault to remove)"
        Write-Host "Kept vault directory: $vaultDir" -ForegroundColor DarkGray
    }
}

# ── Step 3: Venv ──────────────────────────────────────────────────────
if ($KeepVenv) {
    $kept += "Venv $venvPath (-KeepVenv flag set)"
} else {
    if (Test-Path $venvPath) {
        # Defensive: if other services share this venv (unusual but possible),
        # removing it breaks them. Check whether other services in this install
        # path's logs/ folder exist; if so, warn but proceed.
        $logsRoot = Join-Path $InstallPath "logs"
        if (Test-Path $logsRoot) {
            $otherServices = Get-ChildItem -Path $logsRoot -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne $ServiceName }
            if ($otherServices.Count -gt 0) {
                Write-Host "WARNING: other services share this install path (logs found for: $($otherServices.Name -join ', '))." -ForegroundColor Yellow
                Write-Host "         Removing the venv will break those services. Re-run with -KeepVenv to skip." -ForegroundColor Yellow
                $kept += "Venv $venvPath (preserved due to sibling services)"
            } else {
                Remove-Item -Path $venvPath -Recurse -Force -ErrorAction SilentlyContinue
                $removed += "Venv $venvPath"
                Write-Host "Removed venv: $venvPath" -ForegroundColor Green
            }
        } else {
            Remove-Item -Path $venvPath -Recurse -Force -ErrorAction SilentlyContinue
            $removed += "Venv $venvPath"
            Write-Host "Removed venv: $venvPath" -ForegroundColor Green
        }
    } else {
        $kept += "Venv (not present at $venvPath)"
    }
}

# ── Step 4: Logs ──────────────────────────────────────────────────────
if ($KeepLogs) {
    $kept += "Logs $logDir (-KeepLogs flag set)"
} else {
    if (Test-Path $logDir) {
        try {
            Remove-Item -Path $logDir -Recurse -Force -ErrorAction Stop
            $removed += "Logs $logDir"
            Write-Host "Removed logs: $logDir" -ForegroundColor Green
        } catch {
            $failed += "Logs removal ($logDir): $($_.Exception.Message)"
        }
    } else {
        $kept += "Logs (not present at $logDir)"
    }
}

# ── Report ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "Teardown report:" -ForegroundColor Cyan
if ($removed.Count -gt 0) {
    Write-Host ""
    Write-Host "Removed:" -ForegroundColor Green
    $removed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
}
if ($kept.Count -gt 0) {
    Write-Host ""
    Write-Host "Kept:" -ForegroundColor DarkGray
    $kept | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
}
if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "Failed:" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "Teardown complete. Re-create via 02-create-venv.ps1 if needed." -ForegroundColor Green
    Write-Host ""
    exit 0
} else {
    Write-Host "$($failed.Count) step(s) failed — see above. Some cleanup may need manual completion." -ForegroundColor Red
    Write-Host ""
    exit 1
}
