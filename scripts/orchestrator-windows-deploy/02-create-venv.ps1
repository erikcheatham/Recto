# 02-create-venv.ps1 — Create Python venv + install Recto.
#
# Creates an isolated Python virtual environment at the operator-chosen
# install path, installs recto-core (or installs editable against a local
# Recto clone for dev iteration), and verifies the install. Idempotent —
# re-running against an existing venv re-installs without errors.
#
# Usage:
#   .\02-create-venv.ps1                         # default: C:\opt\recto, PyPI install
#   .\02-create-venv.ps1 -InstallPath D:\recto   # operator-chosen path
#   .\02-create-venv.ps1 -DevMode C:\src\Recto   # editable install (dev workstation)
#   .\02-create-venv.ps1 -RectoVersion 1.0.0     # pin a specific PyPI version
#
# Parameters:
#   -InstallPath   Where the venv lives. Default: C:\opt\recto
#   -DevMode       Path to a local Recto checkout. If set, runs `pip install -e .`
#                  against that path instead of pulling from PyPI. Use during
#                  dev iteration on the Recto codebase itself.
#   -RectoVersion  Pin to a specific PyPI version (e.g. "1.0.0"). Default: latest.
#                  Ignored when -DevMode is set.
#   -PythonExe     Override the Python executable used to create the venv.
#                  Default: discovered via `Get-Command python / python3 / py`.
#
# Exit codes:
#   0 — venv created + Recto installed + import verified
#   1 — Python not found, venv creation failed, or pip install failed

param(
    [string]$InstallPath  = "C:\opt\recto",
    [string]$DevMode      = "",
    [string]$RectoVersion = "",
    [string]$PythonExe    = ""
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "Recto orchestrator-windows-deploy — venv + pip install" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# ── Locate Python ─────────────────────────────────────────────────────
if (-not $PythonExe) {
    foreach ($cand in @("python", "python3", "py")) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) {
            try {
                $verOutput = & $cmd --version 2>&1
                if ($verOutput -match "Python (\d+)\.(\d+)") {
                    $major = [int]$Matches[1]
                    $minor = [int]$Matches[2]
                    if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 10)) {
                        $PythonExe = $cmd.Source
                        Write-Host "Python: $verOutput at $PythonExe" -ForegroundColor Green
                        break
                    }
                }
            } catch { }
        }
    }
}
if (-not $PythonExe) {
    Write-Host "ERROR: Python 3.10+ not found on PATH. Run 01-prerequisites.ps1 first." -ForegroundColor Red
    exit 1
}

# ── Create install directory ──────────────────────────────────────────
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Host "Created install directory: $InstallPath" -ForegroundColor Green
} else {
    Write-Host "Install directory exists: $InstallPath" -ForegroundColor DarkGray
}

# ── Create venv (idempotent — re-creates if missing, reuses if present) ─
$venvPath = Join-Path $InstallPath ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
if (Test-Path $venvPython) {
    Write-Host "Existing venv detected at $venvPath; reusing." -ForegroundColor DarkGray
} else {
    Write-Host "Creating venv at $venvPath..." -ForegroundColor Cyan
    & $PythonExe -m venv $venvPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $venvPython)) {
        Write-Host "ERROR: venv creation failed." -ForegroundColor Red
        exit 1
    }
    Write-Host "Venv created." -ForegroundColor Green
}

# ── Upgrade pip + wheel ───────────────────────────────────────────────
Write-Host "Upgrading pip + wheel in venv..." -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip wheel 2>&1 | ForEach-Object {
    if ($_ -match "Successfully installed|Requirement already satisfied") {
        Write-Host "  $_" -ForegroundColor DarkGray
    } elseif ($_ -match "error|Error|ERROR") {
        Write-Host "  $_" -ForegroundColor Red
    }
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: pip upgrade failed." -ForegroundColor Red
    exit 1
}

# ── Install Recto ─────────────────────────────────────────────────────
if ($DevMode) {
    if (-not (Test-Path $DevMode)) {
        Write-Host "ERROR: -DevMode path does not exist: $DevMode" -ForegroundColor Red
        exit 1
    }
    if (-not (Test-Path (Join-Path $DevMode "pyproject.toml"))) {
        Write-Host "ERROR: -DevMode path doesn't look like a Recto checkout (no pyproject.toml): $DevMode" -ForegroundColor Red
        exit 1
    }
    Write-Host "Installing Recto editable from $DevMode..." -ForegroundColor Cyan
    & $venvPython -m pip install -e "$DevMode[v0_4]" 2>&1 | ForEach-Object {
        if ($_ -match "Successfully installed|Requirement already satisfied|Installing collected") {
            Write-Host "  $_" -ForegroundColor DarkGray
        } elseif ($_ -match "error|Error|ERROR") {
            Write-Host "  $_" -ForegroundColor Red
        }
    }
} else {
    $packageSpec = if ($RectoVersion) { "recto-core[v0_4]==$RectoVersion" } else { "recto-core[v0_4]" }
    Write-Host "Installing $packageSpec from PyPI..." -ForegroundColor Cyan
    & $venvPython -m pip install $packageSpec 2>&1 | ForEach-Object {
        if ($_ -match "Successfully installed|Requirement already satisfied|Installing collected") {
            Write-Host "  $_" -ForegroundColor DarkGray
        } elseif ($_ -match "error|Error|ERROR") {
            Write-Host "  $_" -ForegroundColor Red
        }
    }
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Recto pip install failed." -ForegroundColor Red
    exit 1
}

# ── Verify install ────────────────────────────────────────────────────
Write-Host "Verifying Recto import..." -ForegroundColor Cyan
$verifyOutput = & $venvPython -c "import recto; print(recto.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Recto import failed:" -ForegroundColor Red
    Write-Host "  $verifyOutput" -ForegroundColor Red
    exit 1
}
$installedVersion = $verifyOutput.Trim()
Write-Host "Recto version: $installedVersion" -ForegroundColor Green

# ── Report ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Venv ready at:        $venvPath" -ForegroundColor Green
Write-Host "Venv python:          $venvPython" -ForegroundColor Green
Write-Host "Recto version:        $installedVersion" -ForegroundColor Green
if ($DevMode) {
    Write-Host "Source mode:          editable install from $DevMode" -ForegroundColor Green
} else {
    Write-Host "Source mode:          PyPI" -ForegroundColor Green
}
Write-Host ""
Write-Host "Next: 03-bootstrap-vault.ps1 -ServiceName <name> -OperatorPubkeyHex <128-hex>" -ForegroundColor Cyan
Write-Host ""
exit 0
