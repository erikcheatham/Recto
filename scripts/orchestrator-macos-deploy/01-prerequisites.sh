#!/usr/bin/env bash
# 01-prerequisites.sh — Host readiness check for Recto orchestrator on macOS.
#
# Verifies the macOS host can support a Recto-supervised orchestrator:
# root/sudo, macOS version, Python 3.10+, launchctl present, PyPI
# reachable, /Library and /usr/local/var writable. Structured PASS/FAIL.
# Idempotent.
#
# Usage:
#   sudo bash ./01-prerequisites.sh
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed

set +e

# ── ANSI colors ──────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_DIM=""; C_RESET=""
fi

declare -a CHECKS_NAME=()
declare -a CHECKS_PASS=()
declare -a CHECKS_DETAIL=()
declare -a CHECKS_REMEDIATION=()
FAIL_COUNT=0

add_check() {
    CHECKS_NAME+=("$1")
    CHECKS_PASS+=("$2")
    CHECKS_DETAIL+=("$3")
    CHECKS_REMEDIATION+=("$4")
    if [[ "$2" != "true" ]]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

echo ""
echo "${C_CYAN}Recto orchestrator-macos-deploy — prerequisites check${C_RESET}"
echo "${C_CYAN}========================================================${C_RESET}"
echo ""

# ── Check 1: Root / sudo ──────────────────────────────────────────────
if [[ "$EUID" -eq 0 ]]; then
    add_check "Root privileges" "true" "EUID=0" ""
else
    add_check "Root privileges" "false" \
        "EUID=$EUID (not root)" \
        "Re-run with sudo: sudo bash ./01-prerequisites.sh"
fi

# ── Check 2: macOS detected ──────────────────────────────────────────
MACOS_OK="false"
MACOS_DETAIL=""
if [[ "$(uname -s)" == "Darwin" ]]; then
    MACOS_VERSION=$(sw_vers -productVersion 2>/dev/null)
    MACOS_BUILD=$(sw_vers -buildVersion 2>/dev/null)
    if [[ -n "$MACOS_VERSION" ]]; then
        # Recto targets macOS 11 (Big Sur) and newer
        MAJOR=$(echo "$MACOS_VERSION" | cut -d. -f1)
        if [[ "$MAJOR" -ge 11 ]]; then
            MACOS_OK="true"
            MACOS_DETAIL="macOS $MACOS_VERSION (build $MACOS_BUILD)"
        else
            MACOS_DETAIL="macOS $MACOS_VERSION is older than 11 (Big Sur); Recto targets macOS 11+"
        fi
    else
        MACOS_DETAIL="uname says Darwin but sw_vers returned nothing"
    fi
else
    MACOS_DETAIL="uname -s reported '$(uname -s)', not Darwin — not macOS?"
fi
add_check "macOS version" "$MACOS_OK" "$MACOS_DETAIL" \
    "Recto targets macOS 11 (Big Sur) or newer. Older versions may work but are untested."

# ── Check 3: Architecture (informational) ────────────────────────────
ARCH=$(uname -m)
echo "${C_DIM}Architecture: $ARCH (Apple Silicon = arm64; Intel = x86_64)${C_RESET}"

# ── Check 4: Python 3.10+ ─────────────────────────────────────────────
PYTHON_EXE=""
PYTHON_VER_OK="false"
PYTHON_DETAIL=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        ver_output=$("$cand" --version 2>&1)
        if [[ "$ver_output" =~ Python\ ([0-9]+)\.([0-9]+) ]]; then
            major="${BASH_REMATCH[1]}"
            minor="${BASH_REMATCH[2]}"
            if (( major > 3 )) || ( (( major == 3 )) && (( minor >= 10 )) ); then
                PYTHON_EXE=$(command -v "$cand")
                PYTHON_VER_OK="true"
                PYTHON_DETAIL="$ver_output at $PYTHON_EXE"
                break
            else
                PYTHON_DETAIL="$ver_output is below 3.10 (at $(command -v "$cand"))"
            fi
        fi
    fi
done
if [[ -z "$PYTHON_EXE" && -z "$PYTHON_DETAIL" ]]; then
    PYTHON_DETAIL="no python3 / python found on PATH"
fi
add_check "Python 3.10+" "$PYTHON_VER_OK" "$PYTHON_DETAIL" \
    "Install Python 3.10+ via Homebrew: brew install python@3.12. Or use pyenv: pyenv install 3.12.0; pyenv global 3.12.0. macOS ships with python3 but it's often outdated."

# ── Check 5: venv available ──────────────────────────────────────────
VENV_OK="false"
VENV_DETAIL=""
if [[ -n "$PYTHON_EXE" ]]; then
    if "$PYTHON_EXE" -m venv --help >/dev/null 2>&1; then
        VENV_OK="true"
        VENV_DETAIL="$PYTHON_EXE -m venv responded OK"
    else
        VENV_DETAIL="$PYTHON_EXE -m venv failed"
    fi
else
    VENV_DETAIL="Python 3.10+ check failed; venv check skipped"
fi
add_check "python3 -m venv available" "$VENV_OK" "$VENV_DETAIL" \
    "The venv module ships with Python 3 by default. If it's missing, reinstall Python via Homebrew or pyenv."

# ── Check 6: launchctl present ───────────────────────────────────────
LAUNCHCTL_OK="false"
LAUNCHCTL_DETAIL=""
if command -v launchctl >/dev/null 2>&1; then
    # launchctl reports version with `launchctl version` (newer) or no easy version reporting
    LAUNCHCTL_OK="true"
    LAUNCHCTL_DETAIL="launchctl at $(command -v launchctl)"
else
    LAUNCHCTL_DETAIL="launchctl not on PATH (very unusual for macOS)"
fi
add_check "launchctl available" "$LAUNCHCTL_OK" "$LAUNCHCTL_DETAIL" \
    "launchctl is built into macOS. If it's missing, the system is broken — reinstall macOS."

# ── Check 7: PyPI reachable ──────────────────────────────────────────
PYPI_OK="false"
PYPI_DETAIL=""
if command -v curl >/dev/null 2>&1; then
    if curl --silent --fail --max-time 10 -o /dev/null https://pypi.org/simple/; then
        PYPI_OK="true"
        PYPI_DETAIL="https://pypi.org/simple/ returned 2xx"
    else
        PYPI_DETAIL="curl to https://pypi.org/simple/ failed"
    fi
else
    PYPI_DETAIL="curl not available (very unusual for macOS)"
fi
add_check "PyPI reachable" "$PYPI_OK" "$PYPI_DETAIL" \
    "Verify outbound HTTPS on port 443. If behind a proxy: export HTTPS_PROXY=http://proxy:port before running 02-create-venv.sh."

# ── Check 8: /Library/LaunchDaemons writable ─────────────────────────
LAUNCH_DAEMONS_DIR="/Library/LaunchDaemons"
LAUNCH_OK="false"
LAUNCH_DETAIL=""
if [[ -d "$LAUNCH_DAEMONS_DIR" && -w "$LAUNCH_DAEMONS_DIR" ]]; then
    LAUNCH_OK="true"
    LAUNCH_DETAIL="$LAUNCH_DAEMONS_DIR is writable"
else
    LAUNCH_DETAIL="$LAUNCH_DAEMONS_DIR is NOT writable (need root)"
fi
add_check "/Library/LaunchDaemons writable" "$LAUNCH_OK" "$LAUNCH_DETAIL" \
    "Verify the current process is root. System daemons require root-write access to /Library/LaunchDaemons/."

# ── Report ───────────────────────────────────────────────────────────
echo ""
for i in "${!CHECKS_NAME[@]}"; do
    name="${CHECKS_NAME[$i]}"
    passed="${CHECKS_PASS[$i]}"
    detail="${CHECKS_DETAIL[$i]}"
    remediation="${CHECKS_REMEDIATION[$i]}"
    if [[ "$passed" == "true" ]]; then
        echo "${C_GREEN}[PASS]${C_RESET} $name"
        [[ -n "$detail" ]] && echo "${C_DIM}       $detail${C_RESET}"
    else
        echo "${C_RED}[FAIL]${C_RESET} $name"
        [[ -n "$detail" ]] && echo "${C_YELLOW}       $detail${C_RESET}"
        [[ -n "$remediation" ]] && echo "${C_YELLOW}       Remediation: $remediation${C_RESET}"
    fi
done

echo ""
echo "${C_CYAN}========================================================${C_RESET}"
TOTAL=${#CHECKS_NAME[@]}
if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo "${C_GREEN}All $TOTAL prerequisite checks passed. Ready for 02-create-venv.sh.${C_RESET}"
    echo ""
    exit 0
else
    echo "${C_RED}$FAIL_COUNT of $TOTAL checks FAILED.${C_RESET}"
    echo ""
    exit 1
fi
