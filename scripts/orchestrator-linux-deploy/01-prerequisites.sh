#!/usr/bin/env bash
# 01-prerequisites.sh — Host readiness check for Recto orchestrator on Linux.
#
# Verifies the Linux host can support a Recto-supervised orchestrator:
# root/sudo, Linux distro detection, Python 3.10+, systemd present,
# PyPI reachable, /var/lib/recto/ writable. Structured PASS/FAIL per
# check with remediation hints. Idempotent — safe to re-run.
#
# Usage:
#   sudo bash ./01-prerequisites.sh
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed

set +e  # We want to run ALL checks, not bail on first failure

# ── ANSI colors (degrade gracefully when not a TTY) ──────────────────
if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_DIM=""; C_RESET=""
fi

# ── State accumulators ───────────────────────────────────────────────
declare -a CHECKS_NAME=()
declare -a CHECKS_PASS=()
declare -a CHECKS_DETAIL=()
declare -a CHECKS_REMEDIATION=()
FAIL_COUNT=0

add_check() {
    local name="$1"
    local passed="$2"
    local detail="$3"
    local remediation="$4"
    CHECKS_NAME+=("$name")
    CHECKS_PASS+=("$passed")
    CHECKS_DETAIL+=("$detail")
    CHECKS_REMEDIATION+=("$remediation")
    if [[ "$passed" != "true" ]]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

echo ""
echo "${C_CYAN}Recto orchestrator-linux-deploy — prerequisites check${C_RESET}"
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

# ── Check 2: Linux distribution detected ──────────────────────────────
DISTRO_NAME="(unknown)"
DISTRO_DETECTED="false"
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_NAME="${PRETTY_NAME:-${NAME:-unknown}}"
    DISTRO_DETECTED="true"
fi
add_check "Linux distribution detected" "$DISTRO_DETECTED" \
    "$DISTRO_NAME" \
    "Cannot read /etc/os-release — non-standard Linux install. Recto targets systemd-based distros (Debian/Ubuntu/RHEL/Fedora/Arch); other init systems are untested."

# ── Check 3: Python 3.10+ ─────────────────────────────────────────────
PYTHON_EXE=""
PYTHON_VER_OK="false"
PYTHON_DETAIL=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        ver_output=$("$cand" --version 2>&1)
        # Match Python 3.10+
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
    "Install Python 3.10+ via your distro's package manager: apt install python3.10 (Debian/Ubuntu), dnf install python3 (RHEL/Fedora), pacman -S python (Arch). Verify with: python3 --version"

# ── Check 4: python3-venv module ──────────────────────────────────────
# Debian/Ubuntu split venv into a separate package (python3-venv). RHEL/Fedora
# ship it bundled. Detect by trying `python3 -m venv --help`.
VENV_OK="false"
VENV_DETAIL=""
if [[ -n "$PYTHON_EXE" ]]; then
    if "$PYTHON_EXE" -m venv --help >/dev/null 2>&1; then
        VENV_OK="true"
        VENV_DETAIL="$PYTHON_EXE -m venv responded OK"
    else
        VENV_DETAIL="$PYTHON_EXE -m venv failed (likely missing python3-venv package on Debian/Ubuntu)"
    fi
else
    VENV_DETAIL="Python 3.10+ check failed; venv check skipped"
fi
add_check "python3-venv module available" "$VENV_OK" "$VENV_DETAIL" \
    "On Debian/Ubuntu: apt install python3-venv. On RHEL/Fedora the venv module ships with python3 and should already work — if not, install python3-devel."

# ── Check 5: systemd present ──────────────────────────────────────────
SYSTEMD_OK="false"
SYSTEMD_DETAIL=""
if command -v systemctl >/dev/null 2>&1; then
    if [[ -d /run/systemd/system ]]; then
        SYSTEMD_VERSION=$(systemctl --version 2>/dev/null | head -1)
        SYSTEMD_OK="true"
        SYSTEMD_DETAIL="$SYSTEMD_VERSION"
    else
        SYSTEMD_DETAIL="systemctl binary present but /run/systemd/system missing — systemd not running as init?"
    fi
else
    SYSTEMD_DETAIL="systemctl not found on PATH"
fi
add_check "systemd available" "$SYSTEMD_OK" "$SYSTEMD_DETAIL" \
    "Recto's Linux reference deployment uses systemd. Non-systemd inits (openrc, runit, sysvinit) require operator-authored service-supervisor wrapping. Verify systemd via: ps -p 1 -o comm= (should print 'systemd')."

# ── Check 6: PyPI reachability ────────────────────────────────────────
PYPI_OK="false"
PYPI_DETAIL=""
if command -v curl >/dev/null 2>&1; then
    if curl --silent --fail --max-time 10 -o /dev/null https://pypi.org/simple/; then
        PYPI_OK="true"
        PYPI_DETAIL="https://pypi.org/simple/ returned 2xx"
    else
        PYPI_DETAIL="curl https://pypi.org/simple/ failed (network / proxy / DNS issue)"
    fi
elif command -v wget >/dev/null 2>&1; then
    if wget --quiet --timeout=10 --tries=1 -O /dev/null https://pypi.org/simple/; then
        PYPI_OK="true"
        PYPI_DETAIL="https://pypi.org/simple/ returned 2xx (via wget)"
    else
        PYPI_DETAIL="wget https://pypi.org/simple/ failed"
    fi
else
    PYPI_DETAIL="neither curl nor wget available; cannot verify PyPI reachability"
fi
add_check "PyPI reachable" "$PYPI_OK" "$PYPI_DETAIL" \
    "Verify outbound HTTPS on port 443. If behind a proxy: export HTTPS_PROXY=http://proxy:port before running 02-create-venv.sh. If using a private PyPI mirror, configure pip via /etc/pip.conf."

# ── Check 7: /var/lib/recto writable ─────────────────────────────────
# The Linux equivalent of C:\ProgramData\recto\<service>\ is
# /var/lib/recto/<service>/. Need root-write access here.
VAR_LIB_OK="false"
VAR_LIB_DETAIL=""
VAR_LIB_PARENT="/var/lib"
if [[ -w "$VAR_LIB_PARENT" ]]; then
    # Try a real-write smoke
    TEST_FILE="$VAR_LIB_PARENT/.recto-prereq-write-test-$$"
    if echo "test" > "$TEST_FILE" 2>/dev/null; then
        rm -f "$TEST_FILE"
        VAR_LIB_OK="true"
        VAR_LIB_DETAIL="$VAR_LIB_PARENT is writable"
    else
        VAR_LIB_DETAIL="$VAR_LIB_PARENT reports writable but file creation failed"
    fi
else
    VAR_LIB_DETAIL="$VAR_LIB_PARENT is NOT writable (need root)"
fi
add_check "/var/lib writable (vault dir target)" "$VAR_LIB_OK" "$VAR_LIB_DETAIL" \
    "Verify the current process is root. The vault directory at /var/lib/recto/<service>/ requires root-write access to create + chmod."

# ── Report ────────────────────────────────────────────────────────────
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
    echo "${C_RED}$FAIL_COUNT of $TOTAL checks FAILED. Address remediation hints before proceeding.${C_RESET}"
    echo ""
    exit 1
fi
