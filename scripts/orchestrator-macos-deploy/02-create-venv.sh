#!/usr/bin/env bash
# 02-create-venv.sh — Create Python venv + install Recto (macOS).
#
# Mirror of orchestrator-linux-deploy/02-create-venv.sh adapted for
# macOS. The venv-creation + pip-install logic is essentially identical
# (both Linux and macOS use POSIX paths + python3 + pip); only the
# default install path differs (Homebrew convention on macOS).
#
# Usage:
#   sudo bash ./02-create-venv.sh                                       # default: /usr/local/opt/recto, PyPI install
#   sudo bash ./02-create-venv.sh --install-path /opt/recto             # operator-chosen path
#   sudo bash ./02-create-venv.sh --dev-mode /Users/eric/Recto          # editable install
#   sudo bash ./02-create-venv.sh --recto-version 1.0.0                 # pin PyPI version
#
# Exit codes: 0 = success, 1 = failure

set -e

if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_DIM=""; C_RESET=""
fi

INSTALL_PATH="/usr/local/opt/recto"
DEV_MODE=""
RECTO_VERSION=""
PYTHON_EXE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-path)   INSTALL_PATH="$2"; shift 2 ;;
        --dev-mode)       DEV_MODE="$2"; shift 2 ;;
        --recto-version)  RECTO_VERSION="$2"; shift 2 ;;
        --python-exe)     PYTHON_EXE="$2"; shift 2 ;;
        -h|--help)        grep -E "^# " "$0" | sed 's/^# //'; exit 0 ;;
        *)                echo "${C_RED}ERROR: unknown flag: $1${C_RESET}" >&2; exit 1 ;;
    esac
done

echo ""
echo "${C_CYAN}Recto orchestrator-macos-deploy — venv + pip install${C_RESET}"
echo "${C_CYAN}========================================================${C_RESET}"
echo ""

# Locate Python (prefer Homebrew at /opt/homebrew/bin/python3 on Apple Silicon,
# /usr/local/bin/python3 on Intel, /usr/bin/python3 system as fallback).
if [[ -z "$PYTHON_EXE" ]]; then
    for cand in /opt/homebrew/bin/python3 /usr/local/bin/python3 python3 python; do
        if [[ -x "$cand" ]] || command -v "$cand" >/dev/null 2>&1; then
            EXE_PATH=$(command -v "$cand" 2>/dev/null || echo "$cand")
            [[ -x "$EXE_PATH" ]] || continue
            ver_output=$("$EXE_PATH" --version 2>&1)
            if [[ "$ver_output" =~ Python\ ([0-9]+)\.([0-9]+) ]]; then
                major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"
                if (( major > 3 )) || ( (( major == 3 )) && (( minor >= 10 )) ); then
                    PYTHON_EXE="$EXE_PATH"
                    echo "${C_GREEN}Python: $ver_output at $PYTHON_EXE${C_RESET}"
                    break
                fi
            fi
        fi
    done
fi
if [[ -z "$PYTHON_EXE" ]]; then
    echo "${C_RED}ERROR: Python 3.10+ not found. Install via 'brew install python@3.12' or pyenv.${C_RESET}" >&2
    exit 1
fi

# Create install dir + venv
mkdir -p "$INSTALL_PATH"
VENV_PATH="$INSTALL_PATH/.venv"
VENV_PYTHON="$VENV_PATH/bin/python"
if [[ -x "$VENV_PYTHON" ]]; then
    echo "${C_DIM}Existing venv at $VENV_PATH; reusing.${C_RESET}"
else
    echo "${C_CYAN}Creating venv at $VENV_PATH...${C_RESET}"
    "$PYTHON_EXE" -m venv "$VENV_PATH"
    [[ -x "$VENV_PYTHON" ]] || { echo "${C_RED}ERROR: venv creation failed.${C_RESET}" >&2; exit 1; }
fi

# Upgrade pip + wheel
"$VENV_PYTHON" -m pip install --upgrade pip wheel >/dev/null

# Install Recto
if [[ -n "$DEV_MODE" ]]; then
    [[ -f "$DEV_MODE/pyproject.toml" ]] || { echo "${C_RED}ERROR: --dev-mode path doesn't look like a Recto checkout: $DEV_MODE${C_RESET}" >&2; exit 1; }
    echo "${C_CYAN}Installing Recto editable from $DEV_MODE...${C_RESET}"
    "$VENV_PYTHON" -m pip install -e "${DEV_MODE}[v0_4]"
else
    PACKAGE_SPEC="recto-core[v0_4]"
    [[ -n "$RECTO_VERSION" ]] && PACKAGE_SPEC="recto-core[v0_4]==$RECTO_VERSION"
    echo "${C_CYAN}Installing $PACKAGE_SPEC from PyPI...${C_RESET}"
    "$VENV_PYTHON" -m pip install "$PACKAGE_SPEC"
fi

# Verify
INSTALLED_VERSION=$("$VENV_PYTHON" -c "import recto; print(recto.__version__)" 2>&1)
[[ $? -eq 0 ]] || { echo "${C_RED}ERROR: Recto import failed: $INSTALLED_VERSION${C_RESET}" >&2; exit 1; }

echo ""
echo "${C_CYAN}========================================================${C_RESET}"
echo "${C_GREEN}Venv ready at:        $VENV_PATH${C_RESET}"
echo "${C_GREEN}Venv python:          $VENV_PYTHON${C_RESET}"
echo "${C_GREEN}Recto version:        $INSTALLED_VERSION${C_RESET}"
echo ""
echo "${C_CYAN}Next: sudo bash ./03-bootstrap-vault.sh --service-name <name> --operator-pubkey-hex <128-hex>${C_RESET}"
echo ""
exit 0
