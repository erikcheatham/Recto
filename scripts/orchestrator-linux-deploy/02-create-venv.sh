#!/usr/bin/env bash
# 02-create-venv.sh — Create Python venv + install Recto (Linux).
#
# Creates an isolated Python virtual environment at the operator-chosen
# install path, installs recto-core (or installs editable against a local
# Recto clone for dev iteration), and verifies the install. Idempotent.
#
# Usage:
#   sudo bash ./02-create-venv.sh                                        # default: /opt/recto, PyPI install
#   sudo bash ./02-create-venv.sh --install-path /srv/recto              # operator-chosen path
#   sudo bash ./02-create-venv.sh --dev-mode /home/eric/Recto            # editable install (dev workstation)
#   sudo bash ./02-create-venv.sh --recto-version 1.0.0                  # pin specific PyPI version
#
# Flags:
#   --install-path <path>   Where the venv lives. Default: /opt/recto
#   --dev-mode <path>       Path to a local Recto checkout. If set, runs
#                           `pip install -e .` against that path instead of
#                           pulling from PyPI. Use during dev iteration.
#   --recto-version <ver>   Pin to a specific PyPI version (e.g. "1.0.0").
#                           Ignored when --dev-mode is set.
#   --python-exe <path>     Override the Python executable used to create
#                           the venv. Default: discovered via python3 / python.
#
# Exit codes:
#   0 — venv created + Recto installed + import verified
#   1 — Python not found, venv creation failed, or pip install failed

set -e

# ── ANSI colors ──────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_DIM=""; C_RESET=""
fi

# ── Defaults ─────────────────────────────────────────────────────────
INSTALL_PATH="/opt/recto"
DEV_MODE=""
RECTO_VERSION=""
PYTHON_EXE=""

# ── Parse args ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-path)   INSTALL_PATH="$2"; shift 2 ;;
        --dev-mode)       DEV_MODE="$2"; shift 2 ;;
        --recto-version)  RECTO_VERSION="$2"; shift 2 ;;
        --python-exe)     PYTHON_EXE="$2"; shift 2 ;;
        -h|--help)
            grep -E "^# " "$0" | sed 's/^# //'
            exit 0
            ;;
        *)
            echo "${C_RED}ERROR: unknown flag: $1${C_RESET}" >&2
            echo "Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

echo ""
echo "${C_CYAN}Recto orchestrator-linux-deploy — venv + pip install${C_RESET}"
echo "${C_CYAN}========================================================${C_RESET}"
echo ""

# ── Locate Python ────────────────────────────────────────────────────
if [[ -z "$PYTHON_EXE" ]]; then
    for cand in python3 python; do
        if command -v "$cand" >/dev/null 2>&1; then
            ver_output=$("$cand" --version 2>&1)
            if [[ "$ver_output" =~ Python\ ([0-9]+)\.([0-9]+) ]]; then
                major="${BASH_REMATCH[1]}"
                minor="${BASH_REMATCH[2]}"
                if (( major > 3 )) || ( (( major == 3 )) && (( minor >= 10 )) ); then
                    PYTHON_EXE=$(command -v "$cand")
                    echo "${C_GREEN}Python: $ver_output at $PYTHON_EXE${C_RESET}"
                    break
                fi
            fi
        fi
    done
fi
if [[ -z "$PYTHON_EXE" ]]; then
    echo "${C_RED}ERROR: Python 3.10+ not found on PATH. Run 01-prerequisites.sh first.${C_RESET}" >&2
    exit 1
fi

# ── Create install directory ─────────────────────────────────────────
if [[ ! -d "$INSTALL_PATH" ]]; then
    mkdir -p "$INSTALL_PATH"
    echo "${C_GREEN}Created install directory: $INSTALL_PATH${C_RESET}"
else
    echo "${C_DIM}Install directory exists: $INSTALL_PATH${C_RESET}"
fi

# ── Create venv (idempotent) ─────────────────────────────────────────
VENV_PATH="$INSTALL_PATH/.venv"
VENV_PYTHON="$VENV_PATH/bin/python"
if [[ -x "$VENV_PYTHON" ]]; then
    echo "${C_DIM}Existing venv detected at $VENV_PATH; reusing.${C_RESET}"
else
    echo "${C_CYAN}Creating venv at $VENV_PATH...${C_RESET}"
    "$PYTHON_EXE" -m venv "$VENV_PATH"
    if [[ ! -x "$VENV_PYTHON" ]]; then
        echo "${C_RED}ERROR: venv creation failed.${C_RESET}" >&2
        exit 1
    fi
    echo "${C_GREEN}Venv created.${C_RESET}"
fi

# ── Upgrade pip + wheel ──────────────────────────────────────────────
echo "${C_CYAN}Upgrading pip + wheel in venv...${C_RESET}"
"$VENV_PYTHON" -m pip install --upgrade pip wheel 2>&1 | while IFS= read -r line; do
    if [[ "$line" =~ Successfully\ installed|Requirement\ already\ satisfied ]]; then
        echo "${C_DIM}  $line${C_RESET}"
    elif [[ "$line" =~ error|Error|ERROR ]]; then
        echo "${C_RED}  $line${C_RESET}"
    fi
done

# ── Install Recto ────────────────────────────────────────────────────
if [[ -n "$DEV_MODE" ]]; then
    if [[ ! -d "$DEV_MODE" ]]; then
        echo "${C_RED}ERROR: --dev-mode path does not exist: $DEV_MODE${C_RESET}" >&2
        exit 1
    fi
    if [[ ! -f "$DEV_MODE/pyproject.toml" ]]; then
        echo "${C_RED}ERROR: --dev-mode path doesn't look like a Recto checkout (no pyproject.toml): $DEV_MODE${C_RESET}" >&2
        exit 1
    fi
    echo "${C_CYAN}Installing Recto editable from $DEV_MODE...${C_RESET}"
    "$VENV_PYTHON" -m pip install -e "${DEV_MODE}[v0_4]"
else
    if [[ -n "$RECTO_VERSION" ]]; then
        PACKAGE_SPEC="recto-core[v0_4]==$RECTO_VERSION"
    else
        PACKAGE_SPEC="recto-core[v0_4]"
    fi
    echo "${C_CYAN}Installing $PACKAGE_SPEC from PyPI...${C_RESET}"
    "$VENV_PYTHON" -m pip install "$PACKAGE_SPEC"
fi

# ── Verify install ───────────────────────────────────────────────────
echo "${C_CYAN}Verifying Recto import...${C_RESET}"
INSTALLED_VERSION=$("$VENV_PYTHON" -c "import recto; print(recto.__version__)" 2>&1)
if [[ $? -ne 0 ]]; then
    echo "${C_RED}ERROR: Recto import failed:${C_RESET}" >&2
    echo "${C_RED}  $INSTALLED_VERSION${C_RESET}" >&2
    exit 1
fi
echo "${C_GREEN}Recto version: $INSTALLED_VERSION${C_RESET}"

# ── Report ───────────────────────────────────────────────────────────
echo ""
echo "${C_CYAN}========================================================${C_RESET}"
echo "${C_GREEN}Venv ready at:        $VENV_PATH${C_RESET}"
echo "${C_GREEN}Venv python:          $VENV_PYTHON${C_RESET}"
echo "${C_GREEN}Recto version:        $INSTALLED_VERSION${C_RESET}"
if [[ -n "$DEV_MODE" ]]; then
    echo "${C_GREEN}Source mode:          editable install from $DEV_MODE${C_RESET}"
else
    echo "${C_GREEN}Source mode:          PyPI${C_RESET}"
fi
echo ""
echo "${C_CYAN}Next: sudo bash ./03-bootstrap-vault.sh --service-name <name> --operator-pubkey-hex <128-hex>${C_RESET}"
echo ""
exit 0
