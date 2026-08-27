#!/usr/bin/env bash
# 03-bootstrap-vault.sh — Initialize vault + install operator pubkey (macOS).
#
# Creates the vault directory at /usr/local/var/lib/recto/<service>/
# (Homebrew convention — operator can override via --vault-root for
# /Library/Application Support/recto/<service>/ if preferred). Runs
# `recto vault bootstrap <pubkey>` to install the operator's secp256k1
# public key. Optionally seeds an empty .env file with mode 0600 for
# env-backend secret storage.
#
# Usage:
#   sudo bash ./03-bootstrap-vault.sh \
#       --service-name my-consumer \
#       --operator-pubkey-hex "<128-hex-chars>"
#
# Flags:
#   --service-name <name>       Logical service name. Required.
#   --operator-pubkey-hex <hex> 128-hex secp256k1 pubkey. Required.
#   --install-path <path>       Where Recto venv lives. Default: /usr/local/opt/recto.
#   --vault-root <path>         Vault directory root. Default: /usr/local/var/lib/recto.
#                               Alternative: /Library/Application\ Support/recto for
#                               operators preferring the macOS framework convention.
#   --force                     Overwrite an existing operator pubkey.
#   --skip-env-seed             Don't create the .env stub.
#
# Exit codes: 0 = success, 1 = failure

set -e

if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_DIM=""; C_RESET=""
fi

SERVICE_NAME=""
OPERATOR_PUBKEY_HEX=""
INSTALL_PATH="/usr/local/opt/recto"
VAULT_ROOT="/usr/local/var/lib/recto"
FORCE_FLAG=""
SKIP_ENV_SEED="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service-name)         SERVICE_NAME="$2"; shift 2 ;;
        --operator-pubkey-hex)  OPERATOR_PUBKEY_HEX="$2"; shift 2 ;;
        --install-path)         INSTALL_PATH="$2"; shift 2 ;;
        --vault-root)           VAULT_ROOT="$2"; shift 2 ;;
        --force)                FORCE_FLAG="--force"; shift ;;
        --skip-env-seed)        SKIP_ENV_SEED="true"; shift ;;
        -h|--help)              grep -E "^# " "$0" | sed 's/^# //'; exit 0 ;;
        *)                      echo "${C_RED}ERROR: unknown flag: $1${C_RESET}" >&2; exit 1 ;;
    esac
done

[[ -n "$SERVICE_NAME" ]] || { echo "${C_RED}ERROR: --service-name required${C_RESET}" >&2; exit 1; }
[[ -n "$OPERATOR_PUBKEY_HEX" ]] || { echo "${C_RED}ERROR: --operator-pubkey-hex required${C_RESET}" >&2; exit 1; }

echo ""
echo "${C_CYAN}Recto orchestrator-macos-deploy — vault bootstrap${C_RESET}"
echo "${C_CYAN}========================================================${C_RESET}"
echo ""

# Validate pubkey
CLEANED="${OPERATOR_PUBKEY_HEX#0x}"
CLEANED="${CLEANED#0X}"
[[ ${#CLEANED} -eq 130 && "${CLEANED:0:2}" =~ ^0[4] ]] && CLEANED="${CLEANED:2}"
[[ ${#CLEANED} -eq 128 ]] || { echo "${C_RED}ERROR: pubkey must be 128 hex chars (got ${#CLEANED})${C_RESET}" >&2; exit 1; }
[[ "$CLEANED" =~ ^[0-9a-fA-F]{128}$ ]] || { echo "${C_RED}ERROR: pubkey contains non-hex characters${C_RESET}" >&2; exit 1; }
PUBKEY_FINGERPRINT="${CLEANED:0:8}...${CLEANED: -8}"
echo "${C_GREEN}Pubkey validated. Fingerprint: $PUBKEY_FINGERPRINT${C_RESET}"

# Create vault dir
VAULT_DIR="$VAULT_ROOT/$SERVICE_NAME"
mkdir -p "$VAULT_ROOT"
mkdir -p "$VAULT_DIR"
chmod 0700 "$VAULT_DIR"
chown root:wheel "$VAULT_DIR"
echo "${C_GREEN}Service vault: $VAULT_DIR (mode 0700, owner root:wheel)${C_RESET}"

# Optionally seed .env
if [[ "$SKIP_ENV_SEED" == "false" ]]; then
    ENV_FILE="$VAULT_DIR/.env"
    if [[ ! -f "$ENV_FILE" ]]; then
        cat > "$ENV_FILE" <<'ENV_EOF'
# Recto env-backend secret storage (macOS v1.0 fallback).
# Each line is KEY=VALUE. Comments start with #.
# SECURITY: mode 0600 owned by root:wheel — anyone who reads this can read every secret here.
ENV_EOF
        chmod 0600 "$ENV_FILE"
        chown root:wheel "$ENV_FILE"
        echo "${C_GREEN}Seeded env-backend file: $ENV_FILE (mode 0600)${C_RESET}"
    else
        chmod 0600 "$ENV_FILE"
        chown root:wheel "$ENV_FILE"
        echo "${C_DIM}Env-backend file exists: $ENV_FILE (re-set 0600)${C_RESET}"
    fi
fi

# Run recto vault bootstrap
VENV_PYTHON="$INSTALL_PATH/.venv/bin/python"
[[ -x "$VENV_PYTHON" ]] || { echo "${C_RED}ERROR: venv not found at $VENV_PYTHON. Run 02-create-venv.sh first.${C_RESET}" >&2; exit 1; }

echo ""
echo "${C_CYAN}Running 'recto vault bootstrap'...${C_RESET}"
set +e
"$VENV_PYTHON" -m recto vault bootstrap "$CLEANED" $FORCE_FLAG 2>&1 | while IFS= read -r line; do
    if [[ "$line" =~ already\ bootstrapped|already\ configured ]]; then echo "${C_YELLOW}  $line${C_RESET}"
    elif [[ "$line" =~ bootstrap\ complete|installed|success ]]; then echo "${C_GREEN}  $line${C_RESET}"
    elif [[ "$line" =~ error|Error|ERROR|refuse ]]; then echo "${C_RED}  $line${C_RESET}"
    else echo "${C_DIM}  $line${C_RESET}"
    fi
done
RC=${PIPESTATUS[0]}
set -e

if [[ $RC -ne 0 ]]; then
    echo "${C_RED}ERROR: 'recto vault bootstrap' returned exit code $RC.${C_RESET}" >&2
    [[ -z "$FORCE_FLAG" ]] && echo "${C_YELLOW}       To rotate an already-bootstrapped vault, re-run with --force.${C_RESET}" >&2
    exit 1
fi

echo ""
echo "${C_CYAN}========================================================${C_RESET}"
echo "${C_GREEN}Vault root:           $VAULT_DIR${C_RESET}"
echo "${C_GREEN}Operator pubkey:      $PUBKEY_FINGERPRINT${C_RESET}"
[[ "$SKIP_ENV_SEED" == "false" ]] && echo "${C_GREEN}Env-backend file:     $VAULT_DIR/.env${C_RESET}"
echo ""
echo "${C_CYAN}Next: sudo bash ./04-register-service.sh --service-name $SERVICE_NAME --service-yaml <path>${C_RESET}"
echo ""
exit 0
