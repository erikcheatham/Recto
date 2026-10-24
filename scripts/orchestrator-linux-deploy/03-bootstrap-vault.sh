#!/usr/bin/env bash
# 03-bootstrap-vault.sh — Initialize vault + install operator pubkey (Linux).
#
# Creates the vault directory at /var/lib/recto/<service>/ with mode 0700
# (root-readable for systemd-managed services), runs `recto vault bootstrap
# <pubkey>` to install the operator's secp256k1 public key for capability-
# JWS verification. Optionally seeds an empty .env file with mode 0600
# for env-backend secret storage (the v1.0 Linux fallback until the
# v0.3 Secret Service backend ships).
#
# Usage:
#   sudo bash ./03-bootstrap-vault.sh \
#       --service-name my-consumer \
#       --operator-pubkey-hex "<128-hex-chars>"
#
# Flags:
#   --service-name <name>       Logical service name. Vault path becomes
#                               /var/lib/recto/<name>/.
#   --operator-pubkey-hex <hex> The operator's secp256k1 public key as 128
#                               hex chars (64 bytes uncompressed X||Y, no
#                               0x04 prefix). Paste from the phone enclave.
#   --install-path <path>       Where the Recto venv lives. Default: /opt/recto
#   --force                     Overwrite an existing operator pubkey.
#                               Defaults to false; `recto vault bootstrap`
#                               refuses to clobber without explicit --force.
#   --skip-env-seed             Don't create a .env stub in the vault dir.
#                               Default: a 0600-mode .env stub is created
#                               (empty file with a comment header) for
#                               env-backend secret storage.
#
# Exit codes:
#   0 — vault directory created/present + operator pubkey installed
#   1 — invalid pubkey format, mkdir failure, or `recto vault bootstrap`
#       exit non-zero

set -e

# ── ANSI colors ──────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_DIM=""; C_RESET=""
fi

# ── Defaults ─────────────────────────────────────────────────────────
SERVICE_NAME=""
OPERATOR_PUBKEY_HEX=""
INSTALL_PATH="/opt/recto"
FORCE_FLAG=""
SKIP_ENV_SEED="false"

# ── Parse args ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --service-name)         SERVICE_NAME="$2"; shift 2 ;;
        --operator-pubkey-hex)  OPERATOR_PUBKEY_HEX="$2"; shift 2 ;;
        --install-path)         INSTALL_PATH="$2"; shift 2 ;;
        --force)                FORCE_FLAG="--force"; shift ;;
        --skip-env-seed)        SKIP_ENV_SEED="true"; shift ;;
        -h|--help)
            grep -E "^# " "$0" | sed 's/^# //'
            exit 0
            ;;
        *)
            echo "${C_RED}ERROR: unknown flag: $1${C_RESET}" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$SERVICE_NAME" ]]; then
    echo "${C_RED}ERROR: --service-name is required.${C_RESET}" >&2
    exit 1
fi
if [[ -z "$OPERATOR_PUBKEY_HEX" ]]; then
    echo "${C_RED}ERROR: --operator-pubkey-hex is required.${C_RESET}" >&2
    exit 1
fi

echo ""
echo "${C_CYAN}Recto orchestrator-linux-deploy — vault bootstrap${C_RESET}"
echo "${C_CYAN}========================================================${C_RESET}"
echo ""

# ── Validate pubkey shape ────────────────────────────────────────────
CLEANED="${OPERATOR_PUBKEY_HEX#0x}"
CLEANED="${CLEANED#0X}"
# Strip leading 04 if present (uncompressed-point form)
if [[ ${#CLEANED} -eq 130 && "${CLEANED:0:2}" =~ ^(04|0[4]) ]]; then
    CLEANED="${CLEANED:2}"
fi
if [[ ${#CLEANED} -ne 128 ]]; then
    echo "${C_RED}ERROR: --operator-pubkey-hex must be exactly 128 hex chars (64 bytes uncompressed X||Y).${C_RESET}" >&2
    echo "${C_YELLOW}       Got ${#CLEANED} chars after stripping optional 0x / 0x04 prefix.${C_RESET}" >&2
    exit 1
fi
if [[ ! "$CLEANED" =~ ^[0-9a-fA-F]{128}$ ]]; then
    echo "${C_RED}ERROR: --operator-pubkey-hex contains non-hex characters.${C_RESET}" >&2
    exit 1
fi
PUBKEY_FINGERPRINT="${CLEANED:0:8}...${CLEANED: -8}"
echo "${C_GREEN}Pubkey validated: 128 hex chars (64 bytes X||Y form).${C_RESET}"
echo "${C_DIM}Pubkey fingerprint: $PUBKEY_FINGERPRINT${C_RESET}"

# ── Create vault directory ───────────────────────────────────────────
VAULT_ROOT="/var/lib/recto"
VAULT_DIR="$VAULT_ROOT/$SERVICE_NAME"
if [[ ! -d "$VAULT_ROOT" ]]; then
    mkdir -p "$VAULT_ROOT"
    chmod 0755 "$VAULT_ROOT"
    echo "${C_GREEN}Created vault root: $VAULT_ROOT (mode 0755)${C_RESET}"
fi
if [[ ! -d "$VAULT_DIR" ]]; then
    mkdir -p "$VAULT_DIR"
    chmod 0700 "$VAULT_DIR"
    chown root:root "$VAULT_DIR"
    echo "${C_GREEN}Created service vault: $VAULT_DIR (mode 0700, owner root:root)${C_RESET}"
else
    chmod 0700 "$VAULT_DIR"
    chown root:root "$VAULT_DIR"
    echo "${C_DIM}Service vault exists: $VAULT_DIR (re-set mode 0700, owner root:root)${C_RESET}"
fi

# ── Optionally seed .env file for env-backend secret storage ─────────
if [[ "$SKIP_ENV_SEED" == "false" ]]; then
    ENV_FILE="$VAULT_DIR/.env"
    if [[ ! -f "$ENV_FILE" ]]; then
        cat > "$ENV_FILE" <<'ENV_EOF'
# Recto env-backend secret storage.
#
# This file is the v1.0 Linux fallback until the v0.3 Secret Service
# backend (recto.secrets.secretsvc) ships. Each line is KEY=VALUE.
# Lines starting with # are comments.
#
# Recto's launcher reads this file at child-spawn when the service.yaml
# declares `source: env` for a secret AND points env_file: at this path.
# See INTEGRATION.md for the YAML schema.
#
# SECURITY: this file should remain mode 0600 owned by root:root.
# Anyone who can read this file can read every secret here.
#
# Add KEY=VALUE lines below. Example:
#   ANTHROPIC_API_KEY=sk-ant-...
#   STRIPE_API_KEY=sk_live_...
ENV_EOF
        chmod 0600 "$ENV_FILE"
        chown root:root "$ENV_FILE"
        echo "${C_GREEN}Seeded env-backend file: $ENV_FILE (mode 0600, owner root:root)${C_RESET}"
    else
        chmod 0600 "$ENV_FILE"
        chown root:root "$ENV_FILE"
        echo "${C_DIM}Env-backend file exists: $ENV_FILE (re-set mode 0600)${C_RESET}"
    fi
fi

# ── Run `recto vault bootstrap` ──────────────────────────────────────
VENV_PYTHON="$INSTALL_PATH/.venv/bin/python"
if [[ ! -x "$VENV_PYTHON" ]]; then
    echo "${C_RED}ERROR: Recto venv not found at $VENV_PYTHON. Run 02-create-venv.sh first.${C_RESET}" >&2
    exit 1
fi

echo ""
echo "${C_CYAN}Running 'recto vault bootstrap'...${C_RESET}"
set +e
"$VENV_PYTHON" -m recto vault bootstrap "$CLEANED" $FORCE_FLAG 2>&1 | while IFS= read -r line; do
    if [[ "$line" =~ already\ bootstrapped|already\ configured ]]; then
        echo "${C_YELLOW}  $line${C_RESET}"
    elif [[ "$line" =~ bootstrap\ complete|installed|success ]]; then
        echo "${C_GREEN}  $line${C_RESET}"
    elif [[ "$line" =~ error|Error|ERROR|refuse ]]; then
        echo "${C_RED}  $line${C_RESET}"
    else
        echo "${C_DIM}  $line${C_RESET}"
    fi
done
RC=${PIPESTATUS[0]}
set -e

if [[ $RC -ne 0 ]]; then
    echo ""
    echo "${C_RED}ERROR: 'recto vault bootstrap' returned exit code $RC.${C_RESET}" >&2
    echo "${C_YELLOW}       If the vault is already bootstrapped with a different pubkey, re-run with --force to rotate.${C_RESET}" >&2
    exit 1
fi

# ── Verify via `recto vault status` ──────────────────────────────────
echo ""
echo "${C_CYAN}Verifying via 'recto vault status'...${C_RESET}"
"$VENV_PYTHON" -m recto vault status 2>&1 | while IFS= read -r line; do
    echo "${C_DIM}  $line${C_RESET}"
done || echo "${C_YELLOW}WARNING: 'recto vault status' returned non-zero. Bootstrap may have succeeded; investigate.${C_RESET}"

# ── Report ───────────────────────────────────────────────────────────
echo ""
echo "${C_CYAN}========================================================${C_RESET}"
echo "${C_GREEN}Vault root:           $VAULT_DIR (mode 0700, owner root:root)${C_RESET}"
echo "${C_GREEN}Operator pubkey:      $PUBKEY_FINGERPRINT (128-hex form, 64 bytes X||Y)${C_RESET}"
if [[ "$SKIP_ENV_SEED" == "false" ]]; then
    echo "${C_GREEN}Env-backend file:     $VAULT_DIR/.env (mode 0600)${C_RESET}"
fi
echo ""
echo "${C_GREEN}Vault is ready to hold secret entries for service '$SERVICE_NAME'.${C_RESET}"
echo "${C_GREEN}Operator can add secrets by editing $VAULT_DIR/.env directly OR via:${C_RESET}"
echo "${C_DIM}  python -m recto secrets set $SERVICE_NAME <name> --backend env${C_RESET}"
echo ""
echo "${C_CYAN}Next: sudo bash ./04-register-service.sh --service-name $SERVICE_NAME --service-yaml <path-to-yaml>${C_RESET}"
echo ""
exit 0
