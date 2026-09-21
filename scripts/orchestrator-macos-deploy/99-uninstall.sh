#!/usr/bin/env bash
# 99-uninstall.sh — Clean teardown of a Recto-supervised service (macOS).
#
# Boots the daemon out of launchd, removes the plist + the per-service
# launcher-wrapper script, optionally removes vault / venv / logs.
# KEEPS vault by default (vault contents may be precious); explicit
# opt-in via --remove-vault for full destruction. Removes venv unless
# --keep-venv (with sibling-service safety check). Removes logs unless
# --keep-logs.
#
# Usage:
#   sudo bash ./99-uninstall.sh --service-name my-consumer
#   sudo bash ./99-uninstall.sh --service-name my-consumer --remove-vault
#   sudo bash ./99-uninstall.sh --service-name my-consumer --keep-venv --keep-logs
#
# Flags:
#   --service-name <name>   Service name to remove.
#   --install-path <path>   Where the Recto venv lives. Default: /usr/local/opt/recto.
#   --vault-root <path>     Vault directory root. Default: /usr/local/var/lib/recto.
#   --label-prefix <prefix> launchd Label prefix. Default: "com.recto".
#                           Full Label = "<prefix>.<service-name>".
#   --remove-vault          Also delete <vault-root>/<service-name>/.
#                           DEFAULT IS FALSE — vault contents may be
#                           precious + irreversible.
#   --keep-venv             Keep the venv intact. Default: removed (cheap
#                           to re-create via 02-create-venv.sh).
#   --keep-logs             Skip removing /var/log/recto/<service-name>/.
#                           Default: removed.
#   --force                 Skip the confirmation prompt.
#
# Exit codes:
#   0 — teardown completed
#   1 — service not found, or removal failed at some step

set -e

if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_DIM=""; C_RESET=""
fi

SERVICE_NAME=""
INSTALL_PATH="/usr/local/opt/recto"
VAULT_ROOT="/usr/local/var/lib/recto"
LABEL_PREFIX="com.recto"
REMOVE_VAULT="false"
KEEP_VENV="false"
KEEP_LOGS="false"
FORCE="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service-name)   SERVICE_NAME="$2"; shift 2 ;;
        --install-path)   INSTALL_PATH="$2"; shift 2 ;;
        --vault-root)     VAULT_ROOT="$2"; shift 2 ;;
        --label-prefix)   LABEL_PREFIX="$2"; shift 2 ;;
        --remove-vault)   REMOVE_VAULT="true"; shift ;;
        --keep-venv)      KEEP_VENV="true"; shift ;;
        --keep-logs)      KEEP_LOGS="true"; shift ;;
        --force)          FORCE="true"; shift ;;
        -h|--help)        grep -E "^# " "$0" | sed 's/^# //'; exit 0 ;;
        *)                echo "${C_RED}ERROR: unknown flag: $1${C_RESET}" >&2; exit 1 ;;
    esac
done

[[ -n "$SERVICE_NAME" ]] || { echo "${C_RED}ERROR: --service-name required${C_RESET}" >&2; exit 1; }

LABEL="${LABEL_PREFIX}.${SERVICE_NAME}"
PLIST_FILE="/Library/LaunchDaemons/${LABEL}.plist"
WRAPPER_PATH="$INSTALL_PATH/launcher-wrapper-${SERVICE_NAME}.sh"
VAULT_DIR="$VAULT_ROOT/$SERVICE_NAME"
VENV_PATH="$INSTALL_PATH/.venv"
LOG_DIR="/var/log/recto/$SERVICE_NAME"

echo ""
echo "${C_CYAN}Recto orchestrator-macos-deploy — uninstall '$SERVICE_NAME'${C_RESET}"
echo "${C_CYAN}=============================================================${C_RESET}"
echo ""

# ── Pre-flight summary ───────────────────────────────────────────────
echo "${C_YELLOW}Planned actions:${C_RESET}"
echo "${C_YELLOW}  - Bootout + remove launchd daemon '$LABEL'${C_RESET}"
echo "${C_YELLOW}  - Remove plist $PLIST_FILE${C_RESET}"
echo "${C_YELLOW}  - Remove wrapper script $WRAPPER_PATH${C_RESET}"
if [[ "$REMOVE_VAULT" == "true" ]]; then
    echo "${C_YELLOW}  - DELETE vault directory $VAULT_DIR (--remove-vault flag set)${C_RESET}"
else
    echo "${C_YELLOW}  - KEEP vault directory $VAULT_DIR (use --remove-vault to remove)${C_RESET}"
fi
if [[ "$KEEP_VENV" == "true" ]]; then
    echo "${C_YELLOW}  - KEEP venv at $VENV_PATH (--keep-venv flag set)${C_RESET}"
else
    echo "${C_YELLOW}  - DELETE venv at $VENV_PATH${C_RESET}"
fi
if [[ "$KEEP_LOGS" == "true" ]]; then
    echo "${C_YELLOW}  - KEEP logs at $LOG_DIR (--keep-logs flag set)${C_RESET}"
else
    echo "${C_YELLOW}  - REMOVE log directory $LOG_DIR${C_RESET}"
fi
echo ""

if [[ "$FORCE" != "true" ]]; then
    read -r -p "Proceed? Type 'yes' to confirm, anything else to abort: " RESPONSE
    if [[ "$RESPONSE" != "yes" ]]; then
        echo "${C_CYAN}Aborted. No changes made.${C_RESET}"
        exit 0
    fi
    echo ""
fi

declare -a REMOVED=()
declare -a KEPT=()
declare -a FAILED=()

# ── Step 1: Bootout + remove plist + wrapper ─────────────────────────
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    echo "${C_CYAN}Booting out daemon '$LABEL' from launchd...${C_RESET}"
    launchctl bootout "system/$LABEL" 2>&1 | sed 's/^/  /' || true
    sleep 2
fi
if [[ -f "$PLIST_FILE" ]]; then
    rm -f "$PLIST_FILE"
    REMOVED+=("launchd plist $PLIST_FILE")
    echo "${C_GREEN}Removed plist: $PLIST_FILE${C_RESET}"
else
    KEPT+=("launchd plist (not present at $PLIST_FILE)")
fi
if [[ -f "$WRAPPER_PATH" ]]; then
    rm -f "$WRAPPER_PATH"
    REMOVED+=("Wrapper script $WRAPPER_PATH")
    echo "${C_GREEN}Removed wrapper: $WRAPPER_PATH${C_RESET}"
else
    KEPT+=("Wrapper script (not present at $WRAPPER_PATH)")
fi

# ── Step 2: Vault directory ──────────────────────────────────────────
if [[ "$REMOVE_VAULT" == "true" ]]; then
    if [[ -d "$VAULT_DIR" ]]; then
        if rm -rf "$VAULT_DIR"; then
            REMOVED+=("Vault directory $VAULT_DIR")
            echo "${C_GREEN}Removed vault directory: $VAULT_DIR${C_RESET}"
        else
            FAILED+=("Vault directory removal ($VAULT_DIR)")
            echo "${C_RED}ERROR: vault directory removal failed.${C_RESET}"
        fi
    else
        KEPT+=("Vault directory (not present at $VAULT_DIR)")
    fi
else
    if [[ -d "$VAULT_DIR" ]]; then
        KEPT+=("Vault directory $VAULT_DIR (use --remove-vault to remove)")
        echo "${C_DIM}Kept vault directory: $VAULT_DIR${C_RESET}"
    fi
fi

# ── Step 3: Venv ─────────────────────────────────────────────────────
if [[ "$KEEP_VENV" == "true" ]]; then
    KEPT+=("Venv $VENV_PATH (--keep-venv flag set)")
else
    if [[ -d "$VENV_PATH" ]]; then
        # Defensive sibling-service safety check
        OTHER_PLISTS=$(find /Library/LaunchDaemons/ -maxdepth 1 -name "${LABEL_PREFIX}.*.plist" -not -name "${LABEL}.plist" -exec grep -l "$VENV_PATH" {} \; 2>/dev/null)
        if [[ -n "$OTHER_PLISTS" ]]; then
            echo "${C_YELLOW}WARNING: other launchd plists reference this venv:${C_RESET}"
            echo "$OTHER_PLISTS" | sed 's/^/  /'
            echo "${C_YELLOW}         Removing the venv will break those services. Skipping venv removal — pass --keep-venv to silence this warning.${C_RESET}"
            KEPT+=("Venv $VENV_PATH (preserved due to sibling services)")
        else
            if rm -rf "$VENV_PATH"; then
                REMOVED+=("Venv $VENV_PATH")
                echo "${C_GREEN}Removed venv: $VENV_PATH${C_RESET}"
            else
                FAILED+=("Venv removal ($VENV_PATH)")
            fi
        fi
    else
        KEPT+=("Venv (not present at $VENV_PATH)")
    fi
fi

# ── Step 4: Log directory ────────────────────────────────────────────
if [[ "$KEEP_LOGS" == "true" ]]; then
    KEPT+=("Log directory $LOG_DIR (--keep-logs flag set)")
else
    if [[ -d "$LOG_DIR" ]]; then
        if rm -rf "$LOG_DIR"; then
            REMOVED+=("Log directory $LOG_DIR")
            echo "${C_GREEN}Removed log directory: $LOG_DIR${C_RESET}"
        else
            FAILED+=("Log directory removal ($LOG_DIR)")
        fi
    else
        KEPT+=("Log directory (not present at $LOG_DIR)")
    fi
fi

# ── Report ───────────────────────────────────────────────────────────
echo ""
echo "${C_CYAN}=============================================================${C_RESET}"
echo "${C_CYAN}Teardown report:${C_RESET}"
if [[ ${#REMOVED[@]} -gt 0 ]]; then
    echo ""
    echo "${C_GREEN}Removed:${C_RESET}"
    for r in "${REMOVED[@]}"; do echo "${C_GREEN}  - $r${C_RESET}"; done
fi
if [[ ${#KEPT[@]} -gt 0 ]]; then
    echo ""
    echo "${C_DIM}Kept:${C_RESET}"
    for k in "${KEPT[@]}"; do echo "${C_DIM}  - $k${C_RESET}"; done
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo ""
    echo "${C_RED}Failed:${C_RESET}"
    for f in "${FAILED[@]}"; do echo "${C_RED}  - $f${C_RESET}"; done
fi

echo ""
if [[ ${#FAILED[@]} -eq 0 ]]; then
    echo "${C_GREEN}Teardown complete. Re-create via 02-create-venv.sh if needed.${C_RESET}"
    echo ""
    exit 0
else
    echo "${C_RED}${#FAILED[@]} step(s) failed — see above. Some cleanup may need manual completion.${C_RESET}"
    echo ""
    exit 1
fi
