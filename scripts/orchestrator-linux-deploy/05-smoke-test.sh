#!/usr/bin/env bash
# 05-smoke-test.sh — End-to-end deployment verification (Linux).
#
# Starts the registered systemd service, waits for ActiveState=active,
# verifies the supervised python process is running, runs `recto vault
# status` to confirm vault decrypt, optionally hits a bootloader health
# endpoint. Each check produces a structured PASS/FAIL with remediation
# hints.
#
# Usage:
#   sudo bash ./05-smoke-test.sh --service-name my-consumer
#   sudo bash ./05-smoke-test.sh --service-name my-consumer \
#                                --bootloader-health-url http://localhost:8765/v0.4/health
#
# Flags:
#   --service-name <name>             Match what 04-register-service.sh used.
#   --install-path <path>             Where the Recto venv lives. Default: /opt/recto.
#   --bootloader-health-url <url>     HTTP URL of the bootloader's health
#                                     endpoint. Default: empty — skip the
#                                     probe.
#   --startup-grace-seconds <n>       Seconds to wait after systemctl start
#                                     before probing. Default: 15.
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

# ── State accumulators ───────────────────────────────────────────────
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

# ── Defaults ─────────────────────────────────────────────────────────
SERVICE_NAME=""
INSTALL_PATH="/opt/recto"
BOOTLOADER_HEALTH_URL=""
STARTUP_GRACE_SECONDS=15

# ── Parse args ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --service-name)           SERVICE_NAME="$2"; shift 2 ;;
        --install-path)           INSTALL_PATH="$2"; shift 2 ;;
        --bootloader-health-url)  BOOTLOADER_HEALTH_URL="$2"; shift 2 ;;
        --startup-grace-seconds)  STARTUP_GRACE_SECONDS="$2"; shift 2 ;;
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

echo ""
echo "${C_CYAN}Recto orchestrator-linux-deploy — smoke test${C_RESET}"
echo "${C_CYAN}=============================================${C_RESET}"
echo ""

# ── Check 1: Unit file exists ────────────────────────────────────────
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
if [[ -f "$UNIT_FILE" ]]; then
    add_check "systemd unit '$SERVICE_NAME' registered" "true" "Unit at $UNIT_FILE" ""
else
    add_check "systemd unit '$SERVICE_NAME' registered" "false" \
        "$UNIT_FILE not found" \
        "Run 04-register-service.sh first to generate the systemd unit."
    # Bail early
    for i in "${!CHECKS_NAME[@]}"; do
        echo "${C_RED}[FAIL]${C_RESET} ${CHECKS_NAME[$i]}"
        [[ -n "${CHECKS_DETAIL[$i]}" ]] && echo "${C_YELLOW}       ${CHECKS_DETAIL[$i]}${C_RESET}"
        [[ -n "${CHECKS_REMEDIATION[$i]}" ]] && echo "${C_YELLOW}       Remediation: ${CHECKS_REMEDIATION[$i]}${C_RESET}"
    done
    exit 1
fi

# ── Check 2: Start the service ───────────────────────────────────────
ACTIVE_STATE_RAW=$(systemctl is-active "$SERVICE_NAME" 2>&1)
START_OK="false"
START_DETAIL=""
if [[ "$ACTIVE_STATE_RAW" == "active" ]]; then
    START_OK="true"
    START_DETAIL="service was already Running; not restarting"
else
    systemctl start "$SERVICE_NAME"
    sleep "$STARTUP_GRACE_SECONDS"
    NEW_STATE=$(systemctl is-active "$SERVICE_NAME" 2>&1)
    if [[ "$NEW_STATE" == "active" ]]; then
        START_OK="true"
        START_DETAIL="post-start state: $NEW_STATE (waited ${STARTUP_GRACE_SECONDS}s)"
    else
        START_DETAIL="post-start state: $NEW_STATE (waited ${STARTUP_GRACE_SECONDS}s)"
    fi
fi
add_check "Service started" "$START_OK" "$START_DETAIL" \
    "Inspect journalctl -u $SERVICE_NAME -n 100 for spawn errors. Common causes: bad service-yaml path, missing vault entries, missing Python deps."

# ── Check 3: Child process running ───────────────────────────────────
CHILD_FOUND="false"
CHILD_DETAIL=""
CHILD_PIDS=$(pgrep -f "python.*-m recto launch" 2>/dev/null)
if [[ -n "$CHILD_PIDS" ]]; then
    # Take the first PID and report
    FIRST_PID=$(echo "$CHILD_PIDS" | head -1)
    FIRST_CMD=$(ps -p "$FIRST_PID" -o args= 2>/dev/null | head -c 150)
    CHILD_FOUND="true"
    CHILD_DETAIL="PID $FIRST_PID; cmdline: $FIRST_CMD..."
else
    CHILD_DETAIL="no python process with '-m recto launch' in cmdline found"
fi
add_check "Recto launcher child process running" "$CHILD_FOUND" "$CHILD_DETAIL" \
    "The systemd service may be Active but the launcher exited cleanly. Check journalctl -u $SERVICE_NAME for the exit reason."

# ── Check 4: Vault decryptable ───────────────────────────────────────
VENV_PYTHON="$INSTALL_PATH/.venv/bin/python"
VAULT_OK="false"
VAULT_DETAIL=""
if [[ -x "$VENV_PYTHON" ]]; then
    VAULT_OUTPUT=$("$VENV_PYTHON" -m recto vault status 2>&1)
    if echo "$VAULT_OUTPUT" | grep -qE "bootstrapped|operator pubkey:"; then
        VAULT_OK="true"
        # Strip ANSI codes if present + take first 200 chars
        CLEANED=$(echo "$VAULT_OUTPUT" | sed 's/\x1b\[[0-9;]*m//g' | head -c 200)
        VAULT_DETAIL="$CLEANED"
    else
        VAULT_DETAIL="vault status output did not contain 'bootstrapped' marker; output: $VAULT_OUTPUT"
    fi
else
    VAULT_DETAIL="venv python not found at $VENV_PYTHON"
fi
add_check "Vault is decryptable (operator pubkey installed)" "$VAULT_OK" "$VAULT_DETAIL" \
    "Re-run 03-bootstrap-vault.sh to install the operator pubkey."

# ── Check 5: Bootloader health endpoint (optional) ──────────────────
if [[ -n "$BOOTLOADER_HEALTH_URL" ]]; then
    HEALTH_OK="false"
    HEALTH_DETAIL=""
    if command -v curl >/dev/null 2>&1; then
        if curl --silent --fail --max-time 10 -o /dev/null "$BOOTLOADER_HEALTH_URL"; then
            HEALTH_OK="true"
            HEALTH_DETAIL="HTTP 2xx from $BOOTLOADER_HEALTH_URL"
        else
            HEALTH_DETAIL="curl to $BOOTLOADER_HEALTH_URL failed"
        fi
    else
        HEALTH_DETAIL="curl not available"
    fi
    add_check "Bootloader health endpoint reachable" "$HEALTH_OK" "$HEALTH_DETAIL" \
        "Verify the supervised service exposes a health endpoint at the URL passed. Check the service.yaml's exec: + healthz: blocks."
else
    echo "${C_DIM}(Skipping bootloader health check — --bootloader-health-url not provided)${C_RESET}"
fi

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
echo "${C_CYAN}=============================================${C_RESET}"
TOTAL=${#CHECKS_NAME[@]}
if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo "${C_GREEN}All $TOTAL smoke checks passed. Recto-supervised service '$SERVICE_NAME' is live.${C_RESET}"
    echo ""
    echo "${C_CYAN}Operator's next moves:${C_RESET}"
    echo "${C_CYAN}  - Pair phones via the Recto Phone app${C_RESET}"
    echo "${C_CYAN}  - Add secrets via .env edit OR python -m recto secrets set $SERVICE_NAME <name>${C_RESET}"
    echo "${C_CYAN}  - Tail logs: journalctl -u $SERVICE_NAME -f${C_RESET}"
    echo ""
    exit 0
else
    echo "${C_RED}$FAIL_COUNT of $TOTAL checks FAILED. Address remediation + re-run.${C_RESET}"
    echo ""
    exit 1
fi
