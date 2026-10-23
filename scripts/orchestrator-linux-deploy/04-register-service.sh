#!/usr/bin/env bash
# 04-register-service.sh — Register the systemd-supervised service (Linux).
#
# Generates /etc/systemd/system/<service-name>.service pointing the
# venv's python at `-m recto launch <yaml>`, runs `systemctl daemon-reload`
# + `systemctl enable <service-name>`. Service stays STOPPED after this
# script — 05-smoke-test.sh starts it.
#
# Sister of orchestrator-windows-deploy/04-register-service.ps1 but using
# systemd unit files instead of NSSM. systemd handles supervision +
# restart policy + log forwarding to journald natively, so the unit file
# is shorter than its NSSM equivalent.
#
# Usage:
#   sudo bash ./04-register-service.sh \
#       --service-name my-consumer \
#       --service-yaml /opt/recto-deploy/my-consumer.service.yaml
#
#   # Or with a custom service account (least-privilege posture):
#   sudo bash ./04-register-service.sh \
#       --service-name my-consumer \
#       --service-yaml /opt/recto-deploy/my-consumer.service.yaml \
#       --user recto \
#       --group recto
#
# Flags:
#   --service-name <name>   Logical service name. Match what
#                           03-bootstrap-vault.sh used.
#   --service-yaml <path>   Absolute path to the service.yaml.
#   --install-path <path>   Where the Recto venv lives. Default: /opt/recto.
#   --user <name>           systemd User= (the service account). Default:
#                           root. For least-privilege, create a dedicated
#                           service account (useradd --system --shell /sbin/nologin recto)
#                           and pass --user recto.
#   --group <name>          systemd Group=. Default: matches --user.
#   --description <text>    systemd Description=. Default:
#                           "Recto-supervised service '$service-name'".
#   --env-file <path>       systemd EnvironmentFile=. If set, the unit
#                           file declares this path so systemd injects the
#                           .env contents into the supervised process's
#                           env. Default: /var/lib/recto/<service>/.env
#                           (matches the env-backend file 03-bootstrap-
#                           vault.sh seeded).
#   --restart-policy <p>    systemd Restart= value. Default: on-failure.
#                           Options: no, always, on-success, on-failure,
#                           on-abnormal, on-watchdog, on-abort.
#   --restart-sec <n>       systemd RestartSec= (seconds between restart
#                           attempts). Default: 5.
#
# Exit codes:
#   0 — unit file generated + daemon-reload + enabled
#   1 — venv not found, YAML not found, or systemctl command failed

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
SERVICE_YAML=""
INSTALL_PATH="/opt/recto"
SVC_USER="root"
SVC_GROUP=""
DESCRIPTION=""
ENV_FILE=""
RESTART_POLICY="on-failure"
RESTART_SEC="5"

# ── Parse args ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --service-name)    SERVICE_NAME="$2"; shift 2 ;;
        --service-yaml)    SERVICE_YAML="$2"; shift 2 ;;
        --install-path)    INSTALL_PATH="$2"; shift 2 ;;
        --user)            SVC_USER="$2"; shift 2 ;;
        --group)           SVC_GROUP="$2"; shift 2 ;;
        --description)     DESCRIPTION="$2"; shift 2 ;;
        --env-file)        ENV_FILE="$2"; shift 2 ;;
        --restart-policy)  RESTART_POLICY="$2"; shift 2 ;;
        --restart-sec)     RESTART_SEC="$2"; shift 2 ;;
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
if [[ -z "$SERVICE_YAML" ]]; then
    echo "${C_RED}ERROR: --service-yaml is required.${C_RESET}" >&2
    exit 1
fi

# Default group matches user
if [[ -z "$SVC_GROUP" ]]; then
    SVC_GROUP="$SVC_USER"
fi
# Default description
if [[ -z "$DESCRIPTION" ]]; then
    DESCRIPTION="Recto-supervised service '$SERVICE_NAME' (launcher reads $SERVICE_YAML)"
fi
# Default env-file
if [[ -z "$ENV_FILE" ]]; then
    ENV_FILE="/var/lib/recto/$SERVICE_NAME/.env"
fi

echo ""
echo "${C_CYAN}Recto orchestrator-linux-deploy — systemd unit registration${C_RESET}"
echo "${C_CYAN}=============================================================${C_RESET}"
echo ""

# ── Validate inputs ──────────────────────────────────────────────────
VENV_PYTHON="$INSTALL_PATH/.venv/bin/python"
if [[ ! -x "$VENV_PYTHON" ]]; then
    echo "${C_RED}ERROR: Recto venv not found at $VENV_PYTHON. Run 02-create-venv.sh first.${C_RESET}" >&2
    exit 1
fi
if [[ ! -f "$SERVICE_YAML" ]]; then
    echo "${C_RED}ERROR: ServiceYaml not found at $SERVICE_YAML.${C_RESET}" >&2
    echo "${C_YELLOW}       Author the YAML before registering. See INTEGRATION.md for the schema.${C_RESET}" >&2
    exit 1
fi
# Verify --user exists if not root
if [[ "$SVC_USER" != "root" ]]; then
    if ! id -u "$SVC_USER" >/dev/null 2>&1; then
        echo "${C_RED}ERROR: --user '$SVC_USER' does not exist on this host.${C_RESET}" >&2
        echo "${C_YELLOW}       Create the service account first:${C_RESET}" >&2
        echo "${C_YELLOW}       sudo useradd --system --no-create-home --shell /sbin/nologin --group $SVC_USER${C_RESET}" >&2
        exit 1
    fi
fi

# ── Check whether service already exists ─────────────────────────────
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
IS_UPDATE="false"
if [[ -f "$UNIT_FILE" ]]; then
    IS_UPDATE="true"
    echo "${C_YELLOW}Unit file exists at $UNIT_FILE; updating configuration.${C_RESET}"
    # Stop the service before rewriting the unit (avoids surprises when daemon-reload + restart later)
    if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
        echo "${C_CYAN}Stopping service for reconfiguration...${C_RESET}"
        systemctl stop "$SERVICE_NAME" || true
        sleep 2
    fi
else
    echo "${C_CYAN}Generating new systemd unit at $UNIT_FILE...${C_RESET}"
fi

# ── Build EnvironmentFile= directive (optional) ──────────────────────
ENV_FILE_DIRECTIVE=""
if [[ -f "$ENV_FILE" ]]; then
    # The `-` prefix makes systemd tolerant of a missing file at start time;
    # the file IS present, but using `-` lets future operators delete it without
    # systemd refusing to start.
    ENV_FILE_DIRECTIVE="EnvironmentFile=-$ENV_FILE"
    echo "${C_GREEN}Env file detected: $ENV_FILE — will be injected via systemd EnvironmentFile=.${C_RESET}"
else
    echo "${C_DIM}No env file at $ENV_FILE; unit will have no EnvironmentFile= directive.${C_RESET}"
fi

# ── Generate unit file ───────────────────────────────────────────────
cat > "$UNIT_FILE" <<UNIT_EOF
[Unit]
Description=$DESCRIPTION
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_GROUP
WorkingDirectory=$INSTALL_PATH
ExecStart=$VENV_PYTHON -m recto launch $SERVICE_YAML
Restart=$RESTART_POLICY
RestartSec=$RESTART_SEC
$ENV_FILE_DIRECTIVE

# Logging to journald (default; visible via journalctl -u $SERVICE_NAME).
StandardOutput=journal
StandardError=journal

# Hardening (defense-in-depth — adjust per service.yaml needs).
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# ReadWritePaths allowlist — by default just the install path + vault.
# Consumer-specific paths (e.g. /var/log/<app>/) need explicit entries.
ReadWritePaths=$INSTALL_PATH /var/lib/recto/$SERVICE_NAME

[Install]
WantedBy=multi-user.target
UNIT_EOF
chmod 0644 "$UNIT_FILE"

echo "${C_GREEN}Unit file written: $UNIT_FILE${C_RESET}"

# ── Daemon-reload + enable ───────────────────────────────────────────
echo "${C_CYAN}Running systemctl daemon-reload...${C_RESET}"
systemctl daemon-reload

echo "${C_CYAN}Enabling service for auto-start at boot...${C_RESET}"
systemctl enable "$SERVICE_NAME"

# ── Report ───────────────────────────────────────────────────────────
echo ""
echo "${C_CYAN}=============================================================${C_RESET}"
echo "${C_GREEN}Service:              $SERVICE_NAME ($(if [[ "$IS_UPDATE" == "true" ]]; then echo 'updated'; else echo 'newly registered'; fi))${C_RESET}"
echo "${C_GREEN}Unit file:            $UNIT_FILE${C_RESET}"
echo "${C_GREEN}ExecStart:            $VENV_PYTHON -m recto launch $SERVICE_YAML${C_RESET}"
echo "${C_GREEN}User / Group:         $SVC_USER / $SVC_GROUP${C_RESET}"
echo "${C_GREEN}Restart policy:       $RESTART_POLICY (after ${RESTART_SEC}s)${C_RESET}"
if [[ -n "$ENV_FILE_DIRECTIVE" ]]; then
    echo "${C_GREEN}Env file:             $ENV_FILE${C_RESET}"
fi
echo "${C_GREEN}Auto-start at boot:   enabled${C_RESET}"
echo "${C_GREEN}Logs:                 journalctl -u $SERVICE_NAME -f${C_RESET}"
echo ""
echo "${C_YELLOW}Service is registered + enabled but STOPPED. 05-smoke-test.sh starts it and verifies.${C_RESET}"
echo ""
echo "${C_CYAN}Next: sudo bash ./05-smoke-test.sh --service-name $SERVICE_NAME${C_RESET}"
echo ""
exit 0
