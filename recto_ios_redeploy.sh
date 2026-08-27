#!/usr/bin/env bash
# recto_ios_redeploy.sh — pull origin/main, build, install on the test iPhone,
# and post the result to comms. Auto-detects the Recto checkout so it works
# whether the repo lives at ~/Recto or ~/Documents/GitHub/Recto.

set -uo pipefail
LOG=/tmp/recto-redeploy.log
: > "$LOG"

# ---------- helpers ----------------------------------------------------------

ts()  { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
hdr() {
  printf '\n==================================================================\n' | tee -a "$LOG"
  printf '  %s\n' "$*" | tee -a "$LOG"
  printf '==================================================================\n' | tee -a "$LOG"
}

post_comms() {
  # post_comms <subject> <status> <body>
  local subject="$1" status="$2" body="$3"
  if [ -z "${CF_ACCESS_CLIENT_ID:-}" ] || [ -z "${CF_ACCESS_CLIENT_SECRET:-}" ] || [ -z "${MYTRADINGAPP_PUSH_TOKEN:-}" ]; then
    say "comms env vars not set (CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET / MYTRADINGAPP_PUSH_TOKEN); skipping comms post."
    return 0
  fi
  python3 - "$subject" "$status" "$body" <<'PY' >>"$LOG" 2>&1
import json, os, sys, urllib.request
subject, status, body = sys.argv[1], sys.argv[2], sys.argv[3]
payload = {
    "to": "dev",
    "from": "mac",
    "subject": subject,
    "body": body,
    "context": {"project": "recto", "deploy_status": status},
}
req = urllib.request.Request(
    "https://mytradingapp.example.com/api/comms/send",
    data=json.dumps(payload).encode(),
    headers={
        "Content-Type": "application/json",
        "CF-Access-Client-Id": os.environ["CF_ACCESS_CLIENT_ID"],
        "CF-Access-Client-Secret": os.environ["CF_ACCESS_CLIENT_SECRET"],
        "X-MyTradingApp-Token": os.environ["MYTRADINGAPP_PUSH_TOKEN"],
    },
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        print("comms post:", r.status, r.read().decode()[:200])
except Exception as e:
    print("comms post failed:", e)
PY
}

abort() {
  local subject="$1"; shift
  local body="$*"
  say "ABORT: $subject"
  say "$body"
  post_comms "$subject" "failed" "$(tail -n 60 "$LOG")"
  exit 1
}

# ---------- locate the Recto checkout ---------------------------------------

CANDIDATES=(
  "$HOME/Recto"
  "$HOME/Documents/GitHub/Recto"
  "$HOME/recto"
  "$HOME/code/Recto"
  "$PWD"
)
RECTO_DIR=""
for d in "${CANDIDATES[@]}"; do
  if [ -d "$d/.git" ] && [ -d "$d/phone/RectoMAUIBlazor/Recto/Recto" ]; then
    RECTO_DIR="$d"
    break
  fi
done

if [ -z "$RECTO_DIR" ]; then
  abort "iOS redeploy: cannot find Recto checkout" \
    "Looked at: ${CANDIDATES[*]} — none had .git + phone/RectoMAUIBlazor/Recto/Recto/. Set RECTO_DIR=<abs path> and re-run."
fi

# allow override
RECTO_DIR="${RECTO_DIR_OVERRIDE:-$RECTO_DIR}"
say "Recto checkout: $RECTO_DIR"

# ---------- target device ----------------------------------------------------

UDID="${RECTO_IPHONE_UDID:-96049D88-3500-5664-87BF-30E577024F9D}"
say "Target iPhone UDID: $UDID"

# ---------- Build configuration ----------------------------------------------
#
# Default = Debug because dev-iPhone hands-on smoke testing needs entitlements
# matching the "Recto Phone Dev" provisioning profile that's installed on
# Erik's iPhone (development tier, aps-environment=development). The csproj's
# configuration-conditional <CodesignEntitlements> line picks:
#   Debug   -> Entitlements.plist          (aps-environment=development)
#   Release -> Entitlements.Release.plist  (aps-environment=production)
# Release builds with the Dev profile fail install with MT7137 entitlement
# mismatch + 0xe8008015 ApplicationVerificationFailed.
#
# Override RECTO_BUILD_CONFIG=Release ONLY for testing the production-build
# flow + only if the Distribution cert + App Store provisioning profile are
# installed AND the iPhone UDID is registered in the App Store profile's
# allowed-devices list (separate Apple Developer Program ceremony). For the
# canonical TestFlight / App Store upload path, use dotnet publish directly
# with explicit /p:CodesignKey + /p:CodesignProvision (not this script).
CONFIG="${RECTO_BUILD_CONFIG:-Debug}"
say "Build configuration: $CONFIG"

# ---------- Phase 1: git pull -----------------------------------------------
#
# Two escape hatches per the banked Recto gotcha (CLAUDE.md):
#   SKIP_PULL=1        skip the git pull entirely (deploy current local state)
#   RECTO_PAT=<token>  pull with embedded PAT (non-interactive SSH-friendly)
# Default GIT_TERMINAL_PROMPT=0 so the script surfaces a clean error instead
# of hanging forever on "Username for 'https://github.com':".

export GIT_TERMINAL_PROMPT="${GIT_TERMINAL_PROMPT:-0}"

hdr "Phase 1 — git pull origin main"
cd "$RECTO_DIR" || abort "iOS redeploy: cd failed" "Could not cd into $RECTO_DIR"

if [ "${SKIP_PULL:-0}" = "1" ]; then
  say "SKIP_PULL=1 set — using current local state, no git pull"
elif [ -n "${RECTO_PAT:-}" ]; then
  say "RECTO_PAT set — pulling with embedded PAT"
  ORIGIN_URL=$(git remote get-url origin)
  AUTH_URL=$(printf '%s' "$ORIGIN_URL" | sed "s#https://github.com/#https://x-access-token:${RECTO_PAT}@github.com/#")
  if ! git pull "$AUTH_URL" main 2>&1 | tee -a "$LOG"; then
    abort "iOS redeploy: git pull failed (PAT path)" "$(tail -n 40 "$LOG")"
  fi
else
  if ! git pull origin main 2>&1 | tee -a "$LOG"; then
    abort "iOS redeploy: git pull failed" "$(tail -n 40 "$LOG")
Hint: set SKIP_PULL=1 to deploy current local state, or
      set RECTO_PAT=<github_pat> to pull with embedded auth."
  fi
fi

TIP_SHA=$(git rev-parse --short HEAD)
TIP_SUBJECT=$(git log -1 --pretty=%s)
say "tip: $TIP_SHA -- $TIP_SUBJECT"

# ---------- Phase 2: dotnet publish -----------------------------------------

hdr "Phase 2 — dotnet publish (net10.0-ios, $CONFIG, ios-arm64)"
PROJ_DIR="$RECTO_DIR/phone/RectoMAUIBlazor/Recto/Recto"
cd "$PROJ_DIR" || abort "iOS redeploy: project cd failed" "Could not cd into $PROJ_DIR"

START=$(date +%s)
if ! dotnet publish -f net10.0-ios -c "$CONFIG" -r ios-arm64 -p:ArchiveOnBuild=true 2>&1 | tee -a "$LOG"; then
  abort "iOS redeploy: dotnet publish failed" "$(tail -n 80 "$LOG")"
fi
END=$(date +%s)
PUBLISH_SECS=$((END - START))
say "publish duration: ${PUBLISH_SECS}s"

# ---------- Phase 3: locate .ipa / .app and install -------------------------

hdr "Phase 3 — xcrun devicectl install"
PUB_ROOT="$PROJ_DIR/bin/$CONFIG/net10.0-ios/ios-arm64/publish"

ARTIFACT="$(find "$PUB_ROOT" -maxdepth 3 -name '*.ipa' 2>/dev/null | head -1)"
if [ -z "$ARTIFACT" ]; then
  ARTIFACT="$(find "$PUB_ROOT" -maxdepth 3 -name 'Recto.app' 2>/dev/null | head -1)"
fi
if [ -z "$ARTIFACT" ]; then
  abort "iOS redeploy: no install artifact" "No .ipa or Recto.app under $PUB_ROOT"
fi
ART_SIZE=$(du -sh "$ARTIFACT" | awk '{print $1}')
say "install artifact: $ARTIFACT ($ART_SIZE)"

if ! xcrun devicectl device install app --device "$UDID" "$ARTIFACT" 2>&1 | tee -a "$LOG"; then
  abort "iOS redeploy: install failed" "$(tail -n 40 "$LOG")"
fi

# ---------- Phase 4: report -------------------------------------------------

hdr "Phase 4 — report"
SUMMARY="redeploy ok at $(ts).
recto checkout: $RECTO_DIR
tip: $TIP_SHA — $TIP_SUBJECT
publish: ${PUBLISH_SECS}s
artifact: $ARTIFACT ($ART_SIZE)
udid: $UDID
"
say "$SUMMARY"
post_comms "iOS redeploy result" "success" "$SUMMARY"
exit 0
