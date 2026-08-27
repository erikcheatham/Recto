#!/bin/zsh
# appstore_ios_build.sh — Recto Phone iOS App Store build.
#
# Produces a Distribution-signed .ipa ready for Transporter upload to
# App Store Connect. Sister of recto_ios_redeploy.sh (which produces a
# Development-signed .app for sideload to the test iPhone) — same
# project, different cert + profile + entitlements (production push
# gateway vs sandbox).
#
# Why this script exists:
#   PowerShell → SSH → zsh → MSBuild quoting is hell when the codesign
#   key name contains spaces + parentheses (the canonical Apple
#   Distribution identity is literally "Apple Distribution: <Name>
#   (<TeamID>)" — PowerShell tries to interpret the parens as
#   subexpression syntax when passed inline). Wrapping the dotnet
#   publish in a single-shell script keeps all literal strings on
#   the zsh side where they Just Work.
#
# Usage (from a Windows operator workstation via SSH):
#   ssh mac "bash ~/Recto/scripts/appstore_ios_build.sh"
#
# Usage (from MAC terminal directly):
#   bash ~/Recto/scripts/appstore_ios_build.sh
#
# Env-var overrides:
#   CODESIGN_KEY      — override auto-discovered Distribution cert name
#                       (full quoted-name form, including "(TeamID)")
#   CODESIGN_PROVISION — override auto-discovered App Store profile UUID
#   SKIP_KEYCHAIN_UNLOCK=1 — skip the keychain unlock + partition-list step
#                            (set this if your session already primed the
#                             keychain via Keychain Access app)
#
# Exit codes:
#   0 — success; .ipa path printed at end
#   1 — pre-flight failure (cert not found, profile not found, etc.)
#   2 — keychain ACL recovery step failed
#   3 — dotnet publish failed
#   4 — .ipa not located after build
set -e

# Resolve script's own directory + project paths.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_DIR="$REPO_ROOT/phone/RectoMAUIBlazor/Recto/Recto"
PROJECT_CSPROJ="$PROJECT_DIR/Recto.csproj"

if [[ ! -f "$PROJECT_CSPROJ" ]]; then
    echo "ERROR: Recto.csproj not found at $PROJECT_CSPROJ" >&2
    echo "       Expected repo layout: <repo>/phone/RectoMAUIBlazor/Recto/Recto/Recto.csproj" >&2
    exit 1
fi

echo "=================================================================="
echo "  Recto Phone iOS App Store build (Distribution-signed .ipa)"
echo "=================================================================="
echo "  Repo root:    $REPO_ROOT"
echo "  Project:      $PROJECT_CSPROJ"
echo "  HEAD:         $(cd "$REPO_ROOT" && git log -1 --oneline 2>/dev/null || echo 'not a git repo')"
echo ""

# -----------------------------------------------------------------
# Phase 1 — keychain ACL pre-flight
# -----------------------------------------------------------------
if [[ -z "${SKIP_KEYCHAIN_UNLOCK:-}" ]]; then
    echo "Phase 1 — unlock login keychain + set partition-list ACL"
    echo "          (set SKIP_KEYCHAIN_UNLOCK=1 to bypass)"
    # SSH-context detection: if SSH_CONNECTION is set AND no TTY,
    # security unlock-keychain will hang forever waiting for a
    # password prompt that SSH can't surface. Fail loud with
    # operator-actionable guidance rather than infinite-hang.
    if [[ -n "${SSH_CONNECTION:-}" ]] && [[ ! -t 0 ]]; then
        echo "  ERROR: detected non-TTY SSH session; security unlock-keychain" >&2
        echo "         would hang waiting for a stdin password prompt." >&2
        echo "         Two recovery paths:" >&2
        echo "         (a) Re-run from a local terminal on MAC (e.g. via Parsec)" >&2
        echo "             where the password prompt fires interactively. The" >&2
        echo "             script proceeds non-interactively from Phase 2 on." >&2
        echo "         (b) Pre-unlock the keychain via local terminal:" >&2
        echo "                 security unlock-keychain ~/Library/Keychains/login.keychain-db" >&2
        echo "             then re-run this script with SKIP_KEYCHAIN_UNLOCK=1." >&2
        exit 2
    fi
    if ! security unlock-keychain "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null; then
        echo "  WARN: unlock-keychain prompted for password (or failed)."
        echo "        If running over SSH and unlock failed, the script can't"
        echo "        proceed without an interactive prompt. Run via Parsec"
        echo "        OR pre-unlock the keychain in your session OR set"
        echo "        SKIP_KEYCHAIN_UNLOCK=1 if the keychain is already unlocked."
        exit 2
    fi
    if ! security set-key-partition-list \
        -S apple-tool:,apple:,codesign: \
        -s "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1; then
        echo "  WARN: set-key-partition-list failed (may have been prompted for password)."
    fi
    echo "  OK   keychain unlocked + partition-list granted"
    echo ""
fi

# -----------------------------------------------------------------
# Phase 2 — discover Apple Distribution cert
# -----------------------------------------------------------------
echo "Phase 2 — locate Apple Distribution signing identity"
if [[ -n "${CODESIGN_KEY:-}" ]]; then
    CERT_NAME="$CODESIGN_KEY"
    echo "  Using env-var override: $CERT_NAME"
else
    # Find first Apple Distribution cert. The output line shape is:
    #   N) <SHA1> "Apple Distribution: <Name> (<TeamID>)"
    CERT_LINE="$(security find-identity -p codesigning -v | grep 'Apple Distribution' | head -1)"
    if [[ -z "$CERT_LINE" ]]; then
        echo "  ERROR: no 'Apple Distribution' identity found in codesigning keychain." >&2
        echo "         Verify the cert is installed: 'security find-identity -p codesigning -v'" >&2
        exit 1
    fi
    # Extract the quoted cert name from the line.
    CERT_NAME="$(echo "$CERT_LINE" | sed -E 's/.*"(Apple Distribution[^"]+)".*/\1/')"
    echo "  Found: $CERT_NAME"
fi
echo ""

# -----------------------------------------------------------------
# Phase 3 — discover App Store provisioning profile
# -----------------------------------------------------------------
echo "Phase 3 — locate App Store provisioning profile"
if [[ -n "${CODESIGN_PROVISION:-}" ]]; then
    PROFILE_UUID="$CODESIGN_PROVISION"
    echo "  Using env-var override: $PROFILE_UUID"
else
    PROFILE_DIR="$HOME/Library/MobileDevice/Provisioning Profiles"
    if [[ ! -d "$PROFILE_DIR" ]]; then
        echo "  ERROR: provisioning profile directory not found at:" >&2
        echo "    $PROFILE_DIR" >&2
        exit 1
    fi
    # App Store profiles have get-task-allow=false in their entitlements;
    # Dev profiles have get-task-allow=true. Iterate + pick the false one.
    PROFILE_UUID=""
    PROFILE_NAME=""
    PROFILE_PATH=""
    for p in "$PROFILE_DIR"/*.mobileprovision; do
        [[ -f "$p" ]] || continue
        get_task_allow="$(security cms -D -i "$p" 2>/dev/null | plutil -extract 'Entitlements.get-task-allow' raw - 2>/dev/null || echo "unknown")"
        if [[ "$get_task_allow" == "false" ]]; then
            name="$(security cms -D -i "$p" 2>/dev/null | plutil -extract Name raw - 2>/dev/null)"
            uuid="$(security cms -D -i "$p" 2>/dev/null | plutil -extract UUID raw - 2>/dev/null)"
            PROFILE_UUID="$uuid"
            PROFILE_NAME="$name"
            PROFILE_PATH="$p"
            break
        fi
    done
    if [[ -z "$PROFILE_UUID" ]]; then
        echo "  ERROR: no App Store provisioning profile (get-task-allow=false) found in:" >&2
        echo "    $PROFILE_DIR" >&2
        echo "         Available profiles:" >&2
        for p in "$PROFILE_DIR"/*.mobileprovision; do
            [[ -f "$p" ]] || continue
            n="$(security cms -D -i "$p" 2>/dev/null | plutil -extract Name raw - 2>/dev/null)"
            gta="$(security cms -D -i "$p" 2>/dev/null | plutil -extract 'Entitlements.get-task-allow' raw - 2>/dev/null)"
            echo "    - $n  (get-task-allow=$gta)" >&2
        done
        echo "         Install the App Store profile via:" >&2
        echo "           1. developer.apple.com -> Profiles -> + -> App Store" >&2
        echo "           2. scp downloaded .mobileprovision to ~/Library/MobileDevice/Provisioning\\ Profiles/" >&2
        exit 1
    fi
    echo "  Found: $PROFILE_NAME"
    echo "  UUID:  $PROFILE_UUID"
    echo "  Path:  $PROFILE_PATH"
fi
echo ""

# -----------------------------------------------------------------
# Phase 4 — dotnet publish
# -----------------------------------------------------------------
echo "Phase 4 — dotnet publish (net10.0-ios, Release, ios-arm64)"
echo "          Cert:    $CERT_NAME"
echo "          Profile: $PROFILE_UUID"
echo ""

cd "$PROJECT_DIR"

if ! dotnet publish Recto.csproj \
    -f net10.0-ios \
    -c Release \
    -r ios-arm64 \
    "/p:CodesignKey=$CERT_NAME" \
    "/p:CodesignProvision=$PROFILE_UUID" \
    /p:ArchiveOnBuild=true; then
    echo "" >&2
    echo "ABORT: dotnet publish failed." >&2
    echo "       Common causes:" >&2
    echo "       (a) errSecInternalComponent during codesign — keychain ACL" >&2
    echo "           layer 2 (per-key Allow-all) needs Parsec GUI ceremony." >&2
    echo "           See Recto/CLAUDE.md gotchas index 'codesign returns" >&2
    echo "           errSecInternalComponent'." >&2
    echo "       (b) MT7137 entitlements/profile mismatch — verify the App" >&2
    echo "           Store profile (not Dev) has aps-environment=production." >&2
    echo "       (c) cert/profile chain broken — re-verify via 'security" >&2
    echo "           find-identity -p codesigning -v'." >&2
    exit 3
fi

echo ""
echo "=================================================================="

# -----------------------------------------------------------------
# Phase 5 — locate produced .ipa
# -----------------------------------------------------------------
echo "Phase 5 — locate produced .ipa"
IPA_PATH="$(find "$PROJECT_DIR/bin/Release/net10.0-ios" -name '*.ipa' -mmin -10 2>/dev/null | head -1)"
if [[ -z "$IPA_PATH" ]]; then
    echo "  ERROR: no .ipa produced in the last 10 minutes under" >&2
    echo "    $PROJECT_DIR/bin/Release/net10.0-ios/" >&2
    echo "         Listing all .ipa under the project tree:" >&2
    find "$PROJECT_DIR" -name '*.ipa' 2>/dev/null >&2 || true
    exit 4
fi

IPA_SIZE_MB="$(du -m "$IPA_PATH" | cut -f1)"
echo "  IPA: $IPA_PATH"
echo "  Size: ${IPA_SIZE_MB} MB"
echo ""
echo "=================================================================="
echo "  SUCCESS — .ipa ready for Transporter upload."
echo "=================================================================="
echo ""
echo "Next steps:"
echo "  1. Open Transporter on MAC (Mac App Store -> Transporter)."
echo "  2. Drag the .ipa into the drop zone:"
echo "       $IPA_PATH"
echo "  3. Optional: click Validate."
echo "  4. Click Deliver. Upload ~30s for ~12 MB binary."
echo "  5. App Store Connect -> TestFlight -> wait 10-30 min for"
echo "     'Processing' to clear."
echo "  6. App Store Connect -> Apps -> Recto Phone -> rejected"
echo "     version 1.0 -> hover-remove build 2 -> Add Build (3) ->"
echo "     paste demo-flow note into App Review Information notes ->"
echo "     Resubmit for review."
