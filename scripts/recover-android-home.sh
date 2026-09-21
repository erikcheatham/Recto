#!/bin/bash
#
# recover-android-home.sh
#
# Recovers MAC's Android SDK toolchain wiring after sdkmanager installed
# packages to brew's default location (/opt/homebrew/share/android-
# commandlinetools/) instead of the originally-set $ANDROID_HOME at
# $HOME/Library/Android/sdk.
#
# Authored 2026-05-21 alongside the sdkmanager-ignores-ANDROID_HOME gotcha.
#
# Idempotent — safe to run multiple times.

set -e

echo ""
echo "================================================================"
echo "Android SDK recovery — re-point ANDROID_HOME at brew default"
echo "================================================================"
echo ""

# ----------------------------------------------------------------------
# Phase 1: Verify brew's android-commandlinetools install actually exists
# ----------------------------------------------------------------------
echo "[Phase 1/4] Verifying brew install location"
echo "----------------------------------------------------------------"
BREW_SDK="/opt/homebrew/share/android-commandlinetools"
if [ ! -d "$BREW_SDK" ]; then
  echo "ERROR: $BREW_SDK does not exist. android-commandlinetools install may have failed."
  echo "Re-run: brew install --cask android-commandlinetools"
  exit 1
fi
echo "Brew SDK directory exists: $BREW_SDK"
ls -la "$BREW_SDK"

# ----------------------------------------------------------------------
# Phase 2: Re-point ANDROID_HOME in ~/.zprofile
# ----------------------------------------------------------------------
echo ""
echo "[Phase 2/4] Re-pointing ANDROID_HOME in ~/.zprofile"
echo "----------------------------------------------------------------"

ZPROFILE="$HOME/.zprofile"

# Remove the stale ANDROID_HOME line (pointing at HOME/Library/Android/sdk)
# Note: sed -i '' is BSD/macOS syntax; needs empty-string backup arg
sed -i '' '/^export ANDROID_HOME="\$HOME\/Library\/Android\/sdk"$/d' "$ZPROFILE" 2>/dev/null || true
sed -i '' '/^export PATH="\$ANDROID_HOME\/cmdline-tools\/latest\/bin:\$ANDROID_HOME\/platform-tools:\$PATH"$/d' "$ZPROFILE" 2>/dev/null || true

# Add the corrected ANDROID_HOME pointing at brew's default
if ! grep -qxF "export ANDROID_HOME=\"$BREW_SDK\"" "$ZPROFILE"; then
  echo "" >> "$ZPROFILE"
  echo "# Android SDK home (recovered 2026-05-21 — brew's default location)" >> "$ZPROFILE"
  echo "export ANDROID_HOME=\"$BREW_SDK\"" >> "$ZPROFILE"
  echo "ANDROID_HOME export added to ~/.zprofile"
else
  echo "ANDROID_HOME already correctly set in ~/.zprofile"
fi

# Add PATH for cmdline-tools + platform-tools
PATH_LINE='export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"'
if ! grep -qxF "$PATH_LINE" "$ZPROFILE"; then
  echo "$PATH_LINE" >> "$ZPROFILE"
  echo "PATH export added to ~/.zprofile"
else
  echo "PATH export already present"
fi

# Source the updated profile so this session sees the changes
source "$ZPROFILE"
echo ""
echo "ANDROID_HOME (after recovery): $ANDROID_HOME"

# ----------------------------------------------------------------------
# Phase 3: Verify SDK contents are now findable
# ----------------------------------------------------------------------
echo ""
echo "[Phase 3/4] Verifying SDK layout"
echo "----------------------------------------------------------------"

echo ""
echo "=== Top-level SDK directory ==="
ls -la "$ANDROID_HOME"

echo ""
echo "=== cmdline-tools ==="
ls "$ANDROID_HOME/cmdline-tools" 2>/dev/null || echo "  (missing)"

echo ""
echo "=== platforms (expect android-35) ==="
ls "$ANDROID_HOME/platforms" 2>/dev/null || echo "  (missing — re-run sdkmanager install)"

echo ""
echo "=== build-tools (expect 35.0.0) ==="
ls "$ANDROID_HOME/build-tools" 2>/dev/null || echo "  (missing — re-run sdkmanager install)"

echo ""
echo "=== platform-tools (expect adb, fastboot, etc.) ==="
ls "$ANDROID_HOME/platform-tools" 2>/dev/null | head -10 || echo "  (missing — re-run sdkmanager install)"

# ----------------------------------------------------------------------
# Phase 4: Final toolchain verification
# ----------------------------------------------------------------------
echo ""
echo "[Phase 4/4] Final toolchain verification"
echo "----------------------------------------------------------------"

echo ""
echo "=== java ==="
java -version 2>&1 | head -3
which java

echo ""
echo "=== keytool ==="
which keytool

echo ""
echo "=== sdkmanager ==="
which sdkmanager

echo ""
echo "=== adb (from platform-tools) ==="
which adb 2>/dev/null || echo "  (not on PATH yet — open fresh shell to pick up changes)"

echo ""
echo "=== dotnet version ==="
dotnet --version

echo ""
echo "=== dotnet workloads (expect maui-android listed) ==="
dotnet workload list

echo ""
echo "================================================================"
echo "Recovery complete."
echo ""
echo "Next steps:"
echo "  1. Open a FRESH terminal to verify ANDROID_HOME persists across shells"
echo "  2. Generate upload keystore via the Parsec recipe in"
echo "     Recto/docs/app-store/play-store-submission.md"
echo "================================================================"
echo ""
