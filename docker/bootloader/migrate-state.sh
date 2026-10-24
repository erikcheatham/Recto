#!/usr/bin/env bash
# One-shot state migration: host directory → Docker named volume.
#
# Copies an existing host-mode bootloader's state directory (typically
# ~/.recto/bootloader/ on the operator's machine) into a Docker
# named volume, preserving the operator pubkey, paired phones,
# pending capability requests, vault_root.json, master_identity.json,
# and all other state files atomically.
#
# Used during the Blue-Green cutover from launcher-supervised
# bootloader to docker-supervised bootloader — the dockerized
# bootloader starts up with state IDENTICAL to the host-mode
# bootloader without requiring re-bootstrap or re-pair.
#
# Usage:
#   bash migrate-state.sh <source-host-path> <docker-volume-name>
#
# Example (Linux / macOS):
#   bash migrate-state.sh \
#       "$HOME/.recto/bootloader" \
#       "myapp_bootloader-data"
#
# Example (Git Bash / WSL on Windows):
#   bash migrate-state.sh \
#       "/c/Users/$USER/.recto/bootloader" \
#       "myapp_bootloader-data"
#
# Idempotency:
# Re-running on a volume that already has content is SAFE but NOT
# destructive — existing volume content is preserved (cp -n
# semantics). To force-overwrite, manually `docker volume rm` first.
#
# Safety:
# This script never touches the source host directory (read-only
# bind-mount). If anything goes wrong, the source state remains
# intact for fall-back to host-mode bootloader.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    cat <<EOF >&2
Usage: $0 <source-host-path> <docker-volume-name>

Arguments:
  source-host-path    Absolute or relative path to the existing
                      host-mode bootloader state directory. Typically
                      \$HOME/.recto/bootloader/ on the operator's
                      machine.
  docker-volume-name  The Docker named volume to seed. For
                      compose-managed volumes, this is
                      <project-prefix>_<volume-name>, e.g.
                      'myapp_bootloader-data'.

Examples:
  $0 "\$HOME/.recto/bootloader" "myapp_bootloader-data"
  $0 "/c/Users/<you>/.recto/bootloader" "myapp_bootloader-data"
EOF
    exit 2
fi

SOURCE_PATH="$1"
VOLUME_NAME="$2"

# Pre-flight checks.

if [[ ! -d "$SOURCE_PATH" ]]; then
    echo "ERROR: source path $SOURCE_PATH does not exist or is not a directory." >&2
    exit 1
fi

if [[ -z "$(ls -A "$SOURCE_PATH" 2>/dev/null)" ]]; then
    echo "ERROR: source path $SOURCE_PATH is empty. Nothing to migrate." >&2
    echo "If you intended a fresh start, just start the bootloader container without migration." >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker CLI not found in PATH." >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: docker daemon not reachable. Is Docker Desktop / Docker Engine running?" >&2
    exit 1
fi

# Ensure the destination volume exists. `docker volume create` is
# idempotent — creates if absent, no-op if present.
echo "[1/4] Ensuring Docker volume $VOLUME_NAME exists..."
docker volume create "$VOLUME_NAME" >/dev/null

# Inspect the volume — useful diagnostic so operator can confirm
# they're targeting the right volume (compose-prefixing is
# error-prone).
echo "[2/4] Volume inspection:"
docker volume inspect "$VOLUME_NAME" | grep -E '"Name"|"Mountpoint"|"Driver"' | sed 's/^/      /'

# Optional: check if the volume already has content. We don't bail
# on existing content — `cp -n` will preserve it — but we surface a
# warning so the operator knows.
echo "[3/4] Checking existing volume content..."
EXISTING_FILES=$(docker run --rm -v "$VOLUME_NAME:/v" alpine:latest ls -A /v 2>/dev/null || true)
if [[ -n "$EXISTING_FILES" ]]; then
    echo "      WARNING: volume $VOLUME_NAME already contains:"
    echo "$EXISTING_FILES" | sed 's/^/        - /'
    echo "      Migration will preserve existing files (cp -n semantics)."
    echo "      To force fresh migration, run: docker volume rm $VOLUME_NAME && $0 \"$SOURCE_PATH\" \"$VOLUME_NAME\""
    echo ""
fi

# Run the migration in a transient Alpine container.
# - Mount the source host path read-only at /src (defensive — we
#   never modify the original).
# - Mount the destination volume at /dst.
# - `cp -an /src/. /dst/` — archive-mode (preserves perms +
#   timestamps), don't-overwrite-existing (-n). The /src/. trailing
#   slash + dot copies the directory CONTENTS, not the directory
#   itself, so /dst/ ends up populated directly rather than nested
#   under /dst/bootloader/.
echo "[4/4] Copying state from $SOURCE_PATH to volume $VOLUME_NAME..."
docker run --rm \
    -v "$SOURCE_PATH:/src:ro" \
    -v "$VOLUME_NAME:/dst" \
    alpine:latest \
    sh -c 'cp -an /src/. /dst/ && echo "Migration complete. Volume contents:" && ls -la /dst/'

echo ""
echo "Migration complete. The dockerized bootloader can now start"
echo "against volume $VOLUME_NAME with state matching $SOURCE_PATH."
echo ""
echo "Next steps:"
echo "  1. Bring up the bootloader container: docker compose up -d bootloader"
echo "  2. Confirm 'operator pubkey loaded' appears in the startup banner:"
echo "     docker compose logs bootloader | head -30"
echo "  3. Run a side-by-side capability_request smoke against the new"
echo "     bootloader from your consumer's compose stack."
echo "  4. If the smoke is clean, you can confidently rollout-promote"
echo "     the dockerized bootloader to canonical hostname."
echo ""
echo "Rollback insurance: $SOURCE_PATH remains UNCHANGED — host-mode"
echo "bootloader can resume serving canonical traffic by simply"
echo "restarting it. Both state stores are valid."
