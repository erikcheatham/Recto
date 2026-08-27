# Recto bootloader — canonical Docker image.
#
# Ships the substrate-side bootloader as a containerized service.
# Consumers build this image AS-IS
# from their own docker-compose stack and personalize via env vars +
# bind-mounted manifests. The image stays consumer-agnostic; per-deploy
# specifics (which agents are registered, which AppContexts surface on
# the operator's phone, which devices-pair consumers the bootloader
# brokers for) flow in through `examples/run_bootloader_consumer.py`'s
# established env-var + JSON-manifest contract.
#
# Build context expectation
# =========================
# The Docker build context MUST be the Recto repo ROOT (NOT this
# `docker/bootloader/` folder), so the COPY directives below can reach
# the `recto/` package + `examples/` scripts. Canonical consumer-side
# invocation from a sibling-cloned `<your-app>/docker-compose.yml`:
#
#   bootloader:
#     build:
#       context: ../Recto                       # repo root, not subfolder
#       dockerfile: docker/bootloader/Dockerfile
#
# This shape lets the substrate stay packaged at canonical locations
# (`recto/`, `examples/run_bootloader_consumer.py`) and lets consumers
# personalize via compose-level wiring without forking any Recto file.
#
# Secrets path
# ============
# The container has NO access to the Windows DPAPI-machine vault that
# Recto's launcher uses on the host. Secrets MUST reach the container
# via the standard env-interpolation pattern your compose
# already uses for your other service secrets:
# Recto's host-side launcher decrypts the vault entries at your app's
# child-spawn, injects into the docker.exe process env, compose
# interpolates ${VAR:-} references onto the bootloader container's env.
# The launcher script reads from `token_env` (not `vault_service`) when
# operating inside the container.
#
# State persistence
# =================
# Named volume mounted at /var/lib/recto/bootloader/. The volume holds:
# master_identity.json, phones.json, sessions.json, pending_requests.jsonl,
# results.jsonl, revocations.json, vault_root.json. Volume's first-time
# initialization can be seeded by the operator-side migration script
# (docker/bootloader/migrate-state.sh) which copies an existing host
# directory into the fresh volume — typical case when migrating from
# launcher-supervised bootloader to docker-supervised bootloader.
#
# Async-update / Blue-Green discipline
# ====================================
# This image is the substrate-side primitive that lets ANY consumer
# adopt Blue/Green deploys for their bootloader: parallel-hostname
# during cutover, separated state volumes, side-by-side smoke against
# canonical-shape requests, decommission only after the rollback
# window closes. See ./README.md for the canonical cutover recipe.

FROM python:3.12-slim

# --- BUILD STAMP (2026-08-10) ----------------------------------------------
# Until now this image carried NO provenance whatsoever: __version__ is a
# static 0.1.0.dev0 stub, there was no revision label, no banner line and no
# version endpoint. The practical cost was concrete - a 2026-08-09 audit tried
# to answer "is the running bootloader built from before or after 08-05?" and
# could not, from outside OR inside the container. The answer was bracketed to
# a range of commits and left unproven, and a planned stale-build filter had
# nothing to filter on.
#
# Note WHY this defaults to "unknown" rather than being omitted when unset: an
# ABSENT label and a STALE label look identical from the outside, and that
# ambiguity is the whole defect being fixed here. "unknown" is a claim you can
# act on - it says nobody passed a revision - whereas a missing key makes you
# guess whether the image predates the stamp or the build just forgot.
#
# Falsifier (one command, from anywhere docker reaches the daemon):
#   docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' <image>
# It must print a sha that `git cat-file -t <sha>` resolves in a clone of
# this repository.
ARG RECTO_BUILD_REVISION="unknown"
ARG RECTO_BUILD_CREATED="unknown"

LABEL org.opencontainers.image.title="Recto bootloader" \
      org.opencontainers.image.description="Phone-enclave-rooted capability authorization substrate" \
      org.opencontainers.image.source="https://github.com/erikcheatham/Recto" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${RECTO_BUILD_REVISION}" \
      org.opencontainers.image.created="${RECTO_BUILD_CREATED}"

# Build-time arguments (default to most-likely values; consumers can
# override at build time if their deploy needs a tighter image).
ARG RECTO_EXTRAS="v0_4,ethereum,bitcoin,ed25519,tron"

# System deps: curl for the healthcheck primitive (cheaper than baking
# Python startup just to probe an HTTP endpoint), ca-certificates for
# any outbound TLS (e.g. dpapi-machine fallback's HTTPS calls land
# zero in production but the dep is too small to omit defensively).
# tini provides correct PID-1 signal handling for graceful shutdown
# on `docker stop` — the bootloader's serve_forever() loop catches
# KeyboardInterrupt cleanly when SIGINT propagates through.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Recto package installed editable from the build context (repo root).
# Editable install (`-e`) lets a future bind-mount-source workflow
# work without rebuilding — useful for substrate-side dev iteration.
# Production consumers can swap to `pip install .` (non-editable) by
# overriding RECTO_INSTALL_MODE at build time if image-size matters.
WORKDIR /opt/recto

# Copy only what the bootloader needs: pyproject.toml + the recto/
# package + the examples/ launcher. Phone-side MAUI source, tests/,
# scripts/, fake_phone.py, etc. are excluded via .dockerignore so
# build context transfer + image layer stay small.
COPY pyproject.toml README.md LICENSE ./
COPY recto/ ./recto/
COPY examples/ ./examples/

# Upgrade pip BEFORE the editable install. The base image
# (python:3.12-slim) ships pip 25.0.1 which has a known
# `InvalidVersion: 'dev'` bug in the metadata-consistency
# checker when iterating provided_extras on an editable
# install whose pyproject.toml declares a `[project.optional-
# dependencies] dev = [...]` group (which Recto does — pytest +
# mypy + ruff). pip 26.x fixes it. Canonical defense is the
# pip upgrade step ahead of any `pip install -e` against
# pyproject.toml; banked as a canonical consumer-side gotcha
# from the 2026-05-20 bootloader-dockerization cutover sprint
# where this same trap first surfaced on a downstream build.
#
# `--root-user-action=ignore` suppresses the cosmetic
# "Running pip as the 'root' user" warning since the build
# container runs as root by design; not an actual issue.
RUN pip install --no-cache-dir --upgrade pip --root-user-action=ignore

# Install Recto + the credential-kind extras the bootloader needs.
# `cryptography` (pulled via v0_4) is the only meaningful native dep;
# everything else in the extras is pure-Python stdlib or empty-list-
# gated. Wheel cache cleared post-install to keep the layer small.
RUN pip install --no-cache-dir -e ".[${RECTO_EXTRAS}]"

# Canonical paths inside the container. The state-dir + manifest mount
# points are the contract every consumer's compose file targets.
#
# RECTO_BOOTLOADER_STATE_DIR is the name the CODE actually reads
# (recto/bootloader/state.py default_state_dir) — added 2026-07-16
# after the staging wipe-loop hunt: RECTO_STATE_DIR alone was a
# docs-only name the state store never consulted, so pairings wrote
# to the container-layer home and died on every recreate. Both names
# stay exported: RECTO_STATE_DIR remains the documented mount-point
# contract (and the mkdir below), RECTO_BOOTLOADER_STATE_DIR is the
# one that makes the state store honor it.
ENV RECTO_STATE_DIR=/var/lib/recto/bootloader \
    RECTO_BOOTLOADER_STATE_DIR=/var/lib/recto/bootloader \
    RECTO_AGENTS_FILE=/etc/recto/agents.json \
    RECTO_DEVICES_PAIR_CONSUMERS_FILE=/etc/recto/devices-pair-consumers.json \
    RECTO_BIND_HOST=0.0.0.0 \
    RECTO_BIND_PORT=8765 \
    RECTO_BOOTLOADER_QUIET=1 \
    PYTHONUNBUFFERED=1 \
    RECTO_BUILD_REVISION=${RECTO_BUILD_REVISION} \
    RECTO_BUILD_CREATED=${RECTO_BUILD_CREATED}

# Ensure the state-dir + manifest-dir mountpoints exist at the image
# layer (volumes inherit ownership from the mountpoint dir's
# permissions; if either is absent at first-volume-init, Docker
# defaults to root-owned which is fine for the single-tenant
# substrate posture but worth being explicit about).
RUN mkdir -p ${RECTO_STATE_DIR} /etc/recto

# Healthcheck: hit the canonical /v0.4/health endpoint. Returns 200
# with {"ok":true,"bootloader_id":"...","v0_4_protocol":1} when the
# server is serving; any other state (port-closed, server-crashed,
# init-not-finished) trips. Cheaper than running Python just to probe,
# and exercises the actual HTTP serve path rather than just port-open
# like a TCP probe would.
#
# (Diagnosed 2026-06-02: prior probe URL
# /v0.4/capability/manifest is GUARANTEED 404 in the canonical state
# where the manifest isn't wired into the vault, which is the live
# posture for capability_request flows. /v0.4/health is the canonical
# health endpoint per .staging/CLAUDE.md smoke endpoints section —
# returns 200 with bootloader_id + ok:true + v0_4_protocol:1 from
# server.py:_handle_health. Swapping eliminates the cosmetic "Docker
# unhealthy" label that was firing every 30s × 25h despite the
# bootloader operating cleanly end-to-end. Application-state-vs-
# liveness conflation is a common docker-healthcheck anti-pattern;
# /v0.4/health is the right liveness probe.)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --silent --fail --max-time 4 \
        "http://localhost:${RECTO_BIND_PORT}/v0.4/health" \
        > /dev/null || exit 1

EXPOSE 8765

# tini as PID 1 handles SIGTERM → forward to the bootloader process,
# letting serve_forever()'s KeyboardInterrupt path close cleanly
# (preserves pending request state on shutdown rather than hard-kill).
ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["python", "/opt/recto/examples/run_bootloader_consumer.py"]
