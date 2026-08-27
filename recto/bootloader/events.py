r"""Folder-drop event bus for the bootloader.

Substrate-side primitive for AI-to-AI peer communication via the
filesystem. The bootloader emits state-change events as JSONL files
to a configurable directory; application-host AIs on the same
filesystem (peer Cowork instances, openclaw skills, log aggregators,
audit watchers) tail-watch the daily files and react to events at
their own cadence — without polling Recto's HTTP surface.

Banked 2026-05-19 night, surfaced by the muse during the bootloader
dockerization design session. See ``Recto/CLAUDE.md`` "Folder-drop
event bus + filesystem-as-API extension" section for the architectural
commitment + the (A)/(B) framing distinction.

Architectural posture
=====================

Folder-drop is COMPLEMENTARY to the existing HTTP capability_request
flow, NOT a replacement. HTTP stays canonical for synchronous "I need
authority NOW" verbs. Folder-drop is for async "fyi, this happened"
notifications.

Each event is a single-line JSONL append to a daily-rotated file at
``<events_dir>/<YYYY-MM-DD>.jsonl``. Daily rotation keeps any single
file from growing unboundedly for long-running bootloaders; consumers
can read today's file + yesterday's file to cover the typical
catch-up window.

Event records carry:

- ``kind``       — event taxonomy (capability_approved, phone_paired, etc.)
- ``ts``         — emission timestamp (unix seconds, integer)
- ``ts_iso``     — same timestamp ISO-8601 for human readability
- ``bootloader`` — bootloader_id of the emitter (lets multi-bootloader
                   deployments distinguish event sources)
- ``payload``    — event-kind-specific dict; see EVENT_PAYLOAD_SHAPES below

Security posture
================

Events are NOTIFICATIONS, not capability assertions. The contents
have NO authority — a malicious consumer that writes fake JSONL into
the events folder can't escalate privileges, because no downstream
consumer treats event payloads as authoritative. Authority flows
exclusively through the HTTP capability_request → operator-phone-
approval → JWS chain per Hard Rule #9; folder-drop is downstream of
the authority decision, never upstream.

Folder permissions: the events directory MUST be writable by the
bootloader and readable by intended peer consumers. In the Docker
deployment, this is typically a bind-mount with container-uid =
peer-AI-host-uid alignment; for native deployments, standard POSIX
group permissions or Windows ACLs apply.

v1 scope (this module)
======================

Wires ONE canonical event-emission site: the existing
``notify_resolved_fn`` hook in ``create_server``. This covers
capability lifecycle events (capability_approved, capability_denied,
capability_signed for multi-coin sign kinds) without touching
``server.py``. Construct a FileEventEmitter, pass its ``__call__``
method as ``notify_resolved_fn`` to ``create_server``, and approved/
denied capability_requests emit JSONL events.

Future emission sites (follow-up sprints, banked separately):

- ``phone_paired``        — bootloader's pairing handshake completes
- ``phone_revoked``       — operator-trusted agent revokes a paired phone
- ``vault_bootstrapped``  — operator pubkey is written to vault_root.json
- ``capability_revoked``  — ``POST /v0.4/capability/revoke`` succeeds
- ``devices_paired``      — Phase-H end-user device pairing relays clean

Each follow-up adds one ``emitter.emit(kind, payload)`` call at the
matching site in ``server.py`` + an entry in EVENT_PAYLOAD_SHAPES
below. The emitter primitive doesn't need to change.

Disabling
=========

When ``RECTO_EVENTS_DIR`` env var is unset, the launcher does NOT
construct a FileEventEmitter and ``notify_resolved_fn`` stays at its
default (None). The bootloader's behavior is unchanged from the
pre-events-folder baseline. Opt-in is the deployment-time switch.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Event payload shapes documented here as the canonical schema.
# Consumers reading the JSONL files can rely on these field names
# being stable across Recto versions (additive-only changes;
# removals require a minor version bump).
EVENT_PAYLOAD_SHAPES: dict[str, dict[str, str]] = {
    "capability_approved": {
        "request_id": "str (uuid)",
        "agent_id": "str (the cap_agent_id that requested)",
        "purpose": "str (the human-readable purpose claim from the JWS)",
        "tier": "int (capability tier 0-3)",
        "allow_actions": "list[str] (the cap.allow_actions[] claim)",
        "jws_jti": "str (the assembled JWS's jti claim)",
        "approved_at_unix": "int",
    },
    "capability_denied": {
        "request_id": "str (uuid)",
        "agent_id": "str (the cap_agent_id that requested)",
        "purpose": "str",
        "tier": "int",
        "reason": "str (denial reason from the phone-side response)",
        "denied_at_unix": "int",
    },
    "sign_approved": {
        # Multi-coin sign kinds (eth_sign, btc_sign, ed_sign,
        # tron_sign, single_sign, etc.). Approval kinds OTHER than
        # capability_request resolve through the same notify path; we
        # emit a generic sign_approved event so audit watchers see ALL
        # operator approvals in one stream.
        "request_id": "str (uuid)",
        "kind": "str (the PendingRequest.kind value)",
        "approved_at_unix": "int",
    },
    "sign_denied": {
        "request_id": "str (uuid)",
        "kind": "str",
        "reason": "str",
        "denied_at_unix": "int",
    },
    # v1 future emission sites — listed here for schema-stability
    # guarantees; the emitter primitive supports them once the
    # corresponding server.py call sites land.
    "phone_paired": {
        "phone_id": "str (uuid)",
        "public_key_b64u": "str (base64url, no padding)",
        "algorithm": "str (ed25519 | ecdsa-p256)",
        "paired_at_unix": "int",
    },
    "phone_revoked": {
        "phone_id": "str (uuid)",
        "revoked_at_unix": "int",
    },
    "vault_bootstrapped": {
        "pubkey_hex": "str (128 hex chars, secp256k1 uncompressed without 0x04 prefix)",
        "bootstrapped_at_unix": "int",
    },
    "capability_revoked": {
        "jti": "str (the JWS jti claim that was revoked)",
        "original_exp_unix": "int (the revoked JWS's exp)",
        "revoked_at_unix": "int",
    },
    "devices_paired": {
        "consumer_base_url": "str",
        "master_pubkey_hex": "str (128 hex chars)",
        "paired_at_unix": "int",
    },
}


class FileEventEmitter:
    """Append JSONL events to a daily-rotated file under ``events_dir``.

    Thread-safe (uses an internal Lock for the file append step).
    Failures are NEVER fatal — if the events directory becomes
    unwritable (full disk, permissions changed, etc.), the emitter
    logs to stderr and continues. The bootloader's primary HTTP path
    is unaffected.

    Construct once at bootloader startup; the same instance handles
    every emission across the process lifetime. Pass the bound
    ``notify_resolved_fn`` method to ``create_server`` as the
    ``notify_resolved_fn`` kwarg to wire capability + sign lifecycle
    events without touching ``server.py``.
    """

    def __init__(
        self,
        events_dir: str | Path,
        *,
        bootloader_id: str | None = None,
    ) -> None:
        self.events_dir = Path(events_dir)
        self.bootloader_id = bootloader_id or ""
        self._lock = threading.Lock()

        # Eager mkdir at construction time. Failures here are
        # surfaced to the launcher rather than swallowed — if the
        # events dir CAN'T be created at startup, the operator
        # should know immediately rather than discover it on first
        # event emission.
        self.events_dir.mkdir(parents=True, exist_ok=True)

    def emit(self, kind: str, payload: dict[str, Any]) -> None:
        """Append one event to today's JSONL file.

        ``kind`` must match a key in ``EVENT_PAYLOAD_SHAPES`` for
        stable downstream consumption, but the emitter doesn't
        enforce this — unrecognized kinds are written through. The
        schema doc is the contract; enforcement is a downstream-
        consumer concern.
        """
        now = time.time()
        record = {
            "kind": kind,
            "ts": int(now),
            "ts_iso": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "bootloader": self.bootloader_id,
            "payload": payload,
        }

        # Daily-rotated file. Date in UTC to avoid timezone-shift
        # ambiguity when consumers from different timezones tail-read.
        date_str = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d")
        target = self.events_dir / f"{date_str}.jsonl"

        line = json.dumps(record, separators=(",", ":")) + "\n"

        try:
            with self._lock:
                # Open in append mode + buffering=1 (line-buffered) so
                # readers see each event as it lands. The lock guards
                # against threadpool races inside ThreadingHTTPServer;
                # without it, two concurrent emissions could interleave
                # bytes within a JSONL line.
                with open(target, "a", encoding="utf-8") as f:
                    f.write(line)
        except OSError as ex:
            # Don't let event emission failures crash the bootloader.
            # Log to stderr (which docker captures into `docker logs`)
            # so the operator sees the failure during routine log
            # inspection, but proceed serving HTTP.
            print(
                f"[recto.bootloader.events] WARNING: emit failed "
                f"({kind!r} -> {target}): {type(ex).__name__}: {ex}",
                file=sys.stderr,
            )

    # ---------------------------------------------------------------
    # notify_resolved_fn adapter
    # ---------------------------------------------------------------
    # The bootloader's existing notify_resolved_fn callback is the
    # natural wiring point for capability + sign lifecycle events.
    # This method matches that callback's signature (with TypeError-
    # tolerant fallback for older signatures, per the same shape the
    # server.py call site uses).

    def notify_resolved(
        self,
        *,
        req: Any,
        ok: bool,
        signature_b64u: str | None = None,
        eth_signature_rsv: str | None = None,
        btc_signature_base64: str | None = None,
        ed_signature_base64: str | None = None,
        ed_pubkey_hex: str | None = None,
        tron_signature_rsv: str | None = None,
        capability_jws: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Translate a notify_resolved_fn callback into a structured
        event JSONL append. Wire as
        ``create_server(notify_resolved_fn=emitter.notify_resolved, ...)``.
        """
        request_id = getattr(req, "request_id", "") or ""
        kind = getattr(req, "kind", "") or ""

        # Capability lifecycle gets its own dedicated event kind so
        # downstream consumers can filter for capability events
        # without parsing the generic sign_approved.
        if kind == "capability_request":
            if ok:
                # Pull richer metadata when available. The notify
                # callback doesn't pass these directly, but req has
                # them as attributes via the PendingRequest fields
                # the bootloader stashed at queue time.
                self.emit(
                    "capability_approved",
                    {
                        "request_id": request_id,
                        "agent_id": getattr(req, "cap_agent_id", "") or "",
                        "purpose": getattr(req, "cap_purpose", "") or "",
                        "tier": getattr(req, "cap_tier", 0) or 0,
                        "allow_actions": list(
                            getattr(req, "cap_allow_actions", ()) or ()
                        ),
                        "jws_jti": getattr(req, "cap_jti", "") or "",
                        "approved_at_unix": int(time.time()),
                    },
                )
            else:
                self.emit(
                    "capability_denied",
                    {
                        "request_id": request_id,
                        "agent_id": getattr(req, "cap_agent_id", "") or "",
                        "purpose": getattr(req, "cap_purpose", "") or "",
                        "tier": getattr(req, "cap_tier", 0) or 0,
                        "reason": reason or "",
                        "denied_at_unix": int(time.time()),
                    },
                )
            return

        # All other sign kinds (eth_sign, btc_sign, ed_sign,
        # tron_sign, single_sign, etc.) emit a generic sign_approved /
        # sign_denied. Audit watchers that want to subscribe to every
        # operator approval pick these up alongside capability_approved.
        if ok:
            self.emit(
                "sign_approved",
                {
                    "request_id": request_id,
                    "kind": kind,
                    "approved_at_unix": int(time.time()),
                },
            )
        else:
            self.emit(
                "sign_denied",
                {
                    "request_id": request_id,
                    "kind": kind,
                    "reason": reason or "",
                    "denied_at_unix": int(time.time()),
                },
            )


def construct_from_env(
    bootloader_id: str | None = None,
) -> FileEventEmitter | None:
    """Construct a FileEventEmitter from ``RECTO_EVENTS_DIR`` env var.

    Returns the emitter when ``RECTO_EVENTS_DIR`` is set + the
    directory is writable. Returns ``None`` when the env var is
    unset (opt-in to event emission is the deployment-time decision)
    OR when the directory can't be created (emitter falls back to
    no-op gracefully; the bootloader's primary HTTP behavior is
    unaffected). Failures during construction print to stderr so
    operators see misconfiguration during startup.

    Typical use in the launcher script::

        from recto.bootloader.events import construct_from_env

        events_emitter = construct_from_env(bootloader_id=bootloader_id)
        server = create_server(
            ...,
            notify_resolved_fn=(
                events_emitter.notify_resolved
                if events_emitter is not None
                else None
            ),
        )
    """
    events_dir = (os.environ.get("RECTO_EVENTS_DIR") or "").strip()
    if not events_dir:
        return None

    try:
        return FileEventEmitter(events_dir, bootloader_id=bootloader_id)
    except OSError as ex:
        print(
            f"[recto.bootloader.events] WARNING: cannot construct "
            f"FileEventEmitter at {events_dir!r}: "
            f"{type(ex).__name__}: {ex}. Events will NOT be emitted; "
            "bootloader continues serving HTTP normally.",
            file=sys.stderr,
        )
        return None
