"""
Recto Connections Substrate — operator-managed external-integration
credentials, generic across whatever application Recto is installed
alongside of.

A "connection" is a named external integration a consuming application
depends on: an API key for a third-party provider (Podcast Index, Watchmode,
Listen Notes, TMDB, a review-site aggregator, an SMS gateway, an analytics
sink, anything keyed). Recto owns the storage, rotation, capability-gating,
and HTTP surface; the consuming application (ServiceA, ServiceB, ServiceC,
future-N) consumes the dependency via the bootloader's connections endpoints.

Design intent (operator's directive 2026-06-13):
  "make a Recto specific substrate and ServiceA consumes the dependency...
   no more managing keys anymore... no more keys in chat or deployment ever."

Architecture:
  * The SECRET VALUE (the API key/token) lives in the existing dpapi-machine
    vault (`C:\\ProgramData\\recto\\<service>\\conn.<key>.dpapi`), encrypted
    with the machine key. It is NEVER stored in deployment config, NEVER in
    chat, NEVER in source. Only the operator-facing write path puts it there.
  * The METADATA (display_name, category, enabled flag, non-secret config,
    health-probe URL, timestamps) lives in a non-secret sidecar JSON
    (`connections.json`) in the bootloader state dir — sister of phones.json /
    sessions.json. It carries a `has_secret` flag but NEVER the secret value.
  * Reads of the secret value are agent-token-gated (a registered consuming
    app reads only its own service's secrets). Writes/rotations are
    operator-authenticated (v1: operator-token bearer, sister of the
    revocation endpoint per Hard Rule #9's chicken-and-egg; v2: phone
    capability-gated `connections:set`).

Hard rules in play:
  - #2: secrets never logged / serialized / echoed. The secret value lives
    only in the vault + transiently in the read path. ConnectionMeta carries
    no secret value field by construction.
  - #6: the SecretSource ABC is the public API contract. Connections layer
    on top of DpapiMachineSource (the production default) for value storage.
  - #9: phone enclave is the unconditional root of trust. Operator writes
    are sensitive; v2 gates them behind a `connections:set` capability JWS.
  - #10: three-package distribution. This substrate ships in recto-core; the
    consuming-app client lives in recto-client-{py,ts,cs}; neither is
    ServiceA-specific.
  - #13 (consumer-side, ServiceA): connections are how the consumer reaches
    third-party providers it aggregates; the substrate is provider-agnostic.

The metadata + management primitives live in `recto.connections.manage`; the
HTTP surface lands in `recto.bootloader.server` (`/v0.4/connections/*`); the
data contract every layer shares lives here.
"""

from __future__ import annotations

from .types import (
    ConnectionMeta,
    ConnectionStore,
    normalize_connection_key,
)

__all__ = [
    "ConnectionMeta",
    "ConnectionStore",
    "normalize_connection_key",
]
