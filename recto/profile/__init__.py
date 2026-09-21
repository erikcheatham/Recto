"""Multi-profile identity package — v2.0 foothold.

This package is the v1.x SHELL for what becomes the multi-profile
identity layer in Recto v2.0. The architectural decision is banked in
ARCHITECTURE.md under "Multi-profile identity: personal-as-master-key
hierarchy (DESIGN BANKED)" (2026-05-15 entry).

Why this package exists in v1.x at all:

  - **Type contracts are public API.** Downstream consumers writing
    against Recto v1.1 / v1.2 need stable type names + field shapes to
    code against, even before v2.0 ships the runtime. The dataclasses
    in `types.py` are the wire-protocol contract for v2.0; consumers
    can import them today and write conditional code paths that
    activate when the runtime lands.

  - **Wire-protocol slot reservation.** v2.0 will extend
    `CapabilityClaims` with `parent_profile`, extend `PendingRequest`
    with the `profile_create` / `profile_add_device` /
    `profile_revoke_device` kinds, and reserve action keys
    `profile:create` + `profile:add_device` + `profile:revoke_device`
    + `profile:rotate_master` in the capability manifest. Banking the
    types here keeps Hard Rule #1 ("backward compatibility on the
    YAML / wire schema; additive only") clean: v2.0 ships as additive
    field expansions, not a breaking change.

  - **CLI surface stub.** `recto profile list` exists in v1.x as a
    placeholder that prints "v2.0 — coming soon" + links to the ADR.
    Operators reaching for the command early get pointed at the
    design doc instead of a `command not found`.

v2.0 runtime work (NOT shipped in v1.x):

  - Profile derivation (BIP-32 chain over master enclave key)
  - `recto profile create <kind> --name <label>` actual implementation
  - PendingRequest.kind = "profile_create" wire-protocol handler
  - Phone-side profile picker + per-profile capability rendering
  - Capability JWS verifier extension for parent_profile chain
    validation
  - SCIM provisioning surface for enterprise-managed profiles
  - Federation handshake for school / SSO-bound profiles

See ARCHITECTURE.md for the full design rationale + threat model +
trust hierarchy.
"""
