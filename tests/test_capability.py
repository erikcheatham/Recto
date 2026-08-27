"""
Tests for the recto.capability package — Phase 5 Wave A foundation.

Scope of this test module:
  - Base64url encoding round-trips (RFC 7515 §2 compliance)
  - Canonical JSON encoding (signature-stability requirement)
  - Manifest loading and validation (well-formed and malformed inputs)
  - Capability scope resolution (groups, allow/deny actions)
  - Foundation-count weight breakdown (phone-UI-ready output shape)
  - JWS structural validation (parse rejects malformed tokens)

Wave A continuation (deferred TODO):
  - Full JWT mint+verify round-trip (requires a Python-side secp256k1
    sign primitive — recto.ethereum is verify-only)
  - External cross-check (pin a JWT minted by an external ES256K impl
    against verify_jws — required by Recto's "cross-validate any new
    digest function against an external reference impl" gotcha before
    any production use of capability JWTs)

Both deferred items are tracked in `recto/capability/SPEC.md` "What
lands next (Wave A continued)" section.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from recto.capability.jwt import (
    _b64url_decode,
    _b64url_encode,
    _canonical_json,
    assemble_jws,
    build_signing_input,
    mint_jws,
    parse_jws,
)
from recto.capability.manifest import (
    clause_weight_breakdown,
    evaluate_scope,
    load_manifest,
    load_manifest_from_dict,
    resolve_actions,
)
from recto.capability.types import (
    ActionManifest,
    CapabilityClaims,
    CapabilityClause,
    CapabilityLimits,
    CapabilityScope,
    TIER_WEIGHT_CEILINGS,
)


# Read the canonical manifest version once at module load. Any test
# that mints a JWT clause AND exercises the resolver against the
# disk-loaded `template_manifest` MUST use this constant —
# `resolve_actions` in `recto.capability.manifest` strict-checks
# `clause.registry_version == manifest.version`. Pinning a literal
# like "2026-05-05" breaks every time the manifest gets bumped
# (the canonical version moved 2026-05-05 → 2026-05-15 → 2026-05-16
# in the first two weeks of Phase 5 work). The `example_claims`
# fixture and the `test_resolve_actions_rejects_version_mismatch`
# negative-path test intentionally use literal values that DO NOT
# depend on the live manifest and are NOT updated to this constant.
_MANIFEST_VERSION: str = json.loads(
    (Path(__file__).parent.parent / "recto" / "capability" / "manifest_v1.json")
    .read_text(encoding="utf-8")
)["version"]


# ---------------------------------------------------------------------------
# Encoding round-trips (RFC 7515 §2 — base64url without padding)
# ---------------------------------------------------------------------------


def test_b64url_encode_no_padding():
    """RFC 7515 base64url MUST NOT include trailing '=' padding."""
    assert "=" not in _b64url_encode(b"x")
    assert "=" not in _b64url_encode(b"xy")
    assert "=" not in _b64url_encode(b"xyz")


def test_b64url_roundtrip():
    """encode → decode recovers the original bytes."""
    cases = [b"", b"x", b"hello world", bytes(range(256))]
    for data in cases:
        assert _b64url_decode(_b64url_encode(data)) == data


def test_b64url_decode_handles_unpadded_input():
    """decode must restore padding — encoded forms have no trailing '='."""
    # 'aGVsbG8' is base64url for 'hello' (5 bytes → 8 char input → 7 char no-pad)
    assert _b64url_decode("aGVsbG8") == b"hello"


def test_canonical_json_sorts_keys():
    """Canonical JSON sorts top-level keys for signature stability."""
    a = _canonical_json({"b": 1, "a": 2})
    b = _canonical_json({"a": 2, "b": 1})
    assert a == b
    assert a == b'{"a":2,"b":1}'


def test_canonical_json_minimal_separators():
    """No whitespace in canonical JSON (deterministic byte sequence)."""
    out = _canonical_json({"a": 1, "b": [1, 2, 3]})
    assert b" " not in out
    assert out == b'{"a":1,"b":[1,2,3]}'


def test_canonical_json_unicode():
    """Unicode strings encode consistently (json default uses \\u escapes)."""
    out = _canonical_json({"x": "café"})
    # Default json.dumps escapes non-ASCII; canonical is byte-stable.
    assert out == b'{"x":"caf\\u00e9"}'


# ---------------------------------------------------------------------------
# Manifest loading + validation
# ---------------------------------------------------------------------------


@pytest.fixture
def template_manifest_path() -> Path:
    return (
        Path(__file__).parent.parent
        / "recto"
        / "capability"
        / "manifest_v1.json"
    )


@pytest.fixture
def template_manifest(template_manifest_path: Path) -> ActionManifest:
    """The sample template manifest that ships with the package."""
    return load_manifest(template_manifest_path)


def test_template_manifest_loads(template_manifest: ActionManifest):
    """Template manifest is well-formed."""
    # Version is dynamic (bumped over time). Just check it's a
    # non-empty string of the expected YYYY-MM-DD shape; the
    # canonical value lives at the top of this module.
    assert template_manifest.version == _MANIFEST_VERSION
    assert len(template_manifest.version) == 10
    assert template_manifest.version[4] == "-"
    assert "doc:edit" in template_manifest.actions
    assert "darwin:doc-edits" in template_manifest.groups


def test_template_manifest_doc_edit_count(template_manifest: ActionManifest):
    """doc:edit has count 1 per the v1 starter calibration."""
    assert template_manifest.actions["doc:edit"].count == 1


def test_template_manifest_secret_rotate_count(template_manifest: ActionManifest):
    """secret:rotate is high-stakes (count 50) per the calibration."""
    assert template_manifest.actions["secret:rotate"].count == 50


def test_template_manifest_group_weight(template_manifest: ActionManifest):
    """darwin:doc-edits = doc:edit (1) + doc:rename (1) + claude-md:update (1) = 3."""
    assert template_manifest.group_weight("darwin:doc-edits") == 3


def test_template_manifest_starter_capability_weight(
    template_manifest: ActionManifest,
):
    """Darwin v1 starter capability sums to weight 18, well within
    the Tier 1 ceiling of 30."""
    starter_groups = [
        "darwin:doc-edits",
        "darwin:staging-deploys",
        "darwin:secret-reads",
        "darwin:public-comms",
    ]
    total = sum(template_manifest.group_weight(g) for g in starter_groups)
    assert total == 18
    assert total <= TIER_WEIGHT_CEILINGS[1]


def test_template_manifest_catastrophic_group_exceeds_tier2(
    template_manifest: ActionManifest,
):
    """operator:catastrophic exceeds Tier 2 ceiling — Tier 3 territory."""
    weight = template_manifest.group_weight("operator:catastrophic")
    assert weight > TIER_WEIGHT_CEILINGS[2]


def test_load_manifest_rejects_missing_version():
    with pytest.raises(ValueError, match="version"):
        load_manifest_from_dict({"actions": {}, "groups": {}})


def test_load_manifest_rejects_negative_count():
    with pytest.raises(ValueError, match="non-negative"):
        load_manifest_from_dict(
            {
                "version": "test",
                "actions": {
                    "bad:action": {"count": -1, "description": "no"}
                },
                "groups": {},
            }
        )


def test_load_manifest_rejects_unknown_action_in_group():
    """Group references an action not in the actions table → reject."""
    with pytest.raises(ValueError, match="unknown action"):
        load_manifest_from_dict(
            {
                "version": "test",
                "actions": {
                    "a:1": {"count": 1, "description": ""}
                },
                "groups": {
                    "g1": {"actions": ["a:1", "missing:action"]}
                },
            }
        )


def test_load_manifest_rejects_non_int_count():
    with pytest.raises(ValueError, match="non-negative"):
        load_manifest_from_dict(
            {
                "version": "test",
                "actions": {
                    "a:1": {"count": "five", "description": ""}
                },
                "groups": {},
            }
        )


# ---------------------------------------------------------------------------
# Scope resolution
# ---------------------------------------------------------------------------


def test_resolve_actions_expands_groups(template_manifest: ActionManifest):
    """resolve_actions expands group identifiers into member actions."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
    )
    permitted = resolve_actions(clause, template_manifest)
    assert "doc:edit" in permitted
    assert "doc:rename" in permitted
    assert "claude-md:update" in permitted
    assert "deploy:staging" not in permitted


def test_resolve_actions_combines_groups(template_manifest: ActionManifest):
    """Multiple groups union their member actions."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits", "darwin:staging-deploys"],
    )
    permitted = resolve_actions(clause, template_manifest)
    assert "doc:edit" in permitted
    assert "deploy:staging" in permitted
    assert "smoke-test" in permitted


def test_resolve_actions_subtracts_deny(template_manifest: ActionManifest):
    """deny_actions removes from permitted set even if a group included them."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
        deny_actions=["doc:rename"],
    )
    permitted = resolve_actions(clause, template_manifest)
    assert "doc:edit" in permitted
    assert "doc:rename" not in permitted
    assert "claude-md:update" in permitted


def test_resolve_actions_adds_allow(template_manifest: ActionManifest):
    """allow_actions adds beyond the group set."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
        allow_actions=["secret:read"],
    )
    permitted = resolve_actions(clause, template_manifest)
    assert "secret:read" in permitted
    assert "doc:edit" in permitted


def test_resolve_actions_rejects_version_mismatch(
    template_manifest: ActionManifest,
):
    """Clause referencing a different manifest version raises."""
    clause = CapabilityClause(
        tier=1, registry_version="OLD-VERSION", groups=[]
    )
    with pytest.raises(ValueError, match="registry_version"):
        resolve_actions(clause, template_manifest)


def test_resolve_actions_rejects_unknown_group(template_manifest: ActionManifest):
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["unknown:group"],
    )
    with pytest.raises(ValueError, match="unknown group"):
        resolve_actions(clause, template_manifest)


def test_evaluate_scope_permits_authorized_action(
    template_manifest: ActionManifest,
):
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:staging-deploys"],
    )
    assert evaluate_scope("deploy:staging", clause, template_manifest)
    assert evaluate_scope("smoke-test", clause, template_manifest)


def test_evaluate_scope_denies_unauthorized_action(
    template_manifest: ActionManifest,
):
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
    )
    assert not evaluate_scope("deploy:prod", clause, template_manifest)
    assert not evaluate_scope("secret:rotate", clause, template_manifest)


def test_evaluate_scope_fails_closed_on_unknown(
    template_manifest: ActionManifest,
):
    """Unknown group → fail closed (not raise to caller)."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["unknown:group"],
    )
    assert not evaluate_scope("anything", clause, template_manifest)


def test_evaluate_scope_fails_closed_on_version_mismatch(
    template_manifest: ActionManifest,
):
    """Manifest version mismatch → fail closed."""
    clause = CapabilityClause(
        tier=1,
        registry_version="OLD-VERSION",
        groups=["darwin:doc-edits"],
    )
    assert not evaluate_scope("doc:edit", clause, template_manifest)


# ---------------------------------------------------------------------------
# Weight breakdown — phone-side approval UI shape
# ---------------------------------------------------------------------------


def test_weight_breakdown_basic_shape(template_manifest: ActionManifest):
    """Breakdown carries tier, ceiling, total, groups, extras, denies."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
    )
    breakdown = clause_weight_breakdown(clause, template_manifest)
    assert breakdown["tier"] == 1
    assert breakdown["tier_ceiling"] == 30
    assert breakdown["total"] == 3
    assert len(breakdown["groups"]) == 1
    assert breakdown["groups"][0]["weight"] == 3
    assert breakdown["groups"][0]["key"] == "darwin:doc-edits"


def test_weight_breakdown_extra_actions(template_manifest: ActionManifest):
    """allow_actions adds to total and appears in extra_actions list."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
        allow_actions=["secret:read"],
    )
    breakdown = clause_weight_breakdown(clause, template_manifest)
    # doc-edits group (3) + secret:read action (5) = 8
    assert breakdown["total"] == 8
    assert len(breakdown["extra_actions"]) == 1
    assert breakdown["extra_actions"][0]["key"] == "secret:read"
    assert breakdown["extra_actions"][0]["count"] == 5


# --- fail-closed parity with resolve_actions (2026-08-09) -------------------
# These three RED-BUILD the asymmetry a defensive review found: this function
# used to skip unknown groups (bare `continue`), filter unknown allow_actions
# (`if key in manifest.actions`), and never check registry_version at all —
# while resolve_actions raised on every one of them. Every skip made the
# rendered total read LOW, and a consent UI must never round the size of a
# trust transfer downward. At v2 the same total becomes a spend ceiling.


def test_weight_breakdown_rejects_unknown_group(
    template_manifest: ActionManifest,
):
    """Unknown group RAISES — it is an error, not a zero-weight group."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits", "unknown:group"],
    )
    with pytest.raises(ValueError, match="unknown group"):
        clause_weight_breakdown(clause, template_manifest)


def test_weight_breakdown_rejects_unknown_allow_action(
    template_manifest: ActionManifest,
):
    """Unknown allow_actions entry RAISES rather than being filtered out."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
        allow_actions=["totally:unknown"],
    )
    with pytest.raises(ValueError, match="unknown action"):
        clause_weight_breakdown(clause, template_manifest)


def test_weight_breakdown_rejects_version_mismatch(
    template_manifest: ActionManifest,
):
    """Clause from another manifest version RAISES.

    The widest of the three: with a version mismatch EVERY key could be
    resolving against the wrong manifest, so a total computed anyway is
    meaningless rather than merely incomplete.
    """
    clause = CapabilityClause(
        tier=1, registry_version="OLD-VERSION", groups=[]
    )
    with pytest.raises(ValueError, match="registry_version"):
        clause_weight_breakdown(clause, template_manifest)


def test_weight_breakdown_matches_resolve_actions_on_bad_input(
    template_manifest: ActionManifest,
):
    """PARITY: both functions accept and reject the SAME clauses.

    The bug was never one function being wrong in isolation — it was two
    functions disagreeing about what a valid clause is. This pins the
    agreement so they cannot drift apart again.
    """
    bad = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["unknown:group"],
    )
    with pytest.raises(ValueError):
        resolve_actions(bad, template_manifest)
    with pytest.raises(ValueError):
        clause_weight_breakdown(bad, template_manifest)

    good = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
    )
    resolve_actions(good, template_manifest)
    clause_weight_breakdown(good, template_manifest)


def test_weight_breakdown_full_darwin_starter(
    template_manifest: ActionManifest,
):
    """Full Darwin starter capability totals 18 — pinned for regression."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=[
            "darwin:doc-edits",
            "darwin:staging-deploys",
            "darwin:secret-reads",
            "darwin:public-comms",
        ],
    )
    breakdown = clause_weight_breakdown(clause, template_manifest)
    assert breakdown["total"] == 18
    assert breakdown["tier"] == 1
    assert breakdown["tier_ceiling"] == 30


def test_weight_breakdown_denied_actions_listed(
    template_manifest: ActionManifest,
):
    """deny_actions surfaces in breakdown for operator-visible review."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
        deny_actions=["secret:rotate"],
    )
    breakdown = clause_weight_breakdown(clause, template_manifest)
    assert breakdown["denied_actions"] == ["secret:rotate"]


# ---------------------------------------------------------------------------
# JWS structural validation
# ---------------------------------------------------------------------------


def test_parse_jws_rejects_too_few_parts():
    with pytest.raises(ValueError, match="3 dot-separated"):
        parse_jws("only.two")


def test_parse_jws_rejects_too_many_parts():
    with pytest.raises(ValueError, match="3 dot-separated"):
        parse_jws("a.b.c.d")


def test_parse_jws_rejects_invalid_b64():
    """Header that doesn't base64url-decode raises ValueError."""
    with pytest.raises(ValueError):
        parse_jws("!!!.eyJhIjoxfQ.AA")  # invalid b64 in header segment


def test_parse_jws_succeeds_on_well_formed_input():
    """A well-formed (but unsigned/unverified) JWS parses without error."""
    header_b64 = _b64url_encode(_canonical_json({"alg": "ES256K", "typ": "JWT"}))
    payload_b64 = _b64url_encode(_canonical_json({"hello": "world"}))
    sig_b64 = _b64url_encode(b"\x00" * 64)
    token = f"{header_b64}.{payload_b64}.{sig_b64}"
    header, payload, signature, signing_input = parse_jws(token)
    assert header["alg"] == "ES256K"
    assert payload["hello"] == "world"
    assert len(signature) == 64
    assert signing_input == f"{header_b64}.{payload_b64}".encode("ascii")


# ---------------------------------------------------------------------------
# Mint helpers — pre-sign signing input + final assembly
# ---------------------------------------------------------------------------


@pytest.fixture
def example_claims() -> CapabilityClaims:
    """Canonical capability-claims fixture for shape and signing-input
    tests. Same fixture is used by Wave A continuation work to pin
    against an external-tool-minted JWT."""
    return CapabilityClaims(
        iss="phone:operator:enclave",
        sub="agent:darwin@staging",
        aud=["consumer-app", "recto:vault"],
        iat=1715000000,
        nbf=1715000000,
        exp=1715086400,
        jti="cap_2026-05-05_test",
        cap=CapabilityClause(
            tier=1,
            registry_version="2026-05-05",
            groups=["darwin:doc-edits", "darwin:staging-deploys"],
            scope=CapabilityScope(env=["staging"], services=["web"], repos=["recto"]),
            limits=CapabilityLimits(per_hour={"deploy:staging": 5}),
        ),
        purpose="Test capability fixture",
    )


def test_build_signing_input_deterministic(example_claims: CapabilityClaims):
    """Same claims produce the same digest + b64 segments — required for
    signature stability and external cross-check reproducibility."""
    digest1, h1, p1 = build_signing_input(example_claims)
    digest2, h2, p2 = build_signing_input(example_claims)
    assert digest1 == digest2
    assert h1 == h2
    assert p1 == p2
    assert len(digest1) == 32  # SHA-256


def test_build_signing_input_header_shape(example_claims: CapabilityClaims):
    """Header decodes back to the canonical {alg: ES256K, typ: JWT}."""
    _, header_b64, _ = build_signing_input(example_claims)
    decoded = json.loads(_b64url_decode(header_b64))
    assert decoded == {"alg": "ES256K", "typ": "JWT"}


def test_build_signing_input_payload_carries_claims(
    example_claims: CapabilityClaims,
):
    """Payload decodes back to the claims with all fields preserved."""
    _, _, payload_b64 = build_signing_input(example_claims)
    decoded = json.loads(_b64url_decode(payload_b64))
    assert decoded["iss"] == example_claims.iss
    assert decoded["sub"] == example_claims.sub
    assert decoded["aud"] == example_claims.aud
    assert decoded["jti"] == example_claims.jti
    assert decoded["cap"]["tier"] == 1
    assert decoded["cap"]["registry_version"] == "2026-05-05"


def test_build_signing_input_omits_none_optionals(
    example_claims: CapabilityClaims,
):
    """parent_cap and max_uses are None → omitted from the payload."""
    _, _, payload_b64 = build_signing_input(example_claims)
    decoded = json.loads(_b64url_decode(payload_b64))
    assert "parent_cap" not in decoded
    assert "max_uses" not in decoded


# Phase H (2026-05-19 night) — pairing_code scope-extension field
# round-trip + omit-when-None tests. Sister of the chat_room_id /
# target_user_id extension fields banked in Phase F + Phase F follow-on
# (those don't have explicit tests today but pairing_code is the FIRST
# end-user-fired action with a scope-extension; worth pinning the round-
# trip now while the pattern is fresh).
def test_build_signing_input_carries_pairing_code(
    example_claims: CapabilityClaims,
):
    """When CapabilityScope.pairing_code is set, the canonical JSON
    encoding embeds it as a string at cap.scope.pairing_code — the
    SAME location a consumer's SelfAttestedVerifier reads it back via
    raw JsonElement re-parse to bind the JWS to the typed 8-char
    code. Without this byte-parity guarantee, a JWS minted Python-
    side and a JWS minted C#-side could disagree on whether the
    pairing_code is at scope.pairing_code OR top-level OR nested
    elsewhere, breaking the cross-language verifier contract."""
    claims_with_code = CapabilityClaims(
        iss=example_claims.iss,
        sub=example_claims.sub,
        aud=["example-consumer"],
        iat=example_claims.iat,
        nbf=example_claims.nbf,
        exp=example_claims.exp,
        jti=example_claims.jti,
        cap=CapabilityClause(
            tier=0,
            registry_version=example_claims.cap.registry_version,
            groups=[],
            scope=CapabilityScope(
                env=[],
                services=[],
                repos=[],
                pairing_code="ABCD1234",
            ),
            allow_actions=["devices:pair"],
            limits=CapabilityLimits(),
        ),
        purpose="Pair phone with the consumer service",
    )
    _, _, payload_b64 = build_signing_input(claims_with_code)
    decoded = json.loads(_b64url_decode(payload_b64))
    assert decoded["cap"]["scope"]["pairing_code"] == "ABCD1234"
    assert decoded["cap"]["allow_actions"] == ["devices:pair"]
    assert decoded["aud"] == ["example-consumer"]


def test_build_signing_input_omits_pairing_code_when_none(
    example_claims: CapabilityClaims,
):
    """When pairing_code is None (default), the canonical JSON
    encoding MUST NOT include the key — preserves byte-parity with
    existing pinned-fixture tests that pre-date the scope extension.
    Sister of the parent_cap / max_uses None-omission contract."""
    _, _, payload_b64 = build_signing_input(example_claims)
    decoded = json.loads(_b64url_decode(payload_b64))
    # example_claims doesn't set pairing_code — it should NOT appear
    # in the encoded scope.
    assert "pairing_code" not in decoded["cap"]["scope"]


def test_template_manifest_includes_devices_pair(
    template_manifest: ActionManifest,
):
    """Phase H (2026-05-19) added the devices:pair action to the
    template manifest at Tier 0 (count 1) — the FIRST end-user-fired
    capability action and the first action whose scope-extension
    field (pairing_code) is a short typed string rather than a Guid."""
    assert "devices:pair" in template_manifest.actions
    assert template_manifest.actions["devices:pair"].count == 1


def test_template_manifest_devices_pairing_revoke_action(
    template_manifest: ActionManifest,
):
    """devices:pairing_revoke (2026-06-21) is the teardown sibling of
    devices:pair — the per-service-unpair v1.x action. Tier 0 (count 1):
    user-initiated, authority-REMOVING, one-shot. Relayed through the
    bootloader's POST /v0.4/devices/unpair to the consumer's
    /api/v1/devices/pairing/revoke endpoint."""
    assert "devices:pairing_revoke" in template_manifest.actions
    assert template_manifest.actions["devices:pairing_revoke"].count == 1


def test_template_manifest_user_device_pairing_group(
    template_manifest: ActionManifest,
):
    """user:device-pairing is the FIRST group not prefixed `operator:*`
    or `darwin:*` — denotes capabilities the END-USER holds and
    exercises from their own Recto Phone (Phase H). Wraps devices:pair
    (2026-05-19) + its teardown sibling devices:pairing_revoke
    (2026-06-21); future user-fired capabilities (user:profile-rotate)
    will join the same group."""
    assert "user:device-pairing" in template_manifest.groups
    assert template_manifest.groups["user:device-pairing"].actions == [
        "devices:pair",
        "devices:pairing_revoke",
    ]
    # Tier 0 weight: devices:pair (1) + devices:pairing_revoke (1) = 2.
    assert template_manifest.group_weight("user:device-pairing") == 2


def test_assemble_jws_round_trips(example_claims: CapabilityClaims):
    """assemble_jws + parse_jws round-trip preserves header and payload
    structure (signature verification is a separate concern)."""
    digest, header_b64, payload_b64 = build_signing_input(example_claims)
    fake_signature = b"\x00" * 64
    token = assemble_jws(header_b64, payload_b64, fake_signature)
    header, payload, signature, signing_input = parse_jws(token)
    assert header == {"alg": "ES256K", "typ": "JWT"}
    assert payload["jti"] == example_claims.jti
    assert signature == fake_signature
    # signing_input matches what build_signing_input fed into the digest
    assert hashlib_sha256_compat(signing_input) == digest


def test_assemble_jws_rejects_wrong_signature_length():
    with pytest.raises(ValueError, match="64 raw bytes"):
        assemble_jws("h", "p", b"\x00" * 32)


def test_mint_jws_raises_not_implemented(example_claims: CapabilityClaims):
    """Python-side mint is deferred — Wave A continuation TODO."""
    with pytest.raises(NotImplementedError, match="Wave A"):
        mint_jws(example_claims, b"\x00" * 32)


# ---------------------------------------------------------------------------
# Helper used in test_assemble_jws_round_trips
# ---------------------------------------------------------------------------


def hashlib_sha256_compat(data: bytes) -> bytes:
    """Local helper rather than importing hashlib at module top — keeps
    the test imports purely of the recto.capability surface plus pytest."""
    import hashlib

    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Wave A continuation TODO (deferred — not implemented in this commit)
# ---------------------------------------------------------------------------


@pytest.mark.skip(
    reason="Wave A continuation: requires Python-side ECDSA sign primitive "
    "(recto.ethereum is verify-only). See recto/capability/jwt.py mint_jws "
    "docstring for the full plan."
)
def test_mint_verify_roundtrip_TODO():
    """Round-trip mint+verify with a known private key.

    Pins internal consistency: mint a JWT with key K, verify with the
    public key derived from K, expect the parsed claims to match the
    minted claims.

    Internal-consistency tests are necessary but NOT sufficient — see
    ``test_verify_external_jwt_TODO`` for the cross-check that catches
    format-bug regressions internal-consistency tests can't.
    """
    pass


@pytest.mark.skip(
    reason="Wave A continuation: pin a JWT minted by an external ES256K "
    "tool (python-jose / jwcrypto / ethers.js / similar) against verify_jws. "
    "Required by Recto's gotcha 'cross-validate any new digest function "
    "against an external reference impl' before any production use."
)
def test_verify_external_jwt_TODO():
    """Cross-check that catches format bugs internal round-trip can't.

    Plan:
      1. With a fixed test private key (e.g. the canonical secp256k1 k=1
         test vector OR the Trezor 'abandon...about' BIP-39 reference
         derivation), mint a capability JWT via an external ES256K tool
      2. Pin the resulting JWT string here as a fixture
      3. Verify it with verify_jws using the corresponding public key
      4. Assert parsed claims match expected

    Wave 4 banked the lesson that an internally-self-consistent but
    externally-incompatible cryptographic impl is the worst kind of
    bug because it appears to work — only an external reference catches
    it. Capability JWTs need this cross-check before any production
    use.
    """
    pass


# ---------------------------------------------------------------------------
# Phase 2.0.C wave C.2 — parent_profile capability JWS verifier extension
# ---------------------------------------------------------------------------


def _mint_jws_with_priv(claims: CapabilityClaims, priv_int: int) -> str:
    """Test-only ES256K mint helper for C.2 tests. Mirrors the
    `_mint_jws` helper in `tests/test_bootloader_capability_gate.py`
    but lives here so test_capability.py doesn't cross-import its
    sister test module."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    digest, header_b64, payload_b64 = build_signing_input(claims)
    priv = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())
    sig_der = priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(sig_der)
    # Pack r||s as 64 bytes raw (JWS ES256K format).
    sig_raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    from recto.capability.jwt import assemble_jws

    return assemble_jws(header_b64, payload_b64, sig_raw)


def _generate_secp256k1_keypair():
    """Returns (priv_int, pub_bytes_64). Pub bytes is uncompressed
    X || Y (no 0x04 prefix), matching what the on-disk Profile
    derived_pubkey_hex stores."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    priv_int = priv.private_numbers().private_value
    pub_nums = priv.public_key().public_numbers()
    pub_bytes = pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
    return (priv_int, pub_bytes)


def _bootstrap_master_with_child(
    state_dir,
    *,
    child_pubkey_hex: str | None,
    child_kind: str = "personal:child",
    child_display_name: str = "Test child",
    child_revoked: bool = False,
):
    """Test helper: stand up a master + one child profile with the
    requested derived_pubkey_hex. Returns (master_pubkey_hex,
    child_profile_id, master_identity)."""
    from recto.profile.manage import bootstrap_master, create_child_profile, mark_profile_revoked

    master_pubkey_hex = bytes(range(64)).hex()
    mi = bootstrap_master(
        master_pubkey_hex=master_pubkey_hex,
        display_name="Test master",
        state_dir=state_dir,
    )
    child = create_child_profile(
        kind=child_kind,
        display_name=child_display_name,
        derived_pubkey_hex=child_pubkey_hex,
        state_dir=state_dir,
    )
    if child_revoked:
        mark_profile_revoked(child.profile_id, state_dir=state_dir)
    return master_pubkey_hex, child.profile_id, mi


def _make_claims_for_profile(
    *,
    parent_profile: str | None,
    exp_offset_seconds: int = 3600,
    aud: list[str] | None = None,
    groups: list[str] | None = None,
    allow_actions: list[str] | None = None,
    deny_actions: list[str] | None = None,
) -> CapabilityClaims:
    """Build a CapabilityClaims for C.2 testing."""
    import time as _time

    now = int(_time.time())
    return CapabilityClaims(
        iss="phone:operator:enclave",
        sub="agent:test@dev",
        aud=aud if aud is not None else ["test-aud"],
        iat=now,
        nbf=now,
        exp=now + exp_offset_seconds,
        jti=f"cap_c2_test_{now}",
        cap=CapabilityClause(
            tier=1,
            registry_version=_MANIFEST_VERSION,
            groups=groups if groups is not None else [],
            allow_actions=allow_actions if allow_actions is not None else [],
            deny_actions=deny_actions if deny_actions is not None else [],
        ),
        purpose="C.2 verifier-extension test",
        parent_profile=parent_profile,
    )


def test_c2_verify_jws_with_parent_profile_recovers_against_child_key(
    tmp_path,
):
    """Happy path: JWS minted under a child profile's derived key
    verifies when verify_jws is given the master master pubkey AS
    expected_pubkey AND state_dir pointing at the MasterIdentity
    that knows the child's derived_pubkey_hex."""
    from recto.capability.jwt import verify_jws

    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)

    # Mint a child keypair, register its pubkey on a child profile.
    child_priv, child_pub = _generate_secp256k1_keypair()
    master_pubkey_hex, child_id, mi = _bootstrap_master_with_child(
        state_dir, child_pubkey_hex=child_pub.hex(),
    )

    # Mint a JWS signed by the child key with parent_profile=<child_id>.
    claims = _make_claims_for_profile(parent_profile=child_id)
    jws = _mint_jws_with_priv(claims, child_priv)

    # The OPERATOR pubkey passed as expected_pubkey is the master
    # root. With parent_profile set, verify_jws ignores
    # expected_pubkey and dispatches against the child profile's
    # derived_pubkey_hex from state_dir.
    operator_pubkey = bytes.fromhex(master_pubkey_hex)
    verified = verify_jws(
        jws,
        expected_pubkey=operator_pubkey,
        expected_aud="test-aud",
        state_dir=state_dir,
    )
    assert verified.parent_profile == child_id
    assert verified.sub == "agent:test@dev"


def test_c2_verify_jws_without_parent_profile_uses_operator_key(tmp_path):
    """Backward compat: JWS without parent_profile claim still
    verifies against the operator's master pubkey (v1.x / v2.0.B
    behavior unchanged)."""
    from recto.capability.jwt import verify_jws

    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)

    # Bootstrap a master (so state_dir is valid) but the JWS won't
    # need the lookup.
    operator_priv, operator_pub = _generate_secp256k1_keypair()
    from recto.profile.manage import bootstrap_master
    bootstrap_master(
        master_pubkey_hex=operator_pub.hex(),
        display_name="Test master",
        state_dir=state_dir,
    )

    claims = _make_claims_for_profile(parent_profile=None)
    jws = _mint_jws_with_priv(claims, operator_priv)

    verified = verify_jws(
        jws,
        expected_pubkey=operator_pub,
        expected_aud="test-aud",
        state_dir=state_dir,
    )
    assert verified.parent_profile is None


def test_c2_verify_jws_rejects_unknown_parent_profile(tmp_path):
    """JWS claims parent_profile=<id> but no profile with that id
    exists under the master → ValueError 'parent_profile ... not
    found'."""
    from recto.capability.jwt import verify_jws

    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)

    child_priv, child_pub = _generate_secp256k1_keypair()
    master_pubkey_hex, real_child_id, _ = _bootstrap_master_with_child(
        state_dir, child_pubkey_hex=child_pub.hex(),
    )
    # Mint claims pointing at a NONEXISTENT profile_id.
    claims = _make_claims_for_profile(parent_profile="nonexistent-id")
    jws = _mint_jws_with_priv(claims, child_priv)

    with pytest.raises(ValueError, match="parent_profile.*not found"):
        verify_jws(
            jws,
            expected_pubkey=bytes.fromhex(master_pubkey_hex),
            expected_aud="test-aud",
            state_dir=state_dir,
        )


def test_c2_verify_jws_rejects_revoked_parent_profile(tmp_path):
    """JWS claims parent_profile=<id> where the profile exists but
    is revoked → ValueError 'parent_profile ... is revoked'."""
    from recto.capability.jwt import verify_jws

    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)

    child_priv, child_pub = _generate_secp256k1_keypair()
    master_pubkey_hex, child_id, _ = _bootstrap_master_with_child(
        state_dir,
        child_pubkey_hex=child_pub.hex(),
        child_revoked=True,
    )
    claims = _make_claims_for_profile(parent_profile=child_id)
    jws = _mint_jws_with_priv(claims, child_priv)

    with pytest.raises(ValueError, match="parent_profile.*is revoked"):
        verify_jws(
            jws,
            expected_pubkey=bytes.fromhex(master_pubkey_hex),
            expected_aud="test-aud",
            state_dir=state_dir,
        )


def test_c2_verify_jws_rejects_parent_profile_without_derived_pubkey(tmp_path):
    """v2.0.B-era backward compat scenario: the profile exists but
    has derived_pubkey_hex=None (was created before the C.1 schema
    bump). verify_jws rejects with a clear actionable error pointing
    at the future backfill admin command."""
    from recto.capability.jwt import verify_jws

    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)

    child_priv, _child_pub = _generate_secp256k1_keypair()
    # Use child_pubkey_hex=None to simulate a v2.0.B-era profile row.
    master_pubkey_hex, child_id, _ = _bootstrap_master_with_child(
        state_dir, child_pubkey_hex=None,
    )
    claims = _make_claims_for_profile(parent_profile=child_id)
    jws = _mint_jws_with_priv(claims, child_priv)

    with pytest.raises(ValueError, match="lacks derived_pubkey_hex|derive-pubkey"):
        verify_jws(
            jws,
            expected_pubkey=bytes.fromhex(master_pubkey_hex),
            expected_aud="test-aud",
            state_dir=state_dir,
        )


def test_c2_verify_jws_rejects_signature_signed_by_wrong_child_key(tmp_path):
    """JWS claims parent_profile=<id> but signed by a DIFFERENT
    secp256k1 key (not the one registered on the profile's
    derived_pubkey_hex) → ValueError 'did not recover to
    parent_profile'."""
    from recto.capability.jwt import verify_jws

    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)

    real_child_priv, real_child_pub = _generate_secp256k1_keypair()
    master_pubkey_hex, child_id, _ = _bootstrap_master_with_child(
        state_dir, child_pubkey_hex=real_child_pub.hex(),
    )
    # Mint the JWS with a DIFFERENT key.
    impostor_priv, _impostor_pub = _generate_secp256k1_keypair()
    claims = _make_claims_for_profile(parent_profile=child_id)
    jws = _mint_jws_with_priv(claims, impostor_priv)

    with pytest.raises(ValueError, match="did not recover to parent_profile"):
        verify_jws(
            jws,
            expected_pubkey=bytes.fromhex(master_pubkey_hex),
            expected_aud="test-aud",
            state_dir=state_dir,
        )


def test_c2_verify_jws_rejects_parent_profile_without_state_dir(tmp_path):
    """JWS has parent_profile claim but caller didn't supply
    state_dir → ValueError telling caller to pass it. (Catches
    common caller-side oversight where the JWS is from a v2.0.C
    flow but the verifier still uses the v1.x call shape.)"""
    from recto.capability.jwt import verify_jws

    # Mint a child key + JWS for a profile_id that won't actually
    # be looked up (verify_jws fails before that).
    child_priv, child_pub = _generate_secp256k1_keypair()
    claims = _make_claims_for_profile(parent_profile="some-id")
    jws = _mint_jws_with_priv(claims, child_priv)

    with pytest.raises(ValueError, match="state_dir kwarg was not supplied"):
        verify_jws(
            jws,
            expected_pubkey=child_pub,  # arbitrary; verify fails before signature check
            expected_aud="test-aud",
            state_dir=None,
        )


def test_c2_verify_jws_rejects_parent_profile_when_no_master_bootstrapped(
    tmp_path,
):
    """state_dir exists but no MasterIdentity is bootstrapped (no
    master_identity.json file) → ValueError 'no master is
    bootstrapped'."""
    from recto.capability.jwt import verify_jws

    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    # NO bootstrap_master call — the state_dir is empty.

    child_priv, child_pub = _generate_secp256k1_keypair()
    claims = _make_claims_for_profile(parent_profile="some-id")
    jws = _mint_jws_with_priv(claims, child_priv)

    with pytest.raises(ValueError, match="no master is bootstrapped"):
        verify_jws(
            jws,
            expected_pubkey=child_pub,
            expected_aud="test-aud",
            state_dir=state_dir,
        )


# ---------------------------------------------------------------------------
# Phase 2.0.C wave C.2 — evaluate_scope deny_actions_inherited extension
# ---------------------------------------------------------------------------


def test_c2_evaluate_scope_without_deny_actions_inherited_unchanged(
    template_manifest: ActionManifest,
):
    """Backward compat: evaluate_scope without parent_profile_deny_actions
    kwarg behaves identically to v1.x / v2.0.B."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
    )
    assert evaluate_scope("doc:edit", clause, template_manifest)


def test_c2_evaluate_scope_subtracts_parent_profile_deny_actions(
    template_manifest: ActionManifest,
):
    """When parent_profile_deny_actions=("doc:edit",) is passed,
    doc:edit is subtracted from the resolved permitted set even
    though the group includes it."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=["darwin:doc-edits"],
    )
    # Without the deny, doc:edit is permitted.
    assert evaluate_scope("doc:edit", clause, template_manifest)
    # With the deny, doc:edit is NOT permitted.
    assert not evaluate_scope(
        "doc:edit",
        clause,
        template_manifest,
        parent_profile_deny_actions=("doc:edit",),
    )
    # Other actions in the group remain permitted.
    assert evaluate_scope(
        "doc:rename",
        clause,
        template_manifest,
        parent_profile_deny_actions=("doc:edit",),
    )


def test_c2_evaluate_scope_deny_inherited_overrides_explicit_allow(
    template_manifest: ActionManifest,
):
    """If a clause explicitly allow_actions an action that the parent
    profile bans, the deny wins. SCIM-pushed per-profile bans are
    structural overrides — capability scope is bounded by them at
    verify time, regardless of what the operator wished."""
    clause = CapabilityClause(
        tier=1,
        registry_version=_MANIFEST_VERSION,
        groups=[],
        allow_actions=["secret:read"],
    )
    assert evaluate_scope("secret:read", clause, template_manifest)
    assert not evaluate_scope(
        "secret:read",
        clause,
        template_manifest,
        parent_profile_deny_actions=("secret:read",),
    )
