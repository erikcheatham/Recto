"""
JWS (JSON Web Signature) mint and verify primitives for capability JWTs.

Uses the existing `recto.ethereum` secp256k1 primitives (Wave 6) for the
underlying signature operations — no new cryptographic dependencies. The
JWT is signed with the algorithm `ES256K` (RFC 8812) using the
operator's BIP-39-derived secp256k1 key.

Pure stdlib + recto.ethereum. No PyPI dependencies introduced.

Phase 5 Wave A scope:
  - parse_jws:       split a JWS into (header, payload, signature) parts
  - verify_jws:      verify a JWS signature against the operator's
                     known public key and return the parsed claims
  - mint_jws:        sign a CapabilityClaims into a JWS (used for tests
                     and dev tooling — production minting happens on
                     the phone enclave with biometric gating)

Production minting flow does NOT use mint_jws here — it uses the
phone-side Secure Enclave path. mint_jws is provided for unit tests
and dev fixtures to round-trip mint/verify without phone-in-the-loop.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from recto.capability.types import (
    CapabilityClaims,
    CapabilityClause,
    CapabilityLimits,
    CapabilityScope,
)


# ---------------------------------------------------------------------------
# JWS encoding / decoding helpers (base64url, RFC 7515)
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode, restoring padding."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _canonical_json(obj: Any) -> bytes:
    """Encode obj as canonical JSON for signing.

    Uses sort_keys + minimal separators so the same payload always
    produces the same byte sequence — required for signature stability
    across mint / verify.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# CapabilityClaims <-> dict conversion
# ---------------------------------------------------------------------------


def _strip_none(obj: Any) -> Any:
    """Recursively strip None-valued keys from a nested dict/list
    structure. Preserves byte-parity of the canonical JSON across
    additions of new optional fields — unset fields don't appear in
    the JSON, so existing pinned-fixture digests stay valid as long
    as the existing fields' values are unchanged.

    Added 2026-05-17 alongside `CapabilityScope.create_for_owner`
    (the agents:create canonical scope-extension): without this, all
    capabilities would emit `"create_for_owner": null` inside their
    scope object, bloating every JWS by ~25 bytes and breaking every
    byte-parity test downstream. The recursive strip means the new
    field only appears in JSON when actually set."""
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(x) for x in obj]
    return obj


def _claims_to_dict(claims: CapabilityClaims) -> dict[str, Any]:
    """Convert a CapabilityClaims dataclass to a dict ready for JSON
    serialization. Strips None-valued optional fields recursively so
    they don't bloat the JWS payload OR break byte-parity tests."""
    raw = asdict(claims)
    return _strip_none(raw)


def _dict_to_claims(d: dict[str, Any]) -> CapabilityClaims:
    """Convert a dict (parsed from JWS payload) back to CapabilityClaims.

    Validates the shape; raises ValueError on missing required fields.
    """
    required = {"iss", "sub", "aud", "iat", "nbf", "exp", "jti", "cap", "purpose"}
    missing = required - set(d.keys())
    if missing:
        raise ValueError(f"Capability JWT missing required claims: {sorted(missing)}")

    cap_raw = d["cap"]
    cap = CapabilityClause(
        tier=cap_raw["tier"],
        registry_version=cap_raw["registry_version"],
        groups=list(cap_raw.get("groups", [])),
        scope=CapabilityScope(
            env=list(cap_raw.get("scope", {}).get("env", [])),
            services=list(cap_raw.get("scope", {}).get("services", [])),
            repos=list(cap_raw.get("scope", {}).get("repos", [])),
            create_for_owner=cap_raw.get("scope", {}).get("create_for_owner"),
            chat_room_id=cap_raw.get("scope", {}).get("chat_room_id"),
            target_user_id=cap_raw.get("scope", {}).get("target_user_id"),
            pairing_code=cap_raw.get("scope", {}).get("pairing_code"),
            payload_sha256=cap_raw.get("scope", {}).get("payload_sha256"),
        ),
        allow_actions=list(cap_raw.get("allow_actions", [])),
        deny_actions=list(cap_raw.get("deny_actions", [])),
        limits=CapabilityLimits(
            per_hour=dict(cap_raw.get("limits", {}).get("per_hour", {})),
            per_day=dict(cap_raw.get("limits", {}).get("per_day", {})),
            per_session=dict(cap_raw.get("limits", {}).get("per_session", {})),
        ),
    )

    return CapabilityClaims(
        iss=d["iss"],
        sub=d["sub"],
        aud=list(d["aud"]),
        iat=int(d["iat"]),
        nbf=int(d["nbf"]),
        exp=int(d["exp"]),
        jti=d["jti"],
        cap=cap,
        purpose=d["purpose"],
        parent_cap=d.get("parent_cap"),
        max_uses=d.get("max_uses"),
        # Phase 2.0.C wave C.2: parent_profile is an optional v2.0
        # claim. Reader tolerates absence (defaults to None — v1.x /
        # v2.0.B path); reader picks it up when present (v2.0.C-and-
        # later mints).
        parent_profile=d.get("parent_profile"),
    )


# ---------------------------------------------------------------------------
# JWS parse / verify / mint
# ---------------------------------------------------------------------------


def parse_jws(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split a JWS token into (header_dict, payload_dict, signature_bytes,
    signing_input_bytes).

    signing_input_bytes is `header_b64url + "." + payload_b64url` as bytes
    — this is the input that gets hashed and signed.

    Raises ValueError on malformed JWS.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Malformed JWS: expected 3 dot-separated parts, got {len(parts)}"
        )
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Malformed JWS: {e}") from e

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return header, payload, signature, signing_input


def verify_jws(
    token: str,
    expected_pubkey: bytes,
    expected_aud: str | None = None,
    now: int | None = None,
    *,
    state_dir: Path | None = None,
) -> CapabilityClaims:
    """Verify a capability JWS and return the parsed claims.

    Validation steps (all must pass):
      1. JWS structure is well-formed
      2. Header declares `alg: ES256K` and `typ: JWT`
      3. Signature recovers to:
         - the named profile's `derived_pubkey_hex` when the JWS
           payload has a non-None `parent_profile` claim (Phase 2.0.C
           wave C.2 extension — the JWS was minted under a child
           profile's derived key, NOT the operator's master root)
         - `expected_pubkey` otherwise (v1.x / v2.0.B behavior —
           JWS was minted under the operator's master key)
      4. Standard claims time bounds (nbf <= now < exp) using the supplied
         `now` (or current time if None)
      5. If expected_aud is provided, verify it appears in claims.aud

    Raises ValueError on any validation failure with a category prefix
    so callers can distinguish (signature / claims / shape).

    Note: this function does NOT consult the revocation list (the
    capability-JWS jti revocation tracked in the StateStore). Callers
    are responsible for checking jti against revocation state before
    accepting the capability for use. The parent_profile lookup DOES
    consult the Profile.revoked flag in MasterIdentity — that's
    profile-level revocation, distinct from per-JWS jti revocation.

    Args:
        token: the 3-part JWS string.
        expected_pubkey: the operator's master pubkey (64-byte raw
            X || Y). Used as the signature-recovery target when the
            JWS has no parent_profile claim.
        expected_aud: optional audience check.
        now: optional time override.
        state_dir: optional bootloader state directory. Required ONLY
            when the JWS has a non-None parent_profile claim — verifier
            loads `master_identity.json` from this directory to look
            up the profile's derived pubkey. When the JWS has no
            parent_profile claim (the common v1.x / v2.0.B case),
            state_dir is unused and may be None.

    Raises:
        ValueError: on any verification failure. Category prefixes:
            "shape:" for header/JWS shape issues, "signature:" for
            signature recovery failures, "claims:" for time bounds /
            audience / parent_profile lookup failures.
    """
    header, payload, signature, signing_input = parse_jws(token)

    # 2. Header validation
    if header.get("alg") != "ES256K":
        raise ValueError(
            f"shape: unsupported alg '{header.get('alg')}' (expected ES256K)"
        )
    if header.get("typ") not in ("JWT", None):
        raise ValueError(f"shape: unsupported typ '{header.get('typ')}'")

    # 3. Signature validation — uses recto.ethereum's secp256k1 primitives.
    # ES256K signs over SHA-256(signing_input); recovery_id is not part
    # of the canonical 64-byte JWS signature so we try both rec_id
    # candidates by constructing synthetic 65-byte r||s||v rsv
    # signatures (the format recto.ethereum.recover_public_key expects)
    # and accept if either recovers to expected_pubkey.
    digest = hashlib.sha256(signing_input).digest()
    if len(signature) != 64:
        raise ValueError(
            f"signature: expected 64-byte raw r||s, got {len(signature)} bytes"
        )

    # Phase 2.0.C wave C.2: parent_profile dispatch. When the JWS
    # payload has a non-None parent_profile claim, the JWS was minted
    # under a child profile's derived secp256k1 key (NOT the operator's
    # master root). Look up the profile in master_identity.json and
    # use ITS derived_pubkey_hex as the recovery target. Reject specific
    # failure modes with clear category-prefixed error strings so
    # callers can distinguish "JWS shape OK but profile state is wrong"
    # from "JWS doesn't recover to anything."
    parent_profile_claim = payload.get("parent_profile")
    target_pubkey: bytes
    if parent_profile_claim is None:
        # v1.x / v2.0.B path — recover against operator master root.
        target_pubkey = expected_pubkey
    else:
        if not isinstance(parent_profile_claim, str) or not parent_profile_claim:
            raise ValueError(
                f"claims: parent_profile must be a non-empty string when "
                f"present, got {parent_profile_claim!r}"
            )
        if state_dir is None:
            raise ValueError(
                "claims: JWS has parent_profile claim "
                f"{parent_profile_claim!r} but state_dir kwarg was not "
                "supplied to verify_jws; verifier cannot look up profile "
                "derived_pubkey_hex without it. Pass state_dir = "
                "<bootloader state directory> to enable parent_profile "
                "dispatch."
            )
        # NOTE: imported here to avoid a hard dep on recto.profile.store
        # at module load — the capability package can be imported for
        # type-only use cases (manifest tooling, etc.) without dragging
        # in the profile-store layer.
        from recto.profile.store import load_master_identity

        try:
            mi = load_master_identity(state_dir=state_dir)
        except OSError as exc:
            raise ValueError(
                f"claims: state_dir {state_dir!r} master_identity.json "
                f"read failed: {exc}"
            ) from exc
        if mi is None:
            raise ValueError(
                f"claims: JWS parent_profile "
                f"{parent_profile_claim!r} cannot be resolved -- no "
                f"master is bootstrapped at state_dir {state_dir!r}"
            )
        matching_profile = None
        for p in mi.profiles:
            if p.profile_id == parent_profile_claim:
                matching_profile = p
                break
        if matching_profile is None:
            raise ValueError(
                f"claims: parent_profile {parent_profile_claim!r} not "
                f"found under master "
                f"{mi.master_pubkey_hex[:8]}...{mi.master_pubkey_hex[-8:]}"
            )
        if matching_profile.revoked:
            raise ValueError(
                f"claims: parent_profile {parent_profile_claim!r} is "
                f"revoked (kind={matching_profile.kind!r}, "
                f"display_name={matching_profile.display_name!r})"
            )
        if matching_profile.derived_pubkey_hex is None:
            raise ValueError(
                f"claims: parent_profile {parent_profile_claim!r} has "
                f"no derived_pubkey_hex (v2.0.B-era row created before "
                f"Phase 2.0.C wave C.1's schema bump). Run the future "
                f"`recto profile derive-pubkey {parent_profile_claim}` "
                f"admin command to opt-in backfill, OR re-create the "
                f"profile via `recto profile create` so the v2.0.C "
                f"flow captures the pubkey at create time."
            )
        try:
            target_pubkey = bytes.fromhex(matching_profile.derived_pubkey_hex)
        except ValueError as exc:
            # Shouldn't happen — store.py validates hex shape on load,
            # but defense-in-depth in case of corrupt rows somehow
            # slipping through.
            raise ValueError(
                f"claims: parent_profile {parent_profile_claim!r} has "
                f"malformed derived_pubkey_hex on disk: {exc}"
            ) from exc

    # NOTE: imported here to avoid a hard dep on recto.ethereum at module
    # load time — the capability package can be imported for type-only
    # use cases (manifest tooling, etc.) without pulling the secp256k1
    # primitives.
    from recto.ethereum import recover_public_key

    matched = False
    for recovery_id in (0, 1):
        # Append legacy v byte (27 + rec_id) to make the 65-byte rsv
        # form recover_public_key expects.
        synthetic_rsv = signature + bytes([27 + recovery_id])
        try:
            recovered = recover_public_key(digest, synthetic_rsv)
            if recovered == target_pubkey:
                matched = True
                break
        except Exception:
            continue

    if not matched:
        if parent_profile_claim is None:
            raise ValueError(
                "signature: did not recover to expected operator public key"
            )
        raise ValueError(
            f"signature: did not recover to parent_profile "
            f"{parent_profile_claim!r} derived_pubkey_hex (the JWS may "
            f"have been minted under a different key or the canonical "
            f"signing input may have drifted between mint + verify)"
        )

    # 4. Time bounds
    if now is None:
        now = int(time.time())
    nbf = int(payload.get("nbf", 0))
    exp = int(payload.get("exp", 0))
    if now < nbf:
        raise ValueError(f"claims: token nbf={nbf} is in the future (now={now})")
    if now >= exp:
        raise ValueError(f"claims: token exp={exp} has passed (now={now})")

    # 5. Audience check (if requested)
    if expected_aud is not None:
        aud = payload.get("aud", [])
        if not isinstance(aud, list) or expected_aud not in aud:
            raise ValueError(
                f"claims: expected_aud '{expected_aud}' not in token aud {aud}"
            )

    # 6. Convert to typed claims
    return _dict_to_claims(payload)


def build_signing_input(claims: CapabilityClaims) -> tuple[bytes, str, str]:
    """Build the unsigned signing input for a capability JWT.

    Returns ``(digest, header_b64, payload_b64)``:
      - ``digest``: 32-byte SHA-256(signing_input) — what the signer
        signs over
      - ``header_b64``: base64url-encoded JWS header (deterministic)
      - ``payload_b64``: base64url-encoded JWS payload (deterministic)

    Used by:
      - Phone-side mint flow (Wave B) — signing happens in the phone's
        Secure Enclave, which produces the 64-byte r||s and assembles
        the final JWS string ``f"{header_b64}.{payload_b64}.{sig_b64}"``
      - Tests and dev fixtures — pre-mint inputs for cross-checking
        against external signers
    """
    header = {"alg": "ES256K", "typ": "JWT"}
    header_b64 = _b64url_encode(_canonical_json(header))
    payload_b64 = _b64url_encode(_canonical_json(_claims_to_dict(claims)))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    digest = hashlib.sha256(signing_input).digest()
    return digest, header_b64, payload_b64


def assemble_jws(header_b64: str, payload_b64: str, signature: bytes) -> str:
    """Assemble the final JWS string from already-encoded header, payload,
    and a 64-byte raw r||s signature.

    Useful for the phone-side mint flow (Wave B) where the Secure
    Enclave produces the signature and the host assembles the JWS, and
    for tests where an external signer produces the signature.

    Raises ValueError if the signature is not 64 bytes.
    """
    if len(signature) != 64:
        raise ValueError(
            f"signature must be 64 raw bytes (r||s); got {len(signature)}"
        )
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def mint_jws(claims: CapabilityClaims, private_key: bytes) -> str:
    """Python-side mint helper.

    NOT IMPLEMENTED at Wave A — recto.ethereum is verify-only (no
    secp256k1 sign primitive yet); production minting always happens on
    the phone enclave with biometric gating, so the operator's private
    key never leaves the phone.

    Wave A continuation work:
      - Either add a ``sign_digest`` primitive to recto.ethereum
        (pure-stdlib ECDSA with RFC 6979 deterministic-k, sister to the
        existing ``recover_public_key``)
      - Or stand up a small script-only sign helper for test fixtures
        and document that production minting is phone-side-only

    Until Wave A continuation lands, tests that need a known JWT use
    pre-generated fixture strings (pinned via external cross-check)
    rather than minting via this function.
    """
    raise NotImplementedError(
        "Python-side mint_jws is not implemented at Wave A. "
        "Production minting is phone-enclave-only. "
        "See docstring for Wave A continuation TODO."
    )
