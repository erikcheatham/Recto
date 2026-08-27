"""Bootloader state persistence: phones, sessions, pending requests.

State files live under `~/.recto/bootloader/` (Linux/macOS) or
`%APPDATA%\\recto\\bootloader\\` (Windows). Three JSON files:

- `phones.json` -- registered phones (phone_id, device_label, public
  key, registered_at, last_seen).
- `sessions.json` -- cached session JWTs keyed by (service, secret).
  These are SIGNED tokens, not raw secrets; loss exposes nothing the
  phone hasn't already approved for the session lifetime.
- `pending.json` -- in-flight sign requests waiting for phone approval.
  Cleared on bootloader restart (in-flight requests fail rather than
  carrying over).

Concurrency: a single bootloader process owns the state files. There's
no cross-process locking; if you run two bootloaders on the same host
they will fight. The launcher is responsible for spawning exactly one
bootloader per service.

Threat model: state files are ACL-tightened to operator-only on
Linux/macOS (chmod 0600) and DPAPI-machine encrypted on Windows. An
attacker with operator-account access reads the public keys (not
sensitive) and active session JWTs (sensitive but bounded by
JWT.exp). Mitigation: short JWT lifetimes, manual revocation from
phone app.
"""

from __future__ import annotations

import base64
import json
import secrets
from abc import ABC, abstractmethod
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "PhoneRegistration",
    "Session",
    "PendingRequest",
    "CapabilityResult",
    "RevocationEntry",
    "AppContext",
    "StateStore",
    "default_state_dir",
]


def default_state_dir() -> Path:
    """Return the per-platform default state directory, creating it if
    necessary. Override via `RECTO_BOOTLOADER_STATE_DIR` env var (mainly
    for tests; production should use the default)."""
    override = os.environ.get("RECTO_BOOTLOADER_STATE_DIR")
    if override:
        d = Path(override)
    elif os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise RuntimeError(
                "APPDATA not set; cannot determine bootloader state dir"
            )
        d = Path(appdata) / "recto" / "bootloader"
    else:
        d = Path.home() / ".recto" / "bootloader"
    d.mkdir(parents=True, exist_ok=True)
    # Tighten ACLs on Linux/macOS. On Windows the dir inherits ACL from
    # %APPDATA% which is already operator-private.
    if os.name != "nt":
        os.chmod(d, 0o700)
    return d


# --------------------------------------------------------------------------
# Genesis member key algorithms (GATE 5c-c, 2026-08-19)
#
# WHY THIS EXISTS: the genesis store originally hardcoded "32 bytes, raw
# Ed25519". That was true of the PASSPHRASE member and of nothing else -- a
# secp256k1 RECOVERY device could not be sealed at all. The tag is added now,
# with ONE member sealed, because the same logic that governed every other
# decision in this gate applies: a schema is cheap while the set is small and
# expensive once a second member depends on it.
#
# THE TAG IS EXPLICIT AND NEVER INFERRED. A 33-byte key is not "probably
# secp256k1" -- reading an algorithm out of a length is how a key gets
# verified under the wrong curve, and the caller always knows what it sealed.
# THIS SET IS EXACTLY WHAT `sessions.verify_signature` CAN VERIFY, AND THAT IS
# THE WHOLE RULE. A genesis member is a thing that SIGNS; an algorithm the
# verifier cannot read is a member that can be sealed and never used, which is
# only ever discovered at recovery.
GENESIS_ALGORITHMS: dict[str, tuple[int, ...]] = {
    "ed25519": (32,),
    # NIST P-256 (SECP256R1), 64 raw bytes uncompressed X || Y. iOS Secure
    # Enclave's native algorithm, so a recovery iPhone will usually be this.
    "ecdsa-p256": (64,),
}

# secp256k1 IS DELIBERATELY ABSENT, and its removal is the point rather than an
# oversight.
#
# It was here for one reason: the assumption that the operator ROOT (secp256k1,
# BIP-39 master) would participate in a tier-3 quorum. **The operator ruled on
# 2026-08-19 that it does not** -- the tier-3 set is the RECOVERY PHONE plus the
# PASSPHRASE, and the master key stays behind BIP-39 rather than signing
# challenges online. Genesis members are therefore phones and the passphrase,
# and neither uses secp256k1.
#
# Three things fell out of that, all of them simplifications:
#   * A key with no signer is a verb with no caller. Keeping the entry would
#     leave a sealable algorithm that no verifier here reads -- the same shape
#     as an ignore rule for a file that cannot exist.
#   * `ecdsa-p256` is ALSO 64 raw bytes. Registering both would have put two
#     different curves on one length, which is survivable only because the tag
#     is explicit -- but not having the collision beats guarding it.
#   * The whole "which digest does a secp256k1 signer commit to" question
#     dissolves rather than needing an answer.
#
# Re-adding it is a decision, not a merge: it would mean the master key signs
# online, which is the property the operator deliberately gave up.

# The algorithm assumed for a member written before the tag existed. Any such
# member IS Ed25519 -- the old writer validated `len(pubkey) != 32` and
# refused everything else -- so this is a recorded fact, not a guess.
GENESIS_LEGACY_ALGORITHM = "ed25519"


@dataclass(frozen=True, slots=True)
class GenesisMember:
    """A sealed member of the operator SET, with the curve it was sealed on."""

    kind: str
    pubkey: bytes
    algorithm: str


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def validate_genesis_pubkey(pubkey: bytes | None, algorithm: str) -> str:
    """Normalise + check an algorithm/pubkey pair. Returns the algorithm.

    Raises ValueError rather than sealing something unusable -- a member whose
    key cannot be verified is discovered at RECOVERY, which is the one moment
    it must not be discovered.
    """
    algo = (algorithm or "").strip().lower()
    if algo not in GENESIS_ALGORITHMS:
        raise ValueError(
            f"unknown genesis member algorithm {algorithm!r}; "
            f"known: {', '.join(sorted(GENESIS_ALGORITHMS))}"
        )
    valid = GENESIS_ALGORITHMS[algo]
    if pubkey is None or len(pubkey) not in valid:
        got = len(pubkey) if pubkey is not None else 0
        raise ValueError(
            f"genesis member pubkey for {algo} must be "
            f"{' or '.join(str(v) for v in valid)} bytes; got {got}"
        )

    # LENGTH IS NOT ENOUGH, AND THE GAP IS EXACTLY THE FAILURE THIS FUNCTION
    # EXISTS TO PREVENT. A 64-byte value that is not a point on P-256 passes
    # every length check and is REFUSED BY THE VERIFIER -- so the store would
    # happily seal a member that can never sign, and the operator would find
    # out at recovery.
    #
    # So the key is loaded through the SAME decoder the signature path uses.
    # "Sealable" and "verifiable" stop being two lists that have to agree and
    # become one check. Lazy import: `sessions` imports nothing from this
    # module, but keeping the dependency inside the call avoids binding the
    # store's import graph to the verifier's.
    try:
        import base64

        from recto.bootloader.sessions import _public_key_from_b64u

        _public_key_from_b64u(
            base64.urlsafe_b64encode(bytes(pubkey)).rstrip(b"=").decode("ascii"),
            algorithm=algo,
        )
    except Exception as exc:
        # Every length check already ran above, so anything raised here came
        # from the decoder. Wrap it ALL -- including cryptography's own
        # ValueError, which says "Point is not on the curve specified" and
        # gives a caller no idea it was sealing a genesis member.
        raise ValueError(
            f"genesis member pubkey is not a usable {algo} key: {exc}. "
            f"It is the right length but the verifier cannot load it, so "
            f"sealing it would produce a member that can never sign."
        ) from exc
    return algo


@dataclass(frozen=True, slots=True)
class PhoneRegistration:
    """One registered phone."""

    phone_id: str
    device_label: str
    public_key_b64u: str
    supported_algorithms: tuple[str, ...]
    registered_at_unix: int
    last_seen_unix: int
    # Silent-push wake routing (production-scale wave C). Optional +
    # additive so pre-existing phones.json blobs load unchanged: phones
    # that never supplied a token stay poll-only. Values are
    # byte-for-byte what the phone app sends at registration
    # ("apns" / "fcm" + the platform token); rotated via
    # POST /v0.4/manage/push_token. The token is delivery-routing
    # metadata, not key material -- but keep it out of logs anyway.
    push_token: str | None = None
    push_platform: str | None = None

    @classmethod
    def new(
        cls,
        *,
        device_label: str,
        public_key_b64u: str,
        supported_algorithms: tuple[str, ...],
        push_token: str | None = None,
        push_platform: str | None = None,
    ) -> PhoneRegistration:
        now = int(time.time())
        return cls(
            phone_id=str(uuid.uuid4()),
            device_label=device_label,
            public_key_b64u=public_key_b64u,
            supported_algorithms=supported_algorithms,
            registered_at_unix=now,
            last_seen_unix=now,
            push_token=push_token,
            push_platform=push_platform,
        )


@dataclass(frozen=True, slots=True)
class Session:
    """A cached session JWT for a (service, secret) pair."""

    service: str
    secret: str
    phone_id: str
    jwt: str
    expires_at_unix: int
    issued_at_unix: int
    max_uses: int
    uses_so_far: int = 0

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at_unix

    @property
    def is_exhausted(self) -> bool:
        if self.max_uses <= 0:
            return False  # 0 = unlimited
        return self.uses_so_far >= self.max_uses

    def needs_renewal(self, threshold: float = 0.8) -> bool:
        """True when the session has consumed `threshold` of its
        lifetime or max_uses (default 80%). The bootloader uses this to
        proactively renew sessions before they expire/exhaust, avoiding
        latency spikes at the boundary."""
        now = time.time()
        lifetime = self.expires_at_unix - self.issued_at_unix
        consumed_lifetime_pct = (now - self.issued_at_unix) / max(lifetime, 1)
        if consumed_lifetime_pct >= threshold:
            return True
        if self.max_uses > 0:
            consumed_uses_pct = self.uses_so_far / self.max_uses
            if consumed_uses_pct >= threshold:
                return True
        return False


@dataclass(frozen=True, slots=True)
class AppContext:
    """Operator-administered identity of an application that submits
    requests through Recto. The phone displays this at approval time
    so the operator knows which app is asking before granting
    capability / signing operations.

    Recto is public-OSS, designed to be used alongside any
    application -- a single Recto-equipped phone might be paired
    with bootloaders for MyService, a banking app, a self-hosted
    password manager, a CI runner that needs commit signing, etc.
    Without ``AppContext``, the operator would see opaque agent_ids
    on the approval card ("agent:darwin@staging") and have to infer
    which app each one belongs to. With it, the phone can show the
    app's name, brief description, icon, and homepage URL at the
    top of every approval card.

    Each consumer registers its ``AppContext`` once at deploy time
    (typically via ``service.yaml`` or a CLI command); the bootloader
    injects the matching ``AppContext`` into every ``PendingRequest``
    that flows from that consumer. The phone trusts the bootloader's
    identification (the Ed25519 envelope already proves the request
    came from the paired bootloader); within that trust scope,
    ``AppContext`` is authoritative.

    Fields:

    - ``app_id``: stable machine-readable identifier
      (``"myservice"``, ``"mytradingapp"``, ``"consumer-banking"``, etc.).
      Used by the phone for dedup / per-app preferences (e.g.
      "always show this app's request prominently"). Required.
    - ``app_name``: human-readable display name
      (``"MyService"``, ``"MyTradingApp Trading Lens"``). Required.
    - ``app_description``: one-line tagline rendered under the name
      ("Media review platform", "Position-aware trading lens").
      Empty string is acceptable.
    - ``app_url``: homepage / docs link. Operator can verify the
      app is what it claims to be by visiting. Optional.
    - ``app_icon_url``: image URL for phone-side rendering. The
      phone fetches + caches the icon at registration time;
      subsequent approval cards render from cache. Optional.
    - ``app_version``: currently-running version of the app, for
      audit / debugging. Surfaces in the operator UI but isn't used
      for authorization decisions. Optional.

    Frozen + slots-equipped to match the rest of the StateStore's
    dataclass conventions. Operator-administered registries on
    ``BootloaderConfig.principal_apps`` carry instances; the
    bootloader looks up by abstract principal-id (cap_agent_id for
    capability_request, service-name fallback for other
    request kinds).
    """

    app_id: str
    app_name: str
    app_description: str = ""
    app_url: str | None = None
    app_icon_url: str | None = None
    app_version: str | None = None

    def __post_init__(self) -> None:
        if not self.app_id or not isinstance(self.app_id, str):
            raise ValueError("AppContext.app_id must be a non-empty string")
        if not self.app_name or not isinstance(self.app_name, str):
            raise ValueError("AppContext.app_name must be a non-empty string")


@dataclass(frozen=True, slots=True)
class PendingRequest:
    """A sign request waiting for phone approval.

    Kind values that ship today:

    - ``"session_issuance"`` — phone signs a 24h JWT for the
      (service, secret) pair. Existing v0.4.0 flow.
    - ``"single_sign"`` — phone signs a one-shot payload. Existing
      v0.4.0 flow.
    - ``"totp_provision"`` / ``"totp_generate"`` — TOTP universal-vault
      flow (round 5).
    - ``"webauthn_assert"`` — passkey browser-login bridge (round 8).
    - ``"pkcs11_sign"`` / ``"pgp_sign"`` — v0.4.1 protocol seams.
    - ``"eth_sign"`` — Ethereum signing capability (v0.5+ groundwork).
      Populates the seven ``eth_*`` fields below; uses the same
      ``payload_hash_b64u`` Ed25519 envelope as ``single_sign`` so
      the bootloader still proves the response came from the paired
      phone, and additionally surfaces ``eth_signature_rsv`` on the
      respond body for the consumer (smart contract / off-chain
      verifier) to validate.
    - ``"btc_sign"`` — Bitcoin-family signing (BTC / LTC / DOGE / BCH).
      Populates the seven ``btc_*`` fields including the ``btc_coin``
      discriminator. Surfaces ``btc_signature_base64`` (a 65-byte
      BIP-137 compact signature) on the respond body.
    - ``"ed_sign"`` — Ed25519 chains signing (SOL / XLM / XRP). Wave-8
      addition. Populates the six ``ed_*`` fields including the
      ``ed_chain`` discriminator. Surfaces ``ed_signature_base64`` (a
      raw 64-byte ed25519 signature) AND ``ed_pubkey_hex`` (the 32-byte
      ed25519 public key, 64 hex chars) on the respond body. The
      explicit pubkey is required because XRP addresses are one-way
      HASH160s of the pubkey — verifiers can't recover pubkey from
      address — so for protocol uniformity all three chains carry
      the pubkey explicitly even though SOL and XLM addresses ARE
      reversible.
    - ``"capability_request"`` — Phase 5 Wave B routing primitive. An
      external agent (e.g. a downstream consumer's chatbot orchestrator)
      POSTs a proposed ``CapabilityClaims`` JSON to
      ``/v0.4/capability/request``; the bootloader canonical-JSON-
      encodes the claims into JWS header_b64 + payload_b64 segments
      and stores them on the PendingRequest's two ``cap_*`` fields.
      Phone signs ``SHA-256(f"{cap_header_b64}.{cap_payload_b64}")``
      with the operator's BIP-39-derived secp256k1 key (the same key
      that signs ETH messages — same operator identity for both
      surfaces). Response carries the 64-byte raw r||s on
      ``cap_signature_b64u``; bootloader assembles the final 3-part
      JWS via ``recto.capability.jwt.assemble_jws`` and stores it for
      the requesting agent to fetch via
      ``GET /v0.4/capability/result/<request_id>``. The Ed25519
      envelope still applies (proves paired-phone identity); the cap
      signature is the actual JWS that downstream verifiers check.
    """

    request_id: str
    kind: str
    service: str
    secret: str
    phone_id: str
    operation_description: str
    payload_hash_b64u: str
    child_pid: int
    child_argv0: str
    requested_at_unix: int
    expires_at_unix: int

    # ETH-specific context (kind == "eth_sign"). All optional with
    # default None so non-ETH PendingRequests keep working without
    # construction-site changes. The seven fields mirror the C#
    # `PendingRequestContext` ETH additions in
    # `Recto.Shared.Protocol.V04`. See `docs/v0.4-protocol.md`
    # "Ethereum signing capability (v0.5+)".
    eth_chain_id: int | None = None
    eth_message_kind: str | None = None  # "personal_sign" | "typed_data" | "transaction"
    eth_address: str | None = None  # 0x-prefixed lowercase hex (40 chars after 0x)
    eth_derivation_path: str | None = None  # default "m/44'/60'/0'/0/0"
    eth_message_text: str | None = None  # for personal_sign
    eth_typed_data_json: str | None = None  # for typed_data (EIP-712)
    eth_transaction_json: str | None = None  # for transaction (RLP) — reserved

    # BTC-specific context (kind == "btc_sign"). All optional with
    # default None. Six fields mirror the C# `PendingRequestContext`
    # BTC additions in `Recto.Shared.Protocol.V04`. See
    # `docs/v0.4-protocol.md` "Bitcoin signing capability (v0.5+)".
    # Same secp256k1 curve as ETH; different BIP-44 path tree
    # (m/84'/0'/0'/0/N for native-SegWit P2WPKH).
    btc_network: str | None = None  # "mainnet" | "testnet" | "signet" | "regtest"
    btc_message_kind: str | None = None  # "message_signing" | "psbt"
    btc_address: str | None = None  # bech32 (P2WPKH) or Base58Check (legacy / nested)
    btc_derivation_path: str | None = None  # default "m/84'/0'/0'/0/0"
    btc_message_text: str | None = None  # for message_signing
    btc_psbt_base64: str | None = None  # for psbt (BIP-174) — reserved
    # Wave-7: Bitcoin-family coin discriminator. Same `btc_sign`
    # credential kind covers BTC + LTC + DOGE + BCH; this field
    # selects which. Absent / None defaults to "btc" for backward
    # compat with v0.5 launchers that pre-date the multi-coin
    # extension. Mirrors C# `BtcCoin` constants in
    # `Recto.Shared.Protocol.V04`.
    btc_coin: str | None = None  # "btc" | "ltc" | "doge" | "bch"

    # ED25519-chain context (kind == "ed_sign"). All optional with
    # default None. Six fields mirror the C# `PendingRequestContext`
    # ED additions in `Recto.Shared.Protocol.V04`. See
    # `docs/v0.4-protocol.md` "Ed25519 chains signing capability
    # (v0.6+)". Same `ed_sign` credential kind covers SOL, XLM, and
    # XRP-ed25519; the `ed_chain` discriminator selects which.
    # Per-chain BIP-44 / SLIP-0010 paths and address encodings live
    # in the chain-specific Python modules
    # (`recto.solana` / `recto.stellar` / `recto.ripple`) and on the
    # phone-side C# signing service.
    ed_chain: str | None = None  # "sol" | "xlm" | "xrp"
    ed_message_kind: str | None = None  # "message_signing" | "transaction"
    ed_address: str | None = None  # chain-encoded operator-approved address
    ed_derivation_path: str | None = None  # chain-default if absent (see new_ed)
    ed_message_text: str | None = None  # for message_signing
    ed_payload_hex: str | None = None  # for transaction (reserved)

    # TRON-specific context (kind == "tron_sign"). All optional with
    # default None. Six fields mirror the C# `PendingRequestContext`
    # TRON additions in `Recto.Shared.Protocol.V04` (Wave 9 part 2).
    # See `docs/v0.4-protocol.md` "TRON signing capability (v0.6+)".
    # TRON shares the same secp256k1 curve as ETH and BTC; what's
    # different is the address encoding (base58check with version
    # byte 0x41) and the signed-message preamble (TIP-191's
    # "TRON Signed Message:\n" instead of EIP-191's "Ethereum
    # Signed Message:\n"). The phone reuses the same BIP-39 mnemonic
    # at SLIP-0044 coin-type 195: m/44'/195'/0'/0/N.
    tron_network: str | None = None  # "mainnet" | "shasta" | "nile"
    tron_message_kind: str | None = None  # "message_signing" | "transaction"
    tron_address: str | None = None  # base58check, T-prefixed, 34 chars
    tron_derivation_path: str | None = None  # default "m/44'/195'/0'/0/0"
    tron_message_text: str | None = None  # for message_signing
    tron_payload_hex: str | None = None  # for transaction (reserved)

    # Capability-request context (kind == "capability_request",
    # Phase 5 Wave B). All optional with default None. The two
    # ``cap_*_b64`` fields are the canonical-JSON-encoded JWS header
    # and payload segments — the phone's signing input is
    # ``SHA-256(f"{cap_header_b64}.{cap_payload_b64}".encode("ascii"))``
    # which matches ``recto.capability.jwt.build_signing_input``'s
    # output exactly. The bootloader caches them so it can assemble
    # the final 3-part JWS once the phone returns the 64-byte r||s
    # signature; the agent then fetches the assembled JWS via the
    # result endpoint. ``cap_agent_id`` carries the requesting agent's
    # logical identifier (the ``X-Recto-Agent-Id`` header value from
    # the queue request) so audit logs can attribute requests to the
    # right principal even when multiple agents share one phone. See
    # ``docs/v0.4-protocol.md`` "Capability-request flow (v0.6+)".
    cap_header_b64: str | None = None
    cap_payload_b64: str | None = None
    cap_agent_id: str | None = None

    # Grant-window re-stamp (v0.6+ queued-card flow). A capability
    # request created for a HUMAN APPROVAL QUEUE can sit for minutes
    # before the operator opens it, but the authority window the JWS
    # carries should be short (the requester's verifier enforces a
    # lifetime ceiling). Two clocks with two meanings: the request TTL
    # (``expires_at_unix``) bounds how long the CARD may wait; the
    # grant TTL below bounds how long the signed AUTHORITY lives.
    # When ``cap_grant_ttl_seconds`` is set, the bootloader rebuilds
    # iat/nbf/exp (iat = nbf = now, exp = now + grant_ttl) ONCE, at the
    # first phone fetch of the pending list — card-open time — and
    # records the moment in ``cap_window_stamped_at_unix``. Stamping
    # exactly once keeps the bytes stable between the fetch the phone
    # rendered and the signature it returns; a card opened but not
    # approved within the grant window yields a JWS the verifier
    # refuses as expired, which is the designed failure (re-request).
    cap_grant_ttl_seconds: int | None = None
    cap_window_stamped_at_unix: int | None = None

    # Phase 5 Wave C part 3: app context for the phone's approval
    # render. Bootloader injects from BootloaderConfig.principal_apps
    # at queue time, looked up by:
    #   - cap_agent_id when set (capability_request flow)
    #   - service when cap_agent_id is None (other phone-rendered kinds)
    # Phone displays the app's icon / name / description at the top of
    # every approval card so the operator knows which app is asking.
    # None when no matching registration exists; the phone shows an
    # "Unknown app" warning banner in that case so unregistered agents
    # are visible rather than silently approved.
    app_context: AppContext | None = None

    # Profile-create context (kind == "profile_create", Phase 2.0.B
    # integration). All optional with default None. The candidate
    # fields describe the proposed new child profile under the
    # operator's master; phone responds by signing an attestation
    # over the canonical-JSON encoding of these fields PLUS the
    # phone-derived child_pubkey_hex (proving the child key was
    # actually derived from the master mnemonic at the named path).
    # Bootloader verifies the signature against the operator pubkey
    # from vault_root.json, then calls profile.manage.create_child_profile
    # to persist the new Profile.
    candidate_profile_id: str | None = None
    candidate_kind: str | None = None
    candidate_display_name: str | None = None
    candidate_derivation_purpose: int | None = None
    candidate_derivation_coin_type: int | None = None
    candidate_derivation_index: int | None = None
    # Optional metadata fields passed through to the persisted Profile
    # row when the create succeeds. None means "operator-configurable
    # default" at the manage.py layer.
    candidate_theme_hint: str | None = None
    candidate_scim_provider: str | None = None

    # Profile-add-device context (kind == "profile_add_device",
    # Phase 2.0.C wave C.5 integration). All optional with default
    # None. The addev_* fields describe the target profile + new
    # device; phone responds by signing a master-attestation over
    # the canonical-JSON encoding of (profile_id, new_phone_id,
    # added_at_unix, request_id). Bootloader verifies the signature
    # against the operator pubkey from vault_root.json, then calls
    # profile.manage.profile_add_device to atomic-write the appended
    # phone_id to the target profile's device_ids tuple in
    # master_identity.json.
    #
    # Wire-shape simpler than profile_create because the full
    # signing-input is known at queue time (no phone-supplied field
    # needs injection at respond time). cap_payload_b64 stashes the
    # already-canonical signing input directly.
    addev_profile_id: str | None = None
    addev_new_phone_id: str | None = None
    addev_new_phone_label: str | None = None

    # Profile-revoke-device context (kind == "profile_revoke_device",
    # Phase 2.0.C wave C.6 integration). All optional with default
    # None. The revdev_* fields describe the target profile + the
    # device being removed + an optional friendly label. At v1 only
    # K=1 master-only signing is wired (the master phone holds the
    # BIP-39 mnemonic + signs the canonical-JSON binding); K-of-N
    # quorum aggregation across non-master paired devices is banked
    # for v1.1 alongside the schema bump that adds secp256k1 pubkeys
    # to phone registrations.
    #
    # Canonical-JSON signing input is known at queue time (sister of
    # profile_add_device's pattern): {action: "profile_revoke_device",
    # profile_id, phone_id_to_revoke, revoked_at_unix, request_id,
    # master_pubkey_hex}. Phone signs SHA-256 of those bytes;
    # bootloader verifies against operator pubkey + calls
    # profile.manage.profile_revoke_device.
    revdev_profile_id: str | None = None
    revdev_phone_id_to_revoke: str | None = None
    revdev_revoker_label: str | None = None

    @classmethod
    def new(
        cls,
        *,
        kind: str,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        ttl_seconds: int = 300,
    ) -> PendingRequest:
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind=kind,
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
        )

    @classmethod
    def new_eth(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        eth_chain_id: int,
        eth_message_kind: str,
        eth_address: str,
        eth_derivation_path: str = "m/44'/60'/0'/0/0",
        eth_message_text: str | None = None,
        eth_typed_data_json: str | None = None,
        eth_transaction_json: str | None = None,
        ttl_seconds: int = 300,
    ) -> PendingRequest:
        """Construct an ``eth_sign`` PendingRequest with the seven
        Ethereum-specific context fields populated.

        Validates that ``eth_message_kind`` is one of the three
        protocol-defined values and that exactly one of the three
        per-kind body fields (``eth_message_text`` /
        ``eth_typed_data_json`` / ``eth_transaction_json``) is
        populated to match. Raises ``ValueError`` on either failure;
        consumers (the launcher, the mock bootloader operator-UI)
        are expected to validate at construction time so a
        malformed request never lands on the queue.
        """
        if eth_message_kind not in ("personal_sign", "typed_data", "transaction"):
            raise ValueError(
                f"eth_message_kind must be one of "
                f"'personal_sign'|'typed_data'|'transaction', "
                f"got {eth_message_kind!r}"
            )
        body_fields = {
            "personal_sign": eth_message_text,
            "typed_data": eth_typed_data_json,
            "transaction": eth_transaction_json,
        }
        expected = body_fields[eth_message_kind]
        if expected is None or expected == "":
            field_name = {
                "personal_sign": "eth_message_text",
                "typed_data": "eth_typed_data_json",
                "transaction": "eth_transaction_json",
            }[eth_message_kind]
            raise ValueError(
                f"eth_message_kind={eth_message_kind!r} requires {field_name} to be set"
            )
        # Reject obviously-wrong addresses early; full EIP-55 validation
        # happens phone-side when the BIP32 derivation runs.
        addr_clean = eth_address.lower()
        if not addr_clean.startswith("0x") or len(addr_clean) != 42:
            raise ValueError(
                f"eth_address must be 0x-prefixed 42-char hex, got {eth_address!r}"
            )
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="eth_sign",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            eth_chain_id=eth_chain_id,
            eth_message_kind=eth_message_kind,
            eth_address=addr_clean,
            eth_derivation_path=eth_derivation_path,
            eth_message_text=eth_message_text,
            eth_typed_data_json=eth_typed_data_json,
            eth_transaction_json=eth_transaction_json,
        )

    @classmethod
    def new_btc(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        btc_network: str,
        btc_message_kind: str,
        btc_address: str,
        btc_derivation_path: str | None = None,
        btc_message_text: str | None = None,
        btc_psbt_base64: str | None = None,
        btc_coin: str = "btc",
        ttl_seconds: int = 300,
    ) -> PendingRequest:
        """Construct a ``btc_sign`` PendingRequest with the six
        Bitcoin-specific context fields populated.

        Validates that ``btc_message_kind`` is one of the two
        protocol-defined values (``message_signing`` or ``psbt``),
        the ``btc_network`` is one of the four recognized networks,
        and exactly one of the two per-kind body fields
        (``btc_message_text`` / ``btc_psbt_base64``) is populated to
        match. Raises ``ValueError`` on any failure; consumers (the
        launcher, the mock bootloader operator-UI) are expected to
        validate at construction time so a malformed request never
        lands on the queue.
        """
        if btc_message_kind not in ("message_signing", "psbt"):
            raise ValueError(
                f"btc_message_kind must be one of 'message_signing'|'psbt', "
                f"got {btc_message_kind!r}"
            )
        if btc_network not in ("mainnet", "testnet", "signet", "regtest"):
            raise ValueError(
                f"btc_network must be one of "
                f"'mainnet'|'testnet'|'signet'|'regtest', got {btc_network!r}"
            )
        if btc_coin not in ("btc", "ltc", "doge", "bch"):
            raise ValueError(
                f"btc_coin must be one of 'btc'|'ltc'|'doge'|'bch', "
                f"got {btc_coin!r}"
            )
        # Coin-default BIP-44 paths. BTC + LTC default to BIP-84 native
        # SegWit (m/84'); DOGE + BCH default to BIP-44 legacy P2PKH
        # (m/44') since neither chain widely adopted SegWit.
        if btc_derivation_path is None:
            btc_derivation_path = {
                "btc":  "m/84'/0'/0'/0/0",
                "ltc":  "m/84'/2'/0'/0/0",
                "doge": "m/44'/3'/0'/0/0",
                "bch":  "m/44'/145'/0'/0/0",
            }[btc_coin]
        body_fields = {
            "message_signing": btc_message_text,
            "psbt": btc_psbt_base64,
        }
        expected = body_fields[btc_message_kind]
        if expected is None or expected == "":
            field_name = {
                "message_signing": "btc_message_text",
                "psbt": "btc_psbt_base64",
            }[btc_message_kind]
            raise ValueError(
                f"btc_message_kind={btc_message_kind!r} requires {field_name} to be set"
            )
        if not btc_address or len(btc_address) < 14:
            # Loose minimum length sanity-check; full bech32 / Base58Check
            # validation happens phone-side during the BIP-32 derivation.
            # P2WPKH bech32 is ~42 chars, P2PKH Base58Check is 26-35 chars,
            # so 14 is a safe floor that catches obvious mistakes.
            raise ValueError(
                f"btc_address must be at least 14 chars, got {btc_address!r}"
            )
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="btc_sign",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            btc_network=btc_network,
            btc_message_kind=btc_message_kind,
            btc_address=btc_address.strip(),
            btc_derivation_path=btc_derivation_path,
            btc_message_text=btc_message_text,
            btc_psbt_base64=btc_psbt_base64,
            btc_coin=btc_coin,
        )

    @classmethod
    def new_ed(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        ed_chain: str,
        ed_message_kind: str,
        ed_address: str,
        ed_derivation_path: str | None = None,
        ed_message_text: str | None = None,
        ed_payload_hex: str | None = None,
        ttl_seconds: int = 300,
    ) -> PendingRequest:
        """Construct an ``ed_sign`` PendingRequest with the six
        Ed25519-chain-specific context fields populated.

        Validates that:
        - ``ed_chain`` is one of ``"sol"`` / ``"xlm"`` / ``"xrp"``
        - ``ed_message_kind`` is one of ``"message_signing"`` /
          ``"transaction"``
        - exactly one of (``ed_message_text``, ``ed_payload_hex``) is
          populated to match the message kind
        - ``ed_address`` is non-empty and at least 25 chars (loose
          floor; the shortest valid address among the three chains
          is ~25 chars for an XRP classic address)

        Defaults ``ed_derivation_path`` to the chain-canonical SLIP-0010
        path when absent (Phantom for SOL, SEP-0005 for XLM, Xumm-style
        all-hardened for XRP-ed25519).

        Raises ``ValueError`` on any failure; consumers (the launcher,
        the mock bootloader operator-UI) are expected to validate at
        construction time so a malformed request never lands on the
        queue.
        """
        if ed_chain not in ("sol", "xlm", "xrp"):
            raise ValueError(
                f"ed_chain must be one of 'sol'|'xlm'|'xrp', got {ed_chain!r}"
            )
        if ed_message_kind not in ("message_signing", "transaction"):
            raise ValueError(
                f"ed_message_kind must be one of 'message_signing'|'transaction', "
                f"got {ed_message_kind!r}"
            )
        # Coin-default SLIP-0010 paths (all hardened-only).
        if ed_derivation_path is None:
            ed_derivation_path = {
                "sol": "m/44'/501'/0'/0'",      # Phantom / Solflare
                "xlm": "m/44'/148'/0'",         # SEP-0005
                "xrp": "m/44'/144'/0'/0'/0'",   # Xumm-style ed25519
            }[ed_chain]
        body_fields = {
            "message_signing": ed_message_text,
            "transaction": ed_payload_hex,
        }
        expected = body_fields[ed_message_kind]
        if expected is None or expected == "":
            field_name = {
                "message_signing": "ed_message_text",
                "transaction": "ed_payload_hex",
            }[ed_message_kind]
            raise ValueError(
                f"ed_message_kind={ed_message_kind!r} requires {field_name} to be set"
            )
        if not ed_address or len(ed_address.strip()) < 25:
            # Loose floor: the shortest legitimate XRP classic address
            # is ~25 chars; SOL is 32-44 chars; XLM StrKey is exactly
            # 56 chars. 25-char floor catches obvious truncation /
            # paste errors. Full per-chain validation runs phone-side
            # during the BIP-39 → SLIP-0010 → address-encode pipeline.
            raise ValueError(
                f"ed_address must be at least 25 chars, got {ed_address!r}"
            )
        if ed_message_kind == "transaction":
            # Reserved kind; not yet wired through the chain-module
            # transaction-hashing rules. Refuse here so a future phone
            # implementation can enable it without protocol drift.
            raise ValueError(
                "ed_message_kind='transaction' is reserved for a follow-up "
                "wave; only 'message_signing' is wired today"
            )
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="ed_sign",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            ed_chain=ed_chain,
            ed_message_kind=ed_message_kind,
            ed_address=ed_address.strip(),
            ed_derivation_path=ed_derivation_path,
            ed_message_text=ed_message_text,
            ed_payload_hex=ed_payload_hex,
        )

    @classmethod
    def new_tron(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        tron_network: str,
        tron_message_kind: str,
        tron_address: str,
        tron_derivation_path: str = "m/44'/195'/0'/0/0",
        tron_message_text: str | None = None,
        tron_payload_hex: str | None = None,
        ttl_seconds: int = 300,
    ) -> PendingRequest:
        """Construct a ``tron_sign`` PendingRequest with the six
        TRON-specific context fields populated.

        Validates that:
        - ``tron_network`` is one of ``"mainnet"``, ``"shasta"``,
          ``"nile"``. (TRON's testnets share the same address-version
          byte 0x41 as mainnet -- the network distinction lives at
          the RPC + explorer layer, not the address encoding -- but
          we surface it on the request so the operator UI can label
          which environment is being signed against.)
        - ``tron_message_kind`` is one of ``"message_signing"`` /
          ``"transaction"``.
        - exactly one of (``tron_message_text``, ``tron_payload_hex``)
          is populated to match the message kind.
        - ``tron_address`` matches the T-prefixed 34-char shape
          (loose check: starts with ``T`` and is 34 chars long).
          Full base58check validation runs verifier-side via
          ``recto.tron.address_to_hex`` once the request lands.

        Refuses ``tron_message_kind="transaction"`` for the moment --
        TRON transactions wrap a protobuf-serialized ``Transaction``
        message that requires a parser the verifier doesn't yet
        ship. Reserved here for a follow-up wave so the protocol
        seam is ready when the parser lands.

        Raises ``ValueError`` on any failure; consumers (the
        launcher, the mock bootloader operator-UI) are expected to
        validate at construction time so a malformed request never
        lands on the queue.
        """
        if tron_network not in ("mainnet", "shasta", "nile"):
            raise ValueError(
                f"tron_network must be one of 'mainnet'|'shasta'|'nile', "
                f"got {tron_network!r}"
            )
        if tron_message_kind not in ("message_signing", "transaction"):
            raise ValueError(
                f"tron_message_kind must be one of "
                f"'message_signing'|'transaction', got {tron_message_kind!r}"
            )
        body_fields = {
            "message_signing": tron_message_text,
            "transaction": tron_payload_hex,
        }
        expected = body_fields[tron_message_kind]
        if expected is None or expected == "":
            field_name = {
                "message_signing": "tron_message_text",
                "transaction": "tron_payload_hex",
            }[tron_message_kind]
            raise ValueError(
                f"tron_message_kind={tron_message_kind!r} requires "
                f"{field_name} to be set"
            )
        if tron_message_kind == "transaction":
            # Reserved kind; not yet wired through to a TRON
            # protobuf-transaction-hashing rule. Refuse here so a
            # future phone impl can enable it without protocol drift.
            raise ValueError(
                "tron_message_kind='transaction' is reserved for a follow-up "
                "wave; only 'message_signing' is wired today"
            )
        addr_clean = tron_address.strip()
        if not addr_clean.startswith("T") or len(addr_clean) != 34:
            raise ValueError(
                f"tron_address must be 34-char T-prefixed base58check, "
                f"got {tron_address!r}"
            )
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="tron_sign",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            tron_network=tron_network,
            tron_message_kind=tron_message_kind,
            tron_address=addr_clean,
            tron_derivation_path=tron_derivation_path,
            tron_message_text=tron_message_text,
            tron_payload_hex=tron_payload_hex,
        )

    @classmethod
    def new_capability_request(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        cap_header_b64: str,
        cap_payload_b64: str,
        cap_agent_id: str | None = None,
        ttl_seconds: int = 3600,
        grant_ttl_seconds: int | None = None,
    ) -> PendingRequest:
        """Construct a ``capability_request`` PendingRequest for Phase 5
        Wave B routing.

        ``cap_header_b64`` and ``cap_payload_b64`` are the canonical-
        JSON-encoded base64url JWS segments — typically produced via
        ``recto.capability.jwt.build_signing_input`` from a typed
        ``CapabilityClaims`` instance. The bootloader stores them so
        it can later assemble the final 3-part JWS via
        ``recto.capability.jwt.assemble_jws`` once the phone returns
        the 64-byte raw r||s on the respond endpoint.

        Validation at construction time:
          - both segments are non-empty
          - both segments parse cleanly as base64url (no padding)
          - the payload segment decodes to a JSON object that has at
            minimum the standard JWT claims (iss / sub / aud / iat /
            nbf / exp / jti / cap / purpose) — this catches obviously-
            malformed claims before they hit the queue, but the full
            ``CapabilityClaims`` validation is the queue endpoint's
            responsibility (it has the typed payload).

        Default ``ttl_seconds`` is 3600 (one hour) — capability requests
        sit on the queue waiting for the operator's manual approval,
        which is a slower-rhythm interaction than the per-sign request
        flows; a 5-minute TTL would expire too aggressively. The
        operator UI shows the remaining time.

        Raises ``ValueError`` on any structural failure; consumers (the
        capability-request HTTP endpoint, mock-bootloader operator UI)
        are expected to validate at construction time so a malformed
        request never lands on the queue.
        """
        if not cap_header_b64 or not isinstance(cap_header_b64, str):
            raise ValueError(
                "cap_header_b64 must be a non-empty base64url string"
            )
        if not cap_payload_b64 or not isinstance(cap_payload_b64, str):
            raise ValueError(
                "cap_payload_b64 must be a non-empty base64url string"
            )
        # Sanity-check encoding by attempting a decode. We keep the
        # imports local so the bootloader package doesn't pull
        # capability/jwt at module load time.
        import base64 as _base64
        import json as _json
        try:
            pad_h = "=" * (-len(cap_header_b64) % 4)
            _base64.urlsafe_b64decode(cap_header_b64 + pad_h)
        except Exception as exc:
            raise ValueError(
                f"cap_header_b64 is not valid base64url: {exc}"
            ) from exc
        try:
            pad_p = "=" * (-len(cap_payload_b64) % 4)
            payload_bytes = _base64.urlsafe_b64decode(cap_payload_b64 + pad_p)
        except Exception as exc:
            raise ValueError(
                f"cap_payload_b64 is not valid base64url: {exc}"
            ) from exc
        # Confirm payload decodes to a JSON object with the required
        # standard claims. We don't run full CapabilityClaims dataclass
        # construction here — that's the endpoint's job (it has the
        # typed object pre-encoding). This is a structural sanity gate.
        try:
            payload = _json.loads(payload_bytes)
        except Exception as exc:
            raise ValueError(
                f"cap_payload_b64 does not decode to JSON: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise ValueError(
                f"cap_payload_b64 must decode to a JSON object, "
                f"got {type(payload).__name__}"
            )
        required = {"iss", "sub", "aud", "iat", "nbf", "exp", "jti", "cap",
                    "purpose"}
        missing = required - set(payload.keys())
        if missing:
            raise ValueError(
                f"cap_payload_b64 missing required claims: {sorted(missing)}"
            )
        # Defense against an absurdly-distant exp slipping through;
        # a capability whose exp is more than 30 days out is almost
        # certainly a bug. Operator UI / endpoint can tighten further.
        try:
            exp_unix = int(payload["exp"])
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"cap_payload_b64 'exp' must be an integer unix timestamp, "
                f"got {payload['exp']!r}"
            ) from exc
        if exp_unix < int(time.time()):
            raise ValueError(
                f"cap_payload_b64 'exp' is in the past "
                f"(exp={exp_unix}, now={int(time.time())})"
            )
        # cap_agent_id is purely informational (audit-log attribution);
        # any non-empty string is fine. Empty string normalized to None
        # so wire shape doesn't carry an empty-string sentinel.
        if cap_agent_id is not None and not cap_agent_id.strip():
            cap_agent_id = None
        # grant_ttl_seconds bounds the AUTHORITY window (re-stamped at
        # card-open), distinct from ttl_seconds which bounds the CARD's
        # queue life. Kept deliberately short: a verifier-side lifetime
        # ceiling is the whole point of declaring it.
        if grant_ttl_seconds is not None:
            if not isinstance(grant_ttl_seconds, int) or not (30 <= grant_ttl_seconds <= 900):
                raise ValueError(
                    "grant_ttl_seconds must be an integer in [30, 900] when set"
                )
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="capability_request",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            cap_header_b64=cap_header_b64,
            cap_payload_b64=cap_payload_b64,
            cap_agent_id=cap_agent_id,
            cap_grant_ttl_seconds=grant_ttl_seconds,
        )

    @classmethod
    def new_profile_create(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        candidate_profile_id: str,
        candidate_kind: str,
        candidate_display_name: str,
        candidate_derivation_purpose: int,
        candidate_derivation_coin_type: int,
        candidate_derivation_index: int,
        candidate_theme_hint: str | None = None,
        candidate_scim_provider: str | None = None,
        ttl_seconds: int = 600,
    ) -> PendingRequest:
        """Construct a ``profile_create`` PendingRequest for Phase 2.0.B
        integration.

        The candidate fields describe the proposed new child profile.
        Phone responds by signing a master-attestation over the
        canonical-JSON encoding of these fields plus the phone-derived
        ``child_pubkey_hex`` (proving the child key was actually derived
        from the master mnemonic at the named BIP-32 path). Bootloader
        verifies the signature against the operator pubkey from
        ``vault_root.json``, then calls
        ``recto.profile.manage.create_child_profile`` to persist the
        new Profile with ``profile_index_override=candidate_derivation_index``
        so the actual on-disk row matches what the operator approved.

        Default ``ttl_seconds`` is 600 (10 minutes) — profile-create
        requests sit on the queue waiting for the operator's phone-tap
        approval, slower-rhythm than per-sign requests but faster than
        capability-request (which can sit for an hour while the
        operator reviews scope).

        Validation at construction time:
          - ``candidate_profile_id`` non-empty
          - ``candidate_kind`` non-empty
          - ``candidate_display_name`` non-empty after strip()
          - ``candidate_derivation_purpose / coin_type / index`` are
            non-negative ints
          - ``payload_hash_b64u`` non-empty (anchors the Ed25519
            envelope)

        Raises ``ValueError`` on any structural failure.
        """
        if not candidate_profile_id:
            raise ValueError("candidate_profile_id must be non-empty")
        if not candidate_kind:
            raise ValueError("candidate_kind must be non-empty")
        if not candidate_display_name or not candidate_display_name.strip():
            raise ValueError("candidate_display_name must be non-empty")
        for label, value in (
            ("candidate_derivation_purpose", candidate_derivation_purpose),
            ("candidate_derivation_coin_type", candidate_derivation_coin_type),
            ("candidate_derivation_index", candidate_derivation_index),
        ):
            if not isinstance(value, int) or value < 0:
                raise ValueError(
                    f"{label} must be a non-negative int, got {value!r}"
                )
        if not payload_hash_b64u:
            raise ValueError("payload_hash_b64u must be non-empty")
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="profile_create",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            candidate_profile_id=candidate_profile_id,
            candidate_kind=candidate_kind,
            candidate_display_name=candidate_display_name.strip(),
            candidate_derivation_purpose=candidate_derivation_purpose,
            candidate_derivation_coin_type=candidate_derivation_coin_type,
            candidate_derivation_index=candidate_derivation_index,
            candidate_theme_hint=candidate_theme_hint,
            candidate_scim_provider=candidate_scim_provider,
        )

    @classmethod
    def new_profile_add_device(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        addev_profile_id: str,
        addev_new_phone_id: str,
        addev_new_phone_label: str | None = None,
        ttl_seconds: int = 600,
    ) -> PendingRequest:
        """Construct a ``profile_add_device`` PendingRequest for Phase
        2.0.C wave C.5 integration.

        The addev_* fields describe the target profile (``addev_profile_id``)
        and the new device being added (``addev_new_phone_id`` —
        already registered with the bootloader via the v0.4 pair flow
        prior to this call). Phone responds by signing a master-
        attestation over the canonical-JSON encoding of (profile_id,
        new_phone_id, added_at_unix, request_id). Bootloader verifies
        the signature against the operator pubkey from
        ``vault_root.json``, then calls
        ``recto.profile.manage.profile_add_device`` to append the new
        phone_id to the target profile's ``device_ids`` tuple.

        Default ``ttl_seconds`` is 600 (10 minutes) — same rhythm as
        profile_create, faster than capability_request (which can sit
        for an hour while the operator reviews scope).

        Validation at construction time:
          - ``addev_profile_id`` non-empty
          - ``addev_new_phone_id`` non-empty
          - ``addev_new_phone_label`` (if supplied) must be a string
          - ``payload_hash_b64u`` non-empty (anchors the Ed25519
            envelope)

        Raises ``ValueError`` on any structural failure.
        """
        if not addev_profile_id:
            raise ValueError("addev_profile_id must be non-empty")
        if not addev_new_phone_id:
            raise ValueError("addev_new_phone_id must be non-empty")
        if addev_new_phone_label is not None and not isinstance(
            addev_new_phone_label, str
        ):
            raise ValueError(
                "addev_new_phone_label must be a string or None"
            )
        if not payload_hash_b64u:
            raise ValueError("payload_hash_b64u must be non-empty")
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="profile_add_device",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            addev_profile_id=addev_profile_id,
            addev_new_phone_id=addev_new_phone_id,
            addev_new_phone_label=addev_new_phone_label,
        )

    @classmethod
    def new_profile_revoke_device(
        cls,
        *,
        service: str,
        secret: str,
        phone_id: str,
        operation_description: str,
        payload_hash_b64u: str,
        child_pid: int,
        child_argv0: str,
        revdev_profile_id: str,
        revdev_phone_id_to_revoke: str,
        revdev_revoker_label: str | None = None,
        ttl_seconds: int = 600,
    ) -> PendingRequest:
        """Construct a ``profile_revoke_device`` PendingRequest for
        Phase 2.0.C wave C.6 integration.

        The revdev_* fields describe the target profile + the device
        being removed from device_ids. Phone responds by signing a
        master-attestation over the canonical-JSON encoding of
        (action, profile_id, phone_id_to_revoke, revoked_at_unix,
        request_id, master_pubkey_hex). Bootloader verifies the
        signature against the operator pubkey from ``vault_root.json``,
        then calls ``recto.profile.manage.profile_revoke_device`` to
        atomic-write the removed phone_id out of the target profile's
        ``device_ids`` tuple.

        At v1 only K=1 master-only signing is wired end-to-end (the
        endpoint pre-flight rejects K>=2 with
        ``quorum_not_yet_implemented``). K-of-N aggregation is banked
        for v1.1 alongside the schema bump that adds secp256k1
        pubkeys to non-master phone registrations.

        Default ``ttl_seconds`` is 600 (10 minutes) — same rhythm as
        profile_create + profile_add_device.

        Validation at construction time:
          - ``revdev_profile_id`` non-empty
          - ``revdev_phone_id_to_revoke`` non-empty
          - ``revdev_revoker_label`` (if supplied) must be a string
          - ``payload_hash_b64u`` non-empty

        Raises ``ValueError`` on any structural failure.
        """
        if not revdev_profile_id:
            raise ValueError("revdev_profile_id must be non-empty")
        if not revdev_phone_id_to_revoke:
            raise ValueError("revdev_phone_id_to_revoke must be non-empty")
        if revdev_revoker_label is not None and not isinstance(
            revdev_revoker_label, str
        ):
            raise ValueError(
                "revdev_revoker_label must be a string or None"
            )
        if not payload_hash_b64u:
            raise ValueError("payload_hash_b64u must be non-empty")
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            kind="profile_revoke_device",
            service=service,
            secret=secret,
            phone_id=phone_id,
            operation_description=operation_description,
            payload_hash_b64u=payload_hash_b64u,
            child_pid=child_pid,
            child_argv0=child_argv0,
            requested_at_unix=now,
            expires_at_unix=now + ttl_seconds,
            revdev_profile_id=revdev_profile_id,
            revdev_phone_id_to_revoke=revdev_phone_id_to_revoke,
            revdev_revoker_label=revdev_revoker_label,
        )

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at_unix


@dataclass(frozen=True, slots=True)
class RevocationEntry:
    """One revoked capability JWT, identified by its ``jti``.

    Phase 5 Wave C part 2: persistent revocation entries the bootloader
    serves at ``GET /v0.4/capability/revocations`` and consults at every
    capability-gated operation (e.g. ``POST /v0.4/secrets/read``). Each
    entry survives bootloader restart via ``revocations.json`` in the
    state directory.

    Fields:
      - ``jti``: the revoked JWT's unique identifier from the
        original CapabilityClaims.
      - ``revoked_at_unix``: when the operator revoked. Useful for
        audit logs.
      - ``original_exp_unix``: the original JWT's ``exp`` claim. Used
        for auto-pruning -- once ``time.time() >= original_exp_unix``
        the entry is dropped, since a JWT past its own exp is
        already universally rejected by ``verify_jws`` and there's
        no point keeping the revocation record.
      - ``reason``: optional operator-supplied note (e.g. "agent
        compromised 2026-05-09", "scope was wider than intended").
        Surfaces in audit logs; never used for authorization
        decisions.

    Frozen + slots-equipped to match the rest of the StateStore's
    dataclass conventions.
    """

    jti: str
    revoked_at_unix: int
    original_exp_unix: int
    reason: str | None = None

    @property
    def is_expired(self) -> bool:
        """True once the original JWT's exp has passed -- the
        revocation entry is no longer needed because verify_jws
        rejects expired JWTs unconditionally.
        """
        return time.time() >= self.original_exp_unix


@dataclass(frozen=True, slots=True)
class ProfileCreateResult:
    """The post-approval result of a ``profile_create`` PendingRequest
    (Phase 2.0.B integration).

    Stored separately from the in-flight pending queue so the CLI
    (or any other requesting client) can poll for it after the phone
    has resolved the request. Sister of ``CapabilityResult`` but for
    the multi-profile identity flow.

    On approval, the new Profile has ALREADY been persisted to
    ``master_identity.json`` via ``profile.manage.create_child_profile``
    before this result lands in the store. The result carries the
    created profile_id so the CLI / caller can fetch full details
    via ``profile.manage.get_profile_by_id``.

    Status values:
      - ``"approved"``: operator approved; new profile persisted;
        ``profile_id`` populated.
      - ``"denied"``: operator denied at the phone; ``profile_id``
        is None; ``reason`` carries the denial note (e.g. "operator
        rejected the kind").
      - ``"signature_error"``: phone returned an attestation that
        didn't verify against the operator pubkey OR the child
        pubkey it claimed to derive didn't match expected derivation;
        ``profile_id`` is None; ``reason`` carries the diagnostic.

    Phase 2.0.B v1: in-memory only (purged on bootloader restart,
    same as ``_capability_results``). A future wave may add durable
    persistence keyed by candidate_profile_id for replay protection
    if profile-create flows ever happen at high enough volume to
    matter.
    """

    request_id: str
    status: str  # "approved" | "denied" | "signature_error"
    profile_id: str | None
    reason: str | None
    resolved_at_unix: int
    expires_at_unix: int

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at_unix


@dataclass(frozen=True, slots=True)
class ProfileAddDeviceResult:
    """The post-approval result of a ``profile_add_device`` PendingRequest
    (Phase 2.0.C wave C.5 integration).

    Sister of ``ProfileCreateResult`` but for the device-set mutation
    flow. On approval, the new phone_id has ALREADY been appended to
    the target profile's ``device_ids`` tuple in ``master_identity.json``
    via ``profile.manage.profile_add_device`` before this result lands
    in the store. The result carries the target profile_id + the
    appended new_phone_id so the CLI / caller can confirm the mutation
    landed (or fetch full details via ``profile.manage.get_profile_by_id``).

    Status values:
      - ``"approved"``: operator approved; new phone_id is now in
        the profile's device_ids; ``profile_id`` + ``new_phone_id``
        populated.
      - ``"already_member"``: idempotent hit — the new_phone_id was
        already in the profile's device_ids tuple at respond time.
        ``profile_id`` + ``new_phone_id`` populated. No phone prompt
        occurred (caught at the endpoint's pre-flight check).
      - ``"denied"``: operator denied at the phone; ``profile_id``
        + ``new_phone_id`` are None; ``reason`` carries the denial
        note.
      - ``"signature_error"``: phone returned an attestation that
        didn't verify against the operator pubkey OR the disk write
        failed during persist (reason starts with ``persist_error:``
        for the latter case per Milan commitment C).

    Phase 2.0.C v1: in-memory only (purged on bootloader restart,
    same as ProfileCreateResult). A future wave may add durable
    persistence if add-device flows ever happen at high enough
    volume to matter.
    """

    request_id: str
    status: str  # "approved" | "already_member" | "denied" | "signature_error"
    profile_id: str | None
    new_phone_id: str | None
    reason: str | None
    resolved_at_unix: int
    expires_at_unix: int

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at_unix


@dataclass(frozen=True, slots=True)
class ProfileRevokeDeviceResult:
    """The post-approval result of a ``profile_revoke_device``
    PendingRequest (Phase 2.0.C wave C.6 integration).

    Sister of ``ProfileAddDeviceResult`` but for the inverse device-
    set mutation. On approval, the phone_id has ALREADY been removed
    from the target profile's ``device_ids`` tuple in
    ``master_identity.json`` via
    ``profile.manage.profile_revoke_device`` before this result
    lands in the store. The result carries the target profile_id +
    the removed phone_id so the CLI / caller can confirm the
    mutation landed.

    Status values:
      - ``"approved"``: operator approved; phone_id removed from
        the profile's device_ids; both fields populated.
      - ``"already_not_member"``: idempotent hit — the
        phone_id_to_revoke wasn't in the profile's device_ids at
        respond time. Both fields populated. No phone prompt
        occurred (caught at the endpoint's pre-flight check).
      - ``"denied"``: operator denied at the phone; both fields
        None; ``reason`` carries the denial note.
      - ``"signature_error"``: phone returned an attestation that
        didn't verify against the operator pubkey OR the disk write
        failed during persist (reason starts with ``persist_error:``
        for the latter case per Milan commitment C).

    Phase 2.0.C v1: in-memory only (purged on bootloader restart,
    same as ProfileAddDeviceResult). The device_ids mutation IS
    persisted to master_identity.json independently, so a
    bootloader-restart-loses-result scenario is graceful: the
    operator can run ``recto profile show <profile_id>`` and see
    the device tuple post-mutation regardless.
    """

    request_id: str
    status: str  # "approved" | "already_not_member" | "denied" | "signature_error"
    profile_id: str | None
    phone_id_revoked: str | None
    reason: str | None
    resolved_at_unix: int
    expires_at_unix: int

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at_unix


@dataclass(frozen=True, slots=True)
class CapabilityResult:
    """The post-approval result of a ``capability_request`` PendingRequest.

    Stored separately from the in-flight pending queue so the requesting
    agent can poll for it after the phone has resolved the request.
    Lives until ``expires_at_unix``, at which point it's purged
    regardless of whether the agent fetched it (mirrors how the request
    itself has a TTL — agents that don't poll within the window forfeit
    the result).

    ``capability_jws`` is the assembled 3-part JWS string ready for
    consumers to verify; ``status`` is one of ``"approved"`` /
    ``"denied"`` / ``"signature_error"``. Denied / signature_error
    carry a ``reason`` string and ``capability_jws=None``.

    Phase 5 Wave B v1: this is in-memory only (purged on bootloader
    restart, like ``PendingRequest``). Wave C considers durable
    persistence keyed by ``jti`` for replay-protection bookkeeping.
    """

    request_id: str
    status: str  # "approved" | "denied" | "signature_error"
    capability_jws: str | None
    reason: str | None
    agent_id: str | None
    resolved_at_unix: int
    expires_at_unix: int

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at_unix


class StateStoreBase(ABC):
    """Abstract persistence contract for bootloader state.

    The seam that lets the state layer swap backends without touching server
    logic. v1 ships ``StateStore`` below (local-JSON, single-host, operator-
    bound). The production-scale path (Recto scale-readiness brief, Axis A --
    "giant user base") implements this same contract with a
    ``PostgresStateStore`` so the bootloader can run multi-instance behind a
    load balancer (a ``pg_advisory_lock`` guarding the pending-request poller).
    ``create_server`` already takes the store by injection, so the swap is a
    constructor argument, not a rewrite.

    Sister of the ``SecretSource`` ABC -- the same pluggable-backend pattern
    applied to state instead of secrets. Only the public read/write operations
    are part of the contract; persistence mechanics (file I/O + atomic writes,
    or SQL + locking) are each implementation's own concern.
    """

    @property
    @abstractmethod
    def state_dir(self) -> Path: ...

    # Phones
    @abstractmethod
    def register_phone(self, reg: PhoneRegistration) -> None: ...
    @abstractmethod
    def get_phone(self, phone_id: str) -> PhoneRegistration | None: ...
    @abstractmethod
    def list_phones(self) -> list[PhoneRegistration]: ...
    @abstractmethod
    def revoke_phone(self, phone_id: str) -> bool: ...

    # Sessions
    @abstractmethod
    def get_session(self, service: str, secret: str) -> Session | None: ...
    @abstractmethod
    def put_session(self, sess: Session) -> None: ...
    @abstractmethod
    def increment_session_uses(self, service: str, secret: str) -> Session | None: ...

    # Pending requests
    @abstractmethod
    def add_pending(self, req: PendingRequest) -> None: ...
    @abstractmethod
    def list_pending_for_phone(self, phone_id: str) -> list[PendingRequest]: ...
    @abstractmethod
    def take_pending(self, request_id: str) -> PendingRequest | None: ...

    # Capability results
    @abstractmethod
    def put_capability_result(self, result: CapabilityResult) -> None: ...
    @abstractmethod
    def get_capability_result(self, request_id: str) -> CapabilityResult | None: ...
    @abstractmethod
    def take_capability_result(self, request_id: str) -> CapabilityResult | None: ...

    # Profile-create results
    @abstractmethod
    def put_profile_create_result(self, result: ProfileCreateResult) -> None: ...
    @abstractmethod
    def get_profile_create_result(self, request_id: str) -> ProfileCreateResult | None: ...
    @abstractmethod
    def take_profile_create_result(self, request_id: str) -> ProfileCreateResult | None: ...

    # Profile-add-device results
    @abstractmethod
    def put_profile_add_device_result(self, result: ProfileAddDeviceResult) -> None: ...
    @abstractmethod
    def get_profile_add_device_result(self, request_id: str) -> ProfileAddDeviceResult | None: ...
    @abstractmethod
    def take_profile_add_device_result(self, request_id: str) -> ProfileAddDeviceResult | None: ...

    # Profile-revoke-device results
    @abstractmethod
    def put_profile_revoke_device_result(self, result: ProfileRevokeDeviceResult) -> None: ...
    @abstractmethod
    def get_profile_revoke_device_result(self, request_id: str) -> ProfileRevokeDeviceResult | None: ...
    @abstractmethod
    def take_profile_revoke_device_result(self, request_id: str) -> ProfileRevokeDeviceResult | None: ...

    # Operator pubkey / vault root
    @abstractmethod
    def put_operator_pubkey(self, pubkey: bytes) -> None: ...
    @abstractmethod
    def get_operator_pubkey(self) -> bytes | None: ...
    @abstractmethod
    def is_vault_bootstrapped(self) -> bool: ...

    # Genesis members (5c). The operator pubkey above is the SIGNING ROOT;
    # these are the additional members of the operator SET -- today only the
    # passphrase, tomorrow the recovery device. Kept as a keyed store rather
    # than one slot per kind so adding a member is data, not a schema change.
    @abstractmethod
    def put_genesis_member(
        self, kind: str, pubkey: bytes, algorithm: str = GENESIS_LEGACY_ALGORITHM
    ) -> None: ...
    @abstractmethod
    def get_genesis_member(self, kind: str) -> bytes | None: ...
    @abstractmethod
    def list_genesis_members(self) -> dict[str, bytes]: ...
    # `list_genesis_members` returns bytes and KEEPS that shape on purpose:
    # widening its return type would have been a silent break for every
    # existing caller. The algorithm arrives through a new door instead.
    @abstractmethod
    def list_genesis_members_full(self) -> dict[str, GenesisMember]: ...
    @abstractmethod
    def get_genesis_member_algorithm(self, kind: str) -> str | None: ...
    # "nothing is sealed" and "what is sealed cannot be read" are opposite
    # facts. A caller that cannot tell them apart will tell an operator the
    # vault is empty at the exact moment it is not.
    @abstractmethod
    def list_unreadable_genesis_members(self) -> dict[str, str]: ...

    # GATE 5 -- the membership CHAIN.
    #
    # DELIBERATELY NOT @abstractmethod, and the reason is the whole point
    # of these three methods existing at all. The chain is implemented by
    # the file store and NOT by the Postgres store. Making it abstract
    # would force a stub into Postgres that either lies (returns an empty
    # chain, so `list_genesis_members_full` silently falls back to the
    # flat table and tamper-detection is off with nothing said) or raises
    # from deep inside a read path.
    #
    # So the gap is DECLARED instead. `supports_genesis_chain()` is False
    # by default; a backend that cannot hold a chain says so, and the
    # writer refuses up front naming the backend. An undeclared missing
    # capability is the defect; a declared one is a roadmap entry.
    #
    # WHAT IS ACTUALLY MISSING, so nobody has to rediscover it: Postgres
    # is the MULTI-INSTANCE production backend, which means the
    # deployment shape that most needs membership-tamper detection is the
    # one that does not have it. Closing that is a schema change plus its
    # own arm of the contract suite, not a line here.
    def supports_genesis_chain(self) -> bool:
        """Whether this backend can store a GATE 5 membership chain."""
        return False

    def read_genesis_chain(self) -> list[dict[str, Any]]:
        """The stored chain entries, oldest first. `[]` means no chain."""
        raise NotImplementedError(
            f"{type(self).__name__} does not implement the genesis membership "
            f"chain. Membership on this backend is a flat table with no "
            f"tamper detection."
        )

    def append_genesis_chain_entry(self, record: dict[str, Any]) -> None:
        """Append one entry, or refuse.

        The implementation MUST replay the resulting chain before writing,
        so this call cannot be the thing that breaks it.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not implement the genesis membership "
            f"chain, so there is nothing to append to."
        )

    # Capability revocations
    @abstractmethod
    def add_revocation(self, entry: RevocationEntry) -> None: ...
    @abstractmethod
    def is_revoked(self, jti: str) -> bool: ...
    @abstractmethod
    def list_revocations(self) -> list[RevocationEntry]: ...

    # One-time challenges (registration challenges + pairing codes).
    # Part of the state contract so multi-instance backends can share
    # them: the file backend keeps them in-memory (restart invalidates
    # -- the documented single-host semantic), while the postgres
    # backend persists them with DELETE ... RETURNING take semantics so
    # a pairing code survives replica death and any instance behind the
    # load balancer can consume a code minted by a sibling (the
    # 2026-07-20 scale-to-zero field lesson).
    @abstractmethod
    def issue_challenge(self, ttl_seconds: int = 60) -> tuple[str, int]: ...
    @abstractmethod
    def consume_challenge(self, challenge: str) -> bool: ...
    @abstractmethod
    def issue_pairing_code(self, ttl_seconds: int = 300) -> tuple[str, int]: ...
    @abstractmethod
    def consume_pairing_code(self, code: str) -> bool: ...


class StateStore(StateStoreBase):
    """Thread-safe persistence for bootloader state.

    All state is held in JSON files under `state_dir`. Reads are cached
    in memory; writes are write-through (immediately flushed to disk).
    A single threading.RLock serializes all operations -- no
    fine-grained locking, since the bootloader's request rate is bounded
    by phone-interaction latency anyway.
    """

    def __init__(self, state_dir: Path | None = None):
        self._dir = state_dir if state_dir is not None else default_state_dir()
        self._lock = threading.RLock()
        self._phones: dict[str, PhoneRegistration] = {}
        self._sessions: dict[tuple[str, str], Session] = {}
        self._pending: dict[str, PendingRequest] = {}
        # One-time challenges + pairing codes. In-memory only on this
        # backend (restart invalidates; see StateStoreBase contract
        # note). value -> expires_at_unix.
        self._challenges: dict[str, int] = {}
        self._pairing_codes: dict[str, int] = {}
        # Resolved capability requests waiting to be polled by the
        # requesting agent. In-memory only at v1 (purged on bootloader
        # restart, same as the pending queue). Keyed by request_id.
        self._capability_results: dict[str, CapabilityResult] = {}
        # Phase 2.0.B integration: resolved profile_create requests
        # waiting to be polled by the CLI / requesting client. In-
        # memory only (purged on bootloader restart). Keyed by
        # request_id. The new Profile row is ALREADY persisted to
        # master_identity.json by the respond handler before the
        # result lands here, so a bootloader-restart-loses-result
        # scenario is graceful: the operator can run `recto profile
        # list` and see the new profile is there regardless.
        self._profile_create_results: dict[str, ProfileCreateResult] = {}
        # Phase 2.0.C wave C.5: resolved profile_add_device requests
        # waiting to be polled. Same in-memory shape as
        # _profile_create_results. The device_ids tuple mutation IS
        # already persisted to master_identity.json by the respond
        # handler before the result lands here, so a bootloader-
        # restart-loses-result scenario is graceful: the operator can
        # run `recto profile show <profile_id>` and see the new
        # device is in the tuple regardless.
        self._profile_add_device_results: dict[str, ProfileAddDeviceResult] = {}
        # Phase 2.0.C wave C.6: resolved profile_revoke_device requests
        # waiting to be polled. Same in-memory shape as
        # _profile_add_device_results. The device_ids tuple removal
        # IS already persisted to master_identity.json by the respond
        # handler before the result lands here.
        self._profile_revoke_device_results: dict[str, ProfileRevokeDeviceResult] = {}
        # Phase 5 Wave C part 2: persistent revocation list. Keyed by
        # jti. Auto-purged when the original JWT exp passes (verify_jws
        # rejects expired JWTs unconditionally so the revocation record
        # is no longer needed). Persisted via revocations.json in the
        # state directory; survives bootloader restart unlike
        # _pending / _capability_results.
        self._revocations: dict[str, RevocationEntry] = {}
        self._load()

    @property
    def state_dir(self) -> Path:
        return self._dir

    # ------------------------------------------------------------------
    # Phones
    # ------------------------------------------------------------------

    def register_phone(self, reg: PhoneRegistration) -> None:
        with self._lock:
            self._phones[reg.phone_id] = reg
            self._save_phones()

    def get_phone(self, phone_id: str) -> PhoneRegistration | None:
        with self._lock:
            return self._phones.get(phone_id)

    def list_phones(self) -> list[PhoneRegistration]:
        with self._lock:
            return list(self._phones.values())

    def revoke_phone(self, phone_id: str) -> bool:
        with self._lock:
            if phone_id not in self._phones:
                return False
            del self._phones[phone_id]
            # Drop any sessions / pending tied to this phone.
            self._sessions = {
                k: s for k, s in self._sessions.items() if s.phone_id != phone_id
            }
            self._pending = {
                k: p for k, p in self._pending.items() if p.phone_id != phone_id
            }
            self._save_phones()
            self._save_sessions()
            self._save_pending()
            return True

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def get_session(self, service: str, secret: str) -> Session | None:
        with self._lock:
            sess = self._sessions.get((service, secret))
            if sess is None:
                return None
            if sess.is_expired or sess.is_exhausted:
                # Lazy purge -- next get returns None and the caller
                # re-issues. Don't raise here; expiry is normal.
                del self._sessions[(service, secret)]
                self._save_sessions()
                return None
            return sess

    def put_session(self, sess: Session) -> None:
        with self._lock:
            self._sessions[(sess.service, sess.secret)] = sess
            self._save_sessions()

    def increment_session_uses(self, service: str, secret: str) -> Session | None:
        """Increment uses_so_far on a session and persist. Returns the
        updated session, or None if the session is already gone."""
        with self._lock:
            sess = self._sessions.get((service, secret))
            if sess is None:
                return None
            updated = Session(
                service=sess.service,
                secret=sess.secret,
                phone_id=sess.phone_id,
                jwt=sess.jwt,
                expires_at_unix=sess.expires_at_unix,
                issued_at_unix=sess.issued_at_unix,
                max_uses=sess.max_uses,
                uses_so_far=sess.uses_so_far + 1,
            )
            self._sessions[(service, secret)] = updated
            self._save_sessions()
            return updated

    # ------------------------------------------------------------------
    # Pending requests
    # ------------------------------------------------------------------

    def add_pending(self, req: PendingRequest) -> None:
        with self._lock:
            self._pending[req.request_id] = req
            self._save_pending()

    def list_pending_for_phone(self, phone_id: str) -> list[PendingRequest]:
        with self._lock:
            self._purge_expired_pending()
            return [
                p for p in self._pending.values() if p.phone_id == phone_id
            ]

    def take_pending(self, request_id: str) -> PendingRequest | None:
        """Pop a pending request by id. Returns None if not present."""
        with self._lock:
            req = self._pending.pop(request_id, None)
            if req is not None:
                self._save_pending()
            return req

    # ------------------------------------------------------------------
    # Capability results (Phase 5 Wave B)
    # ------------------------------------------------------------------

    def put_capability_result(self, result: CapabilityResult) -> None:
        """Store a resolved capability_request result for later polling
        by the requesting agent. In-memory only at v1; lost on
        bootloader restart (agent re-requests after restart).
        """
        with self._lock:
            self._purge_expired_capability_results()
            self._capability_results[result.request_id] = result

    def get_capability_result(
        self, request_id: str
    ) -> CapabilityResult | None:
        """Fetch a resolved capability_request result. Returns None if
        the request is still pending, never existed, or expired."""
        with self._lock:
            self._purge_expired_capability_results()
            return self._capability_results.get(request_id)

    def take_capability_result(
        self, request_id: str
    ) -> CapabilityResult | None:
        """Fetch + remove a resolved capability_request result.
        Single-use semantics — the agent that fetches the JWT consumes
        it; subsequent fetches return None. This prevents an agent
        from accidentally treating a stale result as fresh on a
        retry."""
        with self._lock:
            self._purge_expired_capability_results()
            return self._capability_results.pop(request_id, None)

    def _purge_expired_capability_results(self) -> None:
        # Caller holds the lock.
        expired = [
            rid for rid, r in self._capability_results.items()
            if r.is_expired
        ]
        for rid in expired:
            del self._capability_results[rid]

    # ------------------------------------------------------------------
    # Profile-create results (Phase 2.0.B integration)
    # ------------------------------------------------------------------

    def put_profile_create_result(self, result: ProfileCreateResult) -> None:
        """Store a resolved profile_create result for later polling
        by the CLI / requesting client. In-memory only; lost on
        bootloader restart (CLI re-requests after restart, OR the
        operator can verify via `recto profile list` since the new
        Profile row is persisted independently)."""
        with self._lock:
            self._purge_expired_profile_create_results()
            self._profile_create_results[result.request_id] = result

    def get_profile_create_result(
        self, request_id: str
    ) -> ProfileCreateResult | None:
        """Fetch a resolved profile_create result. Returns None if
        the request is still pending, never existed, or expired."""
        with self._lock:
            self._purge_expired_profile_create_results()
            return self._profile_create_results.get(request_id)

    def take_profile_create_result(
        self, request_id: str
    ) -> ProfileCreateResult | None:
        """Fetch + remove a resolved profile_create result. Single-
        use semantics — once the CLI consumes the result, subsequent
        fetches return None (prevents a re-polling CLI from acting on
        a stale resolved-but-already-consumed entry)."""
        with self._lock:
            self._purge_expired_profile_create_results()
            return self._profile_create_results.pop(request_id, None)

    def _purge_expired_profile_create_results(self) -> None:
        # Caller holds the lock.
        expired = [
            rid for rid, r in self._profile_create_results.items()
            if r.is_expired
        ]
        for rid in expired:
            del self._profile_create_results[rid]

    # ------------------------------------------------------------------
    # Profile-add-device results (Phase 2.0.C wave C.5)
    # ------------------------------------------------------------------

    def put_profile_add_device_result(
        self, result: ProfileAddDeviceResult
    ) -> None:
        """Store a resolved profile_add_device result for later polling
        by the CLI / requesting client. In-memory only; lost on
        bootloader restart (CLI re-requests after restart, OR the
        operator can verify via `recto profile show <profile_id>` since
        the new phone_id is persisted in the profile's device_ids
        tuple independently)."""
        with self._lock:
            self._purge_expired_profile_add_device_results()
            self._profile_add_device_results[result.request_id] = result

    def get_profile_add_device_result(
        self, request_id: str
    ) -> ProfileAddDeviceResult | None:
        """Fetch a resolved profile_add_device result. Returns None
        if the request is still pending, never existed, or expired."""
        with self._lock:
            self._purge_expired_profile_add_device_results()
            return self._profile_add_device_results.get(request_id)

    def take_profile_add_device_result(
        self, request_id: str
    ) -> ProfileAddDeviceResult | None:
        """Fetch + remove a resolved profile_add_device result. Single-
        use semantics — once the CLI consumes the result, subsequent
        fetches return None."""
        with self._lock:
            self._purge_expired_profile_add_device_results()
            return self._profile_add_device_results.pop(request_id, None)

    def _purge_expired_profile_add_device_results(self) -> None:
        # Caller holds the lock.
        expired = [
            rid for rid, r in self._profile_add_device_results.items()
            if r.is_expired
        ]
        for rid in expired:
            del self._profile_add_device_results[rid]

    # ------------------------------------------------------------------
    # Profile-revoke-device results (Phase 2.0.C wave C.6)
    # ------------------------------------------------------------------

    def put_profile_revoke_device_result(
        self, result: ProfileRevokeDeviceResult
    ) -> None:
        """Store a resolved profile_revoke_device result for later
        polling. In-memory only; lost on bootloader restart (the
        operator can verify via `recto profile show <profile_id>`
        since the device removal is persisted in master_identity.json
        independently)."""
        with self._lock:
            self._purge_expired_profile_revoke_device_results()
            self._profile_revoke_device_results[result.request_id] = result

    def get_profile_revoke_device_result(
        self, request_id: str
    ) -> ProfileRevokeDeviceResult | None:
        """Fetch a resolved profile_revoke_device result. Returns None
        if the request is still pending, never existed, or expired."""
        with self._lock:
            self._purge_expired_profile_revoke_device_results()
            return self._profile_revoke_device_results.get(request_id)

    def take_profile_revoke_device_result(
        self, request_id: str
    ) -> ProfileRevokeDeviceResult | None:
        """Fetch + remove a resolved profile_revoke_device result.
        Single-use semantics."""
        with self._lock:
            self._purge_expired_profile_revoke_device_results()
            return self._profile_revoke_device_results.pop(request_id, None)

    def _purge_expired_profile_revoke_device_results(self) -> None:
        # Caller holds the lock.
        expired = [
            rid for rid, r in self._profile_revoke_device_results.items()
            if r.is_expired
        ]
        for rid in expired:
            del self._profile_revoke_device_results[rid]

    # ------------------------------------------------------------------
    # Operator pubkey root (Phase 5 Wave C part 4)
    # ------------------------------------------------------------------
    #
    # The operator's secp256k1 pubkey is the trust root for capability
    # JWTs. Persisting it lets the bootloader pick it up at startup
    # without having to receive it via kwarg every time create_server
    # runs. ``recto vault bootstrap <pubkey>`` writes via
    # ``put_operator_pubkey``; ``create_server`` falls back to
    # ``get_operator_pubkey`` when its ``capability_operator_pubkey``
    # kwarg is None.

    def put_operator_pubkey(self, pubkey: bytes) -> None:
        """Persist the 64-byte uncompressed secp256k1 pubkey
        (X || Y, no 0x04 prefix). Idempotent: writes/overwrites
        ``vault_root.json`` in state_dir.

        Raises ValueError if the pubkey is not 64 bytes.
        """
        if pubkey is None or len(pubkey) != 64:
            raise ValueError(
                f"operator pubkey must be 64 bytes (uncompressed X||Y); "
                f"got {len(pubkey) if pubkey is not None else 0}"
            )
        with self._lock:
            self._save_operator_pubkey(pubkey)

    def get_operator_pubkey(self) -> bytes | None:
        """Return the persisted operator pubkey as 64 raw bytes, or
        None if no vault_root.json exists in state_dir.

        Used by ``create_server`` to load the persisted root when its
        ``capability_operator_pubkey`` kwarg is None.
        """
        with self._lock:
            path = self._dir / "vault_root.json"
            if not path.exists():
                return None
            raw = json.loads(path.read_text(encoding="utf-8"))
            hex_str = raw.get("operator_pubkey_hex")
            if not hex_str or not isinstance(hex_str, str):
                return None
            try:
                return bytes.fromhex(hex_str)
            except ValueError:
                return None

    def is_vault_bootstrapped(self) -> bool:
        """True when ``vault_root.json`` is present in state_dir.
        Used by ``recto vault status`` to report the bootstrapping
        state without exposing the pubkey value.
        """
        with self._lock:
            return (self._dir / "vault_root.json").exists()

    # ------------------------------------------------------------------
    # Genesis members (5c) -- stored ALONGSIDE the root, not inside it.
    # ------------------------------------------------------------------
    #
    # SEPARATE FILE ON PURPOSE. `vault_root.json` is read on every start by
    # GATE 5a, whose whole job is to refuse when that file disagrees with
    # config. Adding mutable members into it would mean a member enrolment
    # rewrites the file the immutability gate guards -- two different
    # lifetimes in one artifact. The root is written once; members accrete.

    def put_genesis_member(
        self, kind: str, pubkey: bytes, algorithm: str = GENESIS_LEGACY_ALGORITHM
    ) -> None:
        """Seal a genesis member's raw pubkey + its curve under a `kind` label.

        Idempotent per kind. Raises ValueError on a bad kind, algorithm, or
        length so a caller cannot seal something unusable and discover it at
        recovery.

        Writes the TAGGED form. Reads tolerate the untagged form -- see
        `list_genesis_members_full`.
        """
        kind = (kind or "").strip().lower()
        if not kind or not kind.replace("-", "").isalnum():
            raise ValueError(f"genesis member kind must be alphanumeric; got {kind!r}")
        algo = validate_genesis_pubkey(pubkey, algorithm)
        with self._lock:
            path = self._dir / "genesis_members.json"
            body = {}
            if path.exists():
                try:
                    body = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    body = {}
            members = dict(body.get("members") or {})
            members[kind] = {"pubkey": pubkey.hex(), "algorithm": algo}
            self._atomic_write(path, {
                "members": members,
                "stored_at_unix": int(time.time()),
            })

    def get_genesis_member(self, kind: str) -> bytes | None:
        return self.list_genesis_members().get((kind or "").strip().lower())

    def get_genesis_member_algorithm(self, kind: str) -> str | None:
        m = self.list_genesis_members_full().get((kind or "").strip().lower())
        return m.algorithm if m else None

    def list_genesis_members(self) -> dict[str, bytes]:
        return {k: m.pubkey for k, m in self.list_genesis_members_full().items()}

    def _replay_stored_chain(
        self, stored: Any
    ) -> tuple[dict[str, GenesisMember], dict[str, str]]:
        """Replay a stored chain into (readable, unreadable).

        **Any failure makes the WHOLE set unreadable, not the failing entry.**
        A chain is one statement; a partially-accepted chain would let whoever
        broke it choose which membership you end up with.
        """
        from recto.bootloader.genesis_chain import ChainError, build_entry, replay

        try:
            entries = [
                build_entry(
                    seq=e["seq"], op=e["op"], kind=e["kind"],
                    pubkey=bytes.fromhex(e["pubkey"]), algorithm=e["algorithm"],
                    prev=e.get("prev"),
                    signatures=[_b64u_decode(s) for s in (e.get("signatures") or [])],
                )
                for e in (stored or [])
            ]
        except ChainError as exc:
            return {}, {"<chain>": f"membership chain is malformed: {exc}"}
        except Exception as exc:
            return {}, {"<chain>": f"membership chain entry is unreadable: {exc}"}

        if not entries:
            return {}, {}
        try:
            resolved = replay(entries)
        except ChainError as exc:
            return {}, {"<chain>": f"membership chain does not verify: {exc}"}
        return (
            {
                kind: GenesisMember(kind=kind, pubkey=e.pubkey, algorithm=e.algorithm)
                for kind, e in resolved.items()
            },
            {},
        )

    def list_unreadable_genesis_members(self) -> dict[str, str]:
        """`kind -> why it could not be read`, for members that ARE stored but
        cannot be loaded.

        **"NOTHING IS SEALED" AND "WHAT IS SEALED CANNOT BE READ" ARE OPPOSITE
        FACTS AND MUST NEVER SHARE A MESSAGE.** The first says: you have not
        done the thing yet. The second says: you did it, and something is
        wrong. Told the first when the second is true, an operator mid-recovery
        concludes the vault is empty and starts over -- which is the one action
        that destroys what was actually still there.
        """
        return self._read_genesis_members()[1]

    def list_genesis_members_full(self) -> dict[str, GenesisMember]:
        """Read both on-disk shapes.

        A TOLERANT READER IS LOAD-BEARING HERE, NOT A COURTESY. The passphrase
        member is ALREADY SEALED in the untagged form, on a vault whose whole
        purpose is that it cannot be re-created. A reader that only understood
        the new shape would orphan it -- the same failure the derivation pin
        test exists to prevent, arriving through the storage layer instead.

            str  -> legacy, written before the tag existed; Ed25519 by
                    construction, because the old writer refused any length
                    but 32.
            dict -> tagged {"pubkey": hex, "algorithm": name}.

        Members that cannot be loaded are omitted here and reported by
        `list_unreadable_genesis_members` -- they are NOT forgotten, because
        an unreadable member is a different fact from an absent one.
        """
        return self._read_genesis_members()[0]

    def _read_genesis_members(
        self,
    ) -> tuple[dict[str, GenesisMember], dict[str, str]]:
        """(readable, unreadable) -- one pass, two answers.

        A bad entry never takes down the good ones: one corrupt member must
        not deny access to the rest of the set during a recovery. But it is
        RECORDED rather than swallowed, so a caller can tell the difference
        between a member that was never sealed and one that is damaged.
        """
        with self._lock:
            path = self._dir / "genesis_members.json"
            if not path.exists():
                return {}, {}
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                # The FILE is unreadable, which is not the same as an empty
                # vault either. Reported against a reserved kind so the
                # caller sees a reason instead of silence.
                return {}, {"<file>": f"genesis_members.json is unparseable: {exc}"}

            # GATE 5 -- THE CHAIN IS AUTHORITATIVE WHEN IT EXISTS.
            #
            # One source of truth at any moment. A vault sealed before the
            # chain existed has a flat `members` map and no chain; it keeps
            # working unchanged (the live vault is in exactly that state).
            # Once a chain is written the flat map is NOT consulted, because
            # two stores that can disagree is the defect this whole gate is
            # about.
            #
            # A chain that fails replay makes every member UNREADABLE -- never
            # absent. Tampering must never look like an empty vault.
            if raw.get("chain") is not None:
                return self._replay_stored_chain(raw.get("chain"))

            good: dict[str, GenesisMember] = {}
            bad: dict[str, str] = {}
            for k, v in (raw.get("members") or {}).items():
                if isinstance(v, str):
                    hexed, algo = v, GENESIS_LEGACY_ALGORITHM
                elif isinstance(v, dict):
                    hexed = v.get("pubkey")
                    algo = v.get("algorithm") or GENESIS_LEGACY_ALGORITHM
                    if not isinstance(hexed, str) or not isinstance(algo, str):
                        bad[k] = "stored entry is malformed (pubkey/algorithm)"
                        continue
                else:
                    bad[k] = f"stored entry has unexpected type {type(v).__name__}"
                    continue
                try:
                    pk = bytes.fromhex(hexed)
                except ValueError:
                    bad[k] = "stored pubkey is not valid hex"
                    continue
                # A member whose recorded length no longer matches its
                # recorded algorithm is NOT repaired. Repairing would mean
                # guessing which of the two fields is the truth, and a
                # silently corrected member verifies against a key nobody
                # chose.
                try:
                    algo = validate_genesis_pubkey(pk, algo)
                except ValueError as exc:
                    bad[k] = str(exc)
                    continue
                good[k] = GenesisMember(kind=k, pubkey=pk, algorithm=algo)
            return good, bad

    # ------------------------------------------------------------------
    # GATE 5 -- the membership chain WRITER.
    # ------------------------------------------------------------------
    #
    # The chain has had a reader since GATE 5 shipped and, until now, no
    # writer -- so no vault anywhere had a chain, and the detection was
    # guarding a shape that existed only in tests. A verifier with no
    # producer is not half a feature; it is a feature that has never been
    # exercised against anything an operator made.
    #
    # THE FLAT `members` MAP IS LEFT IN PLACE WHEN A CHAIN IS WRITTEN.
    # That is a decision with a cost, so it is stated rather than
    # implied. Current readers ignore it entirely once `chain` exists
    # (see `_read_genesis_members`), so it cannot cause a live
    # disagreement. It is kept because a bootloader running PRE-GATE-5
    # code does not know the `chain` key: with the flat map present such
    # a reader sees the pre-chain membership, and with it deleted it sees
    # an EMPTY VAULT. Between "stale on rollback" and "empty on
    # rollback", stale is the one that does not look like a vault that
    # was never sealed. The map goes deliberately stale from the moment
    # the chain exists and is never updated again.

    def supports_genesis_chain(self) -> bool:
        return True

    def read_genesis_chain(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._read_chain_locked()

    def _read_chain_locked(self) -> list[dict[str, Any]]:
        """Caller holds the lock. `[]` means NO CHAIN -- not a broken one."""
        from recto.bootloader.genesis_chain import ChainError

        path = self._dir / "genesis_members.json"
        if not path.exists():
            return []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            # Refuse rather than return []. An unparseable file that read
            # as "no chain" would let the writer start a FRESH chain over
            # the top of one it could not see -- the single worst thing
            # this writer could do.
            raise ChainError(
                f"genesis_members.json is unparseable ({exc}); refusing to "
                f"treat that as 'no chain'. Restore the file before writing."
            ) from exc
        chain = raw.get("chain")
        if chain is None:
            return []
        if not isinstance(chain, list):
            raise ChainError(
                f"the stored 'chain' is a {type(chain).__name__}, not a list"
            )
        return list(chain)

    def append_genesis_chain_entry(self, record: dict[str, Any]) -> None:
        """Append one entry after proving the RESULT still replays.

        **The whole chain is replayed, not just the new entry.** Validating
        only the appended entry would let this writer extend a chain that was
        already broken, which converts a detectable tamper into a chain with
        one honest-looking entry on the end of it.

        Raises ChainError and writes nothing if the result does not verify.
        """
        from recto.bootloader.genesis_chain import ChainError, build_entry, replay

        with self._lock:
            candidate = self._read_chain_locked() + [dict(record)]
            try:
                entries = [
                    build_entry(
                        seq=e["seq"], op=e["op"], kind=e["kind"],
                        pubkey=bytes.fromhex(e["pubkey"]), algorithm=e["algorithm"],
                        prev=e.get("prev"),
                        signatures=[
                            _b64u_decode(s) for s in (e.get("signatures") or [])
                        ],
                    )
                    for e in candidate
                ]
            except ChainError:
                raise
            except Exception as exc:
                raise ChainError(f"entry is not a well-formed record: {exc}") from exc

            replay(entries)  # THE GUARD. Raises, and nothing below runs.

            path = self._dir / "genesis_members.json"
            body: dict[str, Any] = {}
            if path.exists():
                try:
                    body = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    # Unreachable: `_read_chain_locked` above already refused
                    # on an unparseable file. Kept narrow rather than removed
                    # because the two reads are not one read.
                    body = {}
            if not isinstance(body, dict):
                body = {}
            body["chain"] = candidate
            body["stored_at_unix"] = int(time.time())
            self._atomic_write(path, body)

    def _save_operator_pubkey(self, pubkey: bytes) -> None:
        # Caller holds the lock.
        path = self._dir / "vault_root.json"
        body = {
            "operator_pubkey_hex": pubkey.hex(),
            "stored_at_unix": int(time.time()),
        }
        self._atomic_write(path, body)

    # ------------------------------------------------------------------
    # Capability revocations (Phase 5 Wave C part 2)
    # ------------------------------------------------------------------

    def add_revocation(self, entry: RevocationEntry) -> None:
        """Persist a new revocation entry. Idempotent -- adding the
        same jti twice is a no-op (the existing entry's
        revoked_at_unix / reason stand). Auto-purges expired entries
        before insert to keep the file small.
        """
        with self._lock:
            self._purge_expired_revocations()
            if entry.jti in self._revocations:
                return
            self._revocations[entry.jti] = entry
            self._save_revocations()

    def is_revoked(self, jti: str) -> bool:
        """True if ``jti`` is in the active revocation list. Auto-
        purges expired entries before the lookup so a JWT whose
        revocation entry has aged out (because the original JWT's
        exp passed) returns False -- but verify_jws would have
        already rejected such a JWT for being expired.
        """
        with self._lock:
            self._purge_expired_revocations()
            return jti in self._revocations

    def list_revocations(self) -> list[RevocationEntry]:
        """Return the sorted-by-jti list of active revocation
        entries. Auto-purges expired entries first. Used by
        ``GET /v0.4/capability/revocations`` to serve the wire
        shape.
        """
        with self._lock:
            self._purge_expired_revocations()
            return sorted(
                self._revocations.values(),
                key=lambda e: e.jti,
            )

    def _purge_expired_revocations(self) -> None:
        # Caller holds the lock.
        expired = [
            jti for jti, e in self._revocations.items() if e.is_expired
        ]
        if expired:
            for jti in expired:
                del self._revocations[jti]
            self._save_revocations()

    # ------------------------------------------------------------------
    # One-time challenges (in-memory on the file backend; restart
    # invalidates -- the documented single-host semantic)
    # ------------------------------------------------------------------

    def issue_challenge(self, ttl_seconds: int = 60) -> tuple[str, int]:
        c = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .rstrip(b"=")
            .decode("ascii")
        )
        exp = int(time.time()) + ttl_seconds
        with self._lock:
            self._purge_challenges()
            self._challenges[c] = exp
        return c, exp

    def consume_challenge(self, challenge: str) -> bool:
        with self._lock:
            self._purge_challenges()
            exp = self._challenges.pop(challenge, None)
        return exp is not None and time.time() < exp

    def issue_pairing_code(self, ttl_seconds: int = 300) -> tuple[str, int]:
        # 6-digit human-readable; collision risk acceptable for
        # personal-use (a collision just refreshes the code's expiry).
        code = f"{secrets.randbelow(1_000_000):06d}"
        exp = int(time.time()) + ttl_seconds
        with self._lock:
            self._purge_challenges()
            self._pairing_codes[code] = exp
        return code, exp

    def consume_pairing_code(self, code: str) -> bool:
        with self._lock:
            self._purge_challenges()
            exp = self._pairing_codes.pop(code, None)
        return exp is not None and time.time() < exp

    def _purge_challenges(self) -> None:
        # Caller holds the lock.
        now = time.time()
        self._challenges = {
            c: e for c, e in self._challenges.items() if e > now
        }
        self._pairing_codes = {
            c: e for c, e in self._pairing_codes.items() if e > now
        }

    # ------------------------------------------------------------------
    # Disk I/O (private)
    # ------------------------------------------------------------------

    def _load(self) -> None:
        with self._lock:
            phones_path = self._dir / "phones.json"
            if phones_path.exists():
                raw = json.loads(phones_path.read_text(encoding="utf-8"))
                for r in raw.get("phones", []):
                    r["supported_algorithms"] = tuple(r["supported_algorithms"])
                    self._phones[r["phone_id"]] = PhoneRegistration(**r)
            sessions_path = self._dir / "sessions.json"
            if sessions_path.exists():
                raw = json.loads(sessions_path.read_text(encoding="utf-8"))
                for s in raw.get("sessions", []):
                    sess = Session(**s)
                    self._sessions[(sess.service, sess.secret)] = sess
            # Pending requests are intentionally NOT reloaded across
            # bootloader restarts. In-flight requests fail; the child
            # decides whether to retry. This is safer than carrying
            # state forward across a possibly-dirty restart.
            #
            # Phase 5 Wave C part 2: revocation entries DO survive
            # restart -- a revocation that was committed yesterday
            # stays committed across a bootloader bounce.
            revocations_path = self._dir / "revocations.json"
            if revocations_path.exists():
                raw = json.loads(revocations_path.read_text(encoding="utf-8"))
                for r in raw.get("revocations", []):
                    entry = RevocationEntry(**r)
                    # Skip entries that have already aged out at load
                    # time. The next save_revocations call (triggered
                    # by any add or by the next purge_expired sweep)
                    # writes the cleaned list.
                    if not entry.is_expired:
                        self._revocations[entry.jti] = entry

    def _save_phones(self) -> None:
        path = self._dir / "phones.json"
        body = {
            "phones": [self._asdict_phone(p) for p in self._phones.values()],
        }
        self._atomic_write(path, body)

    def _save_sessions(self) -> None:
        path = self._dir / "sessions.json"
        body = {
            "sessions": [asdict(s) for s in self._sessions.values()],
        }
        self._atomic_write(path, body)

    def _save_pending(self) -> None:
        path = self._dir / "pending.json"
        body = {
            "pending": [asdict(p) for p in self._pending.values()],
        }
        self._atomic_write(path, body)

    def _save_revocations(self) -> None:
        path = self._dir / "revocations.json"
        body = {
            "revocations": [asdict(e) for e in self._revocations.values()],
        }
        self._atomic_write(path, body)

    @staticmethod
    def _asdict_phone(p: PhoneRegistration) -> dict[str, Any]:
        d = asdict(p)
        d["supported_algorithms"] = list(d["supported_algorithms"])
        return d

    @staticmethod
    def _atomic_write(path: Path, body: dict[str, Any]) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(body, indent=2, sort_keys=True), encoding="utf-8")
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        # os.replace is atomic on POSIX; on Windows it replaces if dst
        # exists (Python 3.3+ behavior).
        os.replace(tmp, path)

    def _purge_expired_pending(self) -> None:
        # Caller holds the lock.
        expired = [
            rid for rid, req in self._pending.items() if req.is_expired
        ]
        for rid in expired:
            del self._pending[rid]
        if expired:
            self._save_pending()
