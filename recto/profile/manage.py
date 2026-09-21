"""
High-level master + child profile operations — Phase 2.0.B foundation.

Operations exposed:
  - ``bootstrap_master`` — create the MasterIdentity record from an
    operator pubkey. Refuses to overwrite an existing master unless
    ``force=True`` (rotation path; rare).
  - ``create_child_profile`` — append a child Profile to an existing
    master's profiles list. Idempotent on (kind, display_name) match
    so repeated calls don't accumulate duplicates.
  - ``list_profiles`` — flatten the master's profiles tuple to a list.
  - ``get_profile_by_id`` — O(N) lookup; profiles tuples stay short
    enough (master + handful of children) that a dict cache would be
    premature optimization.
  - ``next_profile_index`` — derive the next available BIP-32 index
    for a given profile_coin_type slot, so callers don't collide.
  - ``mark_profile_revoked`` — flag a profile as revoked; the row
    stays in the blob (history preserved) but capability JWSes
    referencing it via parent_profile fail verification.

Hard rules in play:
  - #1 backward-compat: every operation here is additive at the
    on-disk JSON layer.
  - #9 plural-profiles corollary: the master profile (kind ==
    PROFILE_KIND_PERSONAL_MASTER) can never be revoked while child
    profiles exist. Operators must revoke children first OR rotate
    the master (separate operation, master-rotate, future wave).
  - operations that mutate the MasterIdentity blob go through this
    module's functions, NOT through direct profile/store.py writes.
    Centralizing mutation here keeps invariant-checks consistent.

This module is the public API surface that downstream callers (the
bootloader's profile_create endpoint, the CLI's `recto profile`
subcommands, future SCIM provisioning glue) should reach for. Direct
use of `recto.profile.store` is reserved for tests and dev tooling.

Design reference: recto/profile/SPEC.md "Phase 2.0.B" + ARCHITECTURE.md
"Multi-profile identity" ADR.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from recto.profile.store import (
    load_master_identity,
    save_master_identity,
)
from recto.profile.types import (
    PROFILE_KIND_PERSONAL_MASTER,
    MasterIdentity,
    Profile,
    ProfileDerivationPath,
)


# ---------------------------------------------------------------------------
# BIP-32 derivation constants for profile slots
# ---------------------------------------------------------------------------

# The "purpose" field for profile-tree BIP-32 derivation. Reserved
# value pending formal SLIP-44 / BIP-43 registration; uses the ASCII-
# integer encoding of "rect" (0x72=r, 0x65=e, 0x63=c, 0x74=t) -> bytes
# packed big-endian = 0x72656374. Banked as a v2.0 reservation; if
# this collides with a future BIP-43 assignment we'll re-pick at
# v2.1 with a migration path.
PROFILE_BIP32_PURPOSE = 0x72656374

# Per-canonical-kind coin-type-slot assignments. Custom kinds start
# at 100. Reserved indices 0..99 for canonical kinds in the order
# they appear in CANONICAL_PROFILE_KINDS.
PROFILE_COIN_TYPES: dict[str, int] = {
    "personal:master": 0,
    "personal:child": 1,
    "work": 2,
    "school": 3,
    "contractor": 4,
}

CUSTOM_COIN_TYPE_FLOOR = 100
"""Custom (operator-defined) profile kinds get coin-type slots
starting at 100. Pickers should hash the kind string into a stable
bucket >= 100 to avoid collisions with canonical kinds."""


def _resolve_coin_type(kind: str) -> int:
    """Map a profile kind string to its BIP-32 coin-type slot.

    Canonical kinds get pre-assigned slots (0..4). Custom kinds get
    a stable hash-derived slot at or above CUSTOM_COIN_TYPE_FLOOR.

    Raises:
        ValueError: if kind is the empty string.
    """
    if not kind:
        raise ValueError("profile kind must be a non-empty string")
    canonical = PROFILE_COIN_TYPES.get(kind)
    if canonical is not None:
        return canonical
    # Custom kind: hash to a stable bucket starting at CUSTOM_COIN_TYPE_FLOOR.
    # Using zlib.crc32 + modulo keeps the result deterministic across Python
    # versions (unlike hash() which is salted per-process).
    import zlib

    bucket_range = 10000  # custom kinds occupy 100..10099
    bucket = zlib.crc32(kind.encode("utf-8")) % bucket_range
    return CUSTOM_COIN_TYPE_FLOOR + bucket


# ---------------------------------------------------------------------------
# Bootstrap (one-time, idempotent)
# ---------------------------------------------------------------------------


class MasterAlreadyBootstrappedError(Exception):
    """Raised when bootstrap_master would overwrite an existing master.

    Re-raise this in CLI handlers so the operator gets a clear error
    instead of a silent overwrite. To intentionally rotate, pass
    ``force=True`` to bootstrap_master.
    """


def bootstrap_master(
    master_pubkey_hex: str,
    *,
    display_name: str = "Personal (master)",
    label: str | None = None,
    state_dir: Path | None = None,
    force: bool = False,
) -> MasterIdentity:
    """Create the MasterIdentity record from an operator's pubkey.

    The master profile (kind = personal:master, index 0, no parent)
    is created as the first row in the profiles list. The operator's
    BIP-39 mnemonic stays on the phone enclave; this function only
    records the public-side identity.

    Args:
        master_pubkey_hex: 128-hex secp256k1 master pubkey (X||Y, no
            0x04 prefix). Matches what `recto vault bootstrap` accepts
            as the operator pubkey.
        display_name: human-readable label for the master profile row.
            Defaults to "Personal (master)".
        label: optional operator-facing label for the MasterIdentity
            itself (e.g. "Erik (primary master)"). Defaults to
            display_name if None.
        state_dir: override the default bootloader state directory.
            Tests + multi-instance hosts use this.
        force: True to overwrite an existing MasterIdentity. Used for
            master rotation (catastrophic-tier operation; future wave
            adds the capability JWS gating).

    Returns:
        The newly-created MasterIdentity.

    Raises:
        MasterAlreadyBootstrappedError: if a MasterIdentity already
            exists and force is False.
        ValueError: on pubkey shape failure (length / non-hex chars).
    """
    # Validate pubkey shape
    cleaned = master_pubkey_hex.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if cleaned.startswith("04") and len(cleaned) == 130:
        # Strip the SEC1 uncompressed-point prefix
        cleaned = cleaned[2:]
    if len(cleaned) != 128:
        raise ValueError(
            f"master_pubkey_hex must be 128 hex chars (got {len(cleaned)}); "
            f"accepts optional 0x prefix and 0x04 SEC1 uncompressed prefix"
        )
    try:
        bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"master_pubkey_hex contains non-hex chars: {exc}") from exc

    # Idempotency check
    existing = load_master_identity(state_dir=state_dir)
    if existing is not None and not force:
        raise MasterAlreadyBootstrappedError(
            f"MasterIdentity already exists at "
            f"master_pubkey={existing.master_pubkey_hex[:8]}...{existing.master_pubkey_hex[-8:]}; "
            f"pass force=True to overwrite (rotation path)"
        )

    # Construct the master profile row
    master_profile_id = str(uuid.uuid4())
    now = int(time.time())
    master_profile = Profile(
        profile_id=master_profile_id,
        kind=PROFILE_KIND_PERSONAL_MASTER,
        display_name=display_name,
        derivation=ProfileDerivationPath(
            purpose=PROFILE_BIP32_PURPOSE,
            profile_coin_type=PROFILE_COIN_TYPES[PROFILE_KIND_PERSONAL_MASTER],
            profile_index=0,
        ),
        parent_profile_id=None,
        created_at_unix=now,
    )

    mi = MasterIdentity(
        master_pubkey_hex=cleaned,
        master_profile_id=master_profile_id,
        profiles=(master_profile,),
        label=label if label is not None else display_name,
    )

    save_master_identity(mi, state_dir=state_dir)
    return mi


# ---------------------------------------------------------------------------
# Child profile creation
# ---------------------------------------------------------------------------


def create_child_profile(
    *,
    kind: str,
    display_name: str,
    state_dir: Path | None = None,
    theme_hint: str | None = None,
    scim_provider: str | None = None,
    deny_actions_inherited: tuple[str, ...] = (),
    profile_index_override: int | None = None,
    profile_id_override: str | None = None,
    derived_pubkey_hex: str | None = None,
    device_ids: tuple[str, ...] = (),
    revoke_quorum_k: int = 1,
) -> Profile:
    """Append a child Profile under the existing master.

    The BIP-32 derivation path is computed automatically:
      - purpose = PROFILE_BIP32_PURPOSE
      - profile_coin_type = looked up from PROFILE_COIN_TYPES (canonical
        kinds) or hashed (custom kinds)
      - profile_index = next available index in that coin-type slot
        (callers can override via profile_index_override for tests)

    Idempotent on (kind, display_name): if a profile with the same
    kind AND display_name already exists, returns that profile rather
    than creating a duplicate. This lets startup-time provisioning
    code call this function unconditionally without needing pre-flight
    "does it exist" checks.

    Args:
        kind: canonical (personal:child / work / school / contractor)
            or operator-defined custom string. Empty string rejected.
        display_name: human-readable label shown on phone approval
            cards. Must be non-empty.
        state_dir: override the default bootloader state directory.
        theme_hint: optional UI theme identifier for the phone
            profile picker.
        scim_provider: optional SCIM provider URL for managed work /
            school / contractor profiles.
        deny_actions_inherited: action keys this profile can never use,
            even with valid capability scope. Populated by SCIM policy
            push for managed profiles; default empty for operator-
            controlled personal/contractor profiles.
        profile_index_override: skip the next-available-index logic
            and use this index instead. Tests pin specific indices;
            production code should always omit this.
        profile_id_override: use this profile_id instead of an
            auto-generated UUID4. Required by the bootloader's
            `_handle_profile_create` endpoint so the
            caller-authored ``candidate_profile_id`` becomes the
            canonical Profile.profile_id (Milan idempotency-key
            commitment A — the same id is the lookup key on retry,
            the audit trail key downstream, and what the caller
            knows BEFORE the operator approves on the phone). Direct
            CLI / SCIM callers should omit this and let manage.py
            auto-generate. Raises ValueError if the override
            collides with an existing profile (caller's
            responsibility to detect and handle).
        derived_pubkey_hex: Phase 2.0.C wave C.1 — the 128-hex
            secp256k1 pubkey (X||Y, no 0x04 prefix) the phone
            derived from the master mnemonic at this profile's
            BIP-32 path. Validated at the bootloader level (the
            master attestation binds this value to the candidate
            fields; if the phone lied, the recovered pubkey won't
            match the operator's master). Nullable so v2.0.B
            callers stay valid; v2.0.C bootloader respond path
            passes the verified-pubkey through. Raises ValueError
            if the value is malformed (length ≠ 128 OR non-hex).
            Idempotent-match path: if an existing Profile with the
            same (kind, display_name) is returned, its existing
            `derived_pubkey_hex` is preserved unchanged (the
            idempotency-key contract means re-submitting the same
            intent must NOT mutate persisted state).
        device_ids: Phase 2.0.C wave C.5 — phone_ids of the
            paired devices authorized to act on this profile's
            behalf. Defaults to empty tuple for v2.0.B callers
            that don't track device sets; v2.0.C bootloader
            respond path passes the approving phone's phone_id
            through as a single-element tuple at create time
            (the phone that approves master attestation becomes
            the new profile's first device). Subsequent additions
            land via the profile_add_device PendingRequest flow.
            Idempotent-match path: returned existing Profile's
            device_ids tuple is preserved unchanged. Raises
            ValueError on malformed entries (non-string OR empty
            string).
        revoke_quorum_k: Phase 2.0.C wave C.6 — number of
            signatures required from devices in `device_ids` to
            authorize a profile_revoke_device against this
            profile. Default 1 (any-single-device-signs).
            Must be >= 1. If `device_ids` is non-empty,
            additionally must be <= len(device_ids). At v1
            only K=1 is fully wired end-to-end; values >=2
            reserve the K-of-N aggregation surface for v1.1.
            Idempotent-match path: returned existing Profile's
            revoke_quorum_k is preserved unchanged.

    Returns:
        The created (or existing-matching) Profile.

    Raises:
        ValueError: kind / display_name validation failures, OR
            profile_id_override collision with an existing profile
            on a DIFFERENT (kind, display_name) — collisions on the
            SAME (kind, display_name) hit the idempotency early-return
            and don't raise.
        FileNotFoundError: MasterIdentity hasn't been bootstrapped.
            Call bootstrap_master first.
    """
    if not kind:
        raise ValueError("kind must be a non-empty string")
    if not display_name or not display_name.strip():
        raise ValueError("display_name must be a non-empty string")
    if kind == PROFILE_KIND_PERSONAL_MASTER:
        raise ValueError(
            f"cannot create child profile of kind {PROFILE_KIND_PERSONAL_MASTER!r}; "
            f"the master is created via bootstrap_master only"
        )
    # derived_pubkey_hex (Phase 2.0.C wave C.1): nullable for v2.0.B
    # callers; v2.0.C bootloader respond path passes the verified
    # value through. When supplied, validate shape — full secp256k1-
    # point-validity check happens at the bootloader's master-
    # attestation verify step (if the phone lied about the derived
    # pubkey, the recovered pubkey won't match the operator master,
    # so we don't double-validate here).
    if derived_pubkey_hex is not None:
        cleaned_pubkey = derived_pubkey_hex.strip().lower()
        if cleaned_pubkey.startswith("0x"):
            cleaned_pubkey = cleaned_pubkey[2:]
        if cleaned_pubkey.startswith("04") and len(cleaned_pubkey) == 130:
            cleaned_pubkey = cleaned_pubkey[2:]
        if len(cleaned_pubkey) != 128:
            raise ValueError(
                f"derived_pubkey_hex must be 128 hex chars after optional "
                f"0x / 0x04 prefix strip (got {len(cleaned_pubkey)})"
            )
        try:
            bytes.fromhex(cleaned_pubkey)
        except ValueError as exc:
            raise ValueError(
                f"derived_pubkey_hex contains non-hex chars: {exc}"
            ) from exc
        derived_pubkey_hex = cleaned_pubkey

    # revoke_quorum_k (Phase 2.0.C wave C.6): must be >= 1; upper-bound
    # check against device_ids happens after device_ids is dedup'd.
    if not isinstance(revoke_quorum_k, int) or revoke_quorum_k < 1:
        raise ValueError(
            f"revoke_quorum_k must be a positive int (>= 1); got "
            f"{revoke_quorum_k!r}"
        )

    # device_ids (Phase 2.0.C wave C.5): nullable-tuple shape. Validate
    # entries are non-empty strings; the bootloader respond path always
    # passes the approving phone_id which is a UUID4 string so this is
    # belt-and-suspenders against malformed test fixtures.
    device_ids_clean: tuple[str, ...] = tuple()
    for entry in device_ids:
        if not isinstance(entry, str):
            raise ValueError(
                f"device_ids entries must be str, got {type(entry).__name__}"
            )
        if not entry.strip():
            raise ValueError("device_ids entries must be non-empty strings")
        device_ids_clean = device_ids_clean + (entry.strip(),)
    # Dedupe while preserving order (a phone can't be on a profile twice).
    seen: set[str] = set()
    deduped: list[str] = []
    for entry in device_ids_clean:
        if entry not in seen:
            seen.add(entry)
            deduped.append(entry)
    device_ids_clean = tuple(deduped)

    # Upper-bound check on revoke_quorum_k. Only enforced when
    # device_ids is non-empty (you can't require K signatures from N
    # devices when N is smaller than K). Empty device_ids skip the
    # check because profile_add_device will populate device_ids before
    # any revoke can fire — by which point the quorum must already be
    # satisfiable.
    if device_ids_clean and revoke_quorum_k > len(device_ids_clean):
        raise ValueError(
            f"revoke_quorum_k={revoke_quorum_k} exceeds device_ids "
            f"length {len(device_ids_clean)}; cannot require more "
            f"signatures than the profile has devices"
        )

    mi = load_master_identity(state_dir=state_dir)
    if mi is None:
        raise FileNotFoundError(
            "MasterIdentity not bootstrapped; call bootstrap_master first"
        )

    # Idempotency: same (kind, display_name) already present?
    for existing in mi.profiles:
        if existing.kind == kind and existing.display_name == display_name:
            return existing

    # profile_id_override collision check — if the caller-supplied id
    # is already in use on a DIFFERENT (kind, display_name), refuse
    # the create rather than silently creating a row that breaks the
    # caller's idempotency-key contract.
    if profile_id_override is not None:
        for existing in mi.profiles:
            if existing.profile_id == profile_id_override:
                raise ValueError(
                    f"profile_id_override {profile_id_override!r} collides "
                    f"with an existing profile (kind={existing.kind!r}, "
                    f"display_name={existing.display_name!r}); caller must "
                    f"generate a fresh UUID for distinct intents"
                )

    coin_type = _resolve_coin_type(kind)
    if profile_index_override is not None:
        new_index = int(profile_index_override)
    else:
        new_index = _next_profile_index(mi, coin_type)

    now = int(time.time())
    new_profile = Profile(
        profile_id=(
            profile_id_override
            if profile_id_override is not None
            else str(uuid.uuid4())
        ),
        kind=kind,
        display_name=display_name.strip(),
        derivation=ProfileDerivationPath(
            purpose=PROFILE_BIP32_PURPOSE,
            profile_coin_type=coin_type,
            profile_index=new_index,
        ),
        parent_profile_id=mi.master_profile_id,
        theme_hint=theme_hint,
        scim_provider=scim_provider,
        deny_actions_inherited=tuple(deny_actions_inherited),
        created_at_unix=now,
        derived_pubkey_hex=derived_pubkey_hex,
        device_ids=device_ids_clean,
        revoke_quorum_k=revoke_quorum_k,
    )

    # Append + save
    updated = MasterIdentity(
        master_pubkey_hex=mi.master_pubkey_hex,
        master_profile_id=mi.master_profile_id,
        profiles=mi.profiles + (new_profile,),
        label=mi.label,
    )
    save_master_identity(updated, state_dir=state_dir)
    return new_profile


def profile_add_device(
    *,
    profile_id: str,
    new_phone_id: str,
    state_dir: Path | None = None,
) -> Profile:
    """Append a phone_id to an existing Profile's device_ids tuple.

    Phase 2.0.C wave C.5 storage-mutation primitive. The bootloader
    respond-handler for profile_add_device PendingRequests calls this
    AFTER verifying the master OR an already-paired device on the
    profile signed the canonical-JSON binding (profile_id +
    new_phone_id + added_at_unix). This function does NOT verify
    signatures — that's the bootloader's job; this function trusts the
    caller and persists the mutation.

    Idempotent on (profile_id, new_phone_id): if the phone is ALREADY
    in the profile's device_ids tuple, returns the unchanged Profile
    rather than re-appending. Lets the bootloader's idempotency-key
    handling (Milan commitment A) work without needing pre-flight
    "does it exist" checks at this layer.

    Args:
        profile_id: target profile to append the device to. Must
            match an existing profile_id under the bootstrapped master.
        new_phone_id: phone_id of the device being added. Must be
            non-empty string (UUID4 in production; tests may use
            simpler fixtures).
        state_dir: override the default bootloader state directory.

    Returns:
        The updated Profile with the new phone_id appended (or the
        unchanged existing Profile if new_phone_id was already in
        device_ids).

    Raises:
        ValueError: profile_id / new_phone_id validation failure,
            OR the target profile is revoked (revoked profiles
            cannot accept new devices; revoke + re-create instead).
        FileNotFoundError: MasterIdentity hasn't been bootstrapped.
        KeyError: profile_id not found under the bootstrapped master.
    """
    if not profile_id or not profile_id.strip():
        raise ValueError("profile_id must be a non-empty string")
    if not new_phone_id or not new_phone_id.strip():
        raise ValueError("new_phone_id must be a non-empty string")
    profile_id_clean = profile_id.strip()
    new_phone_id_clean = new_phone_id.strip()

    mi = load_master_identity(state_dir=state_dir)
    if mi is None:
        raise FileNotFoundError(
            "MasterIdentity not bootstrapped; call bootstrap_master first"
        )

    # Locate the target profile
    target_idx: int | None = None
    target: Profile | None = None
    for idx, existing in enumerate(mi.profiles):
        if existing.profile_id == profile_id_clean:
            target_idx = idx
            target = existing
            break
    if target is None or target_idx is None:
        raise KeyError(
            f"profile_id {profile_id_clean!r} not found under master "
            f"{mi.master_pubkey_hex[:16]}..."
        )

    # Revoked profiles cannot accept new devices.
    if target.revoked:
        raise ValueError(
            f"cannot add device to revoked profile {profile_id_clean!r}; "
            f"revoke + re-create the profile instead"
        )

    # Idempotency: already a member? return unchanged.
    if new_phone_id_clean in target.device_ids:
        return target

    # Construct the updated Profile with the new phone appended.
    updated_profile = Profile(
        profile_id=target.profile_id,
        kind=target.kind,
        display_name=target.display_name,
        derivation=target.derivation,
        parent_profile_id=target.parent_profile_id,
        theme_hint=target.theme_hint,
        scim_provider=target.scim_provider,
        deny_actions_inherited=target.deny_actions_inherited,
        created_at_unix=target.created_at_unix,
        revoked=target.revoked,
        derived_pubkey_hex=target.derived_pubkey_hex,
        device_ids=target.device_ids + (new_phone_id_clean,),
    )

    # Replace the profile in the MasterIdentity's profiles tuple.
    updated_profiles = (
        mi.profiles[:target_idx]
        + (updated_profile,)
        + mi.profiles[target_idx + 1 :]
    )
    updated_mi = MasterIdentity(
        master_pubkey_hex=mi.master_pubkey_hex,
        master_profile_id=mi.master_profile_id,
        profiles=updated_profiles,
        label=mi.label,
    )
    save_master_identity(updated_mi, state_dir=state_dir)
    return updated_profile


def profile_revoke_device(
    *,
    profile_id: str,
    phone_id_to_revoke: str,
    state_dir: Path | None = None,
) -> Profile:
    """Remove a phone_id from an existing Profile's device_ids tuple.

    Phase 2.0.C wave C.6 storage-mutation primitive. The bootloader
    respond-handler for profile_revoke_device PendingRequests calls
    this AFTER verifying K signatures from devices in `device_ids`
    over the canonical-JSON binding (profile_id +
    phone_id_to_revoke + revoked_at_unix + request_id). At v1 only
    K=1 is fully wired end-to-end; v1.1 lands the K-of-N
    signature-aggregation state machine on top of this storage
    primitive without schema changes.

    This function does NOT verify signatures — that's the bootloader's
    job; this function trusts the caller and persists the mutation.

    Idempotent on "not a member": if the phone_id_to_revoke is NOT
    in the profile's device_ids tuple, returns the unchanged Profile
    rather than failing. Lets the bootloader's idempotency-key
    handling (Milan commitment A) work without needing pre-flight
    "is it a member" checks at this layer.

    Args:
        profile_id: target profile to remove the device from.
            Must match an existing profile_id under the bootstrapped
            master.
        phone_id_to_revoke: phone_id of the device being removed.
            Must be a non-empty string (UUID4 in production).
        state_dir: override the default bootloader state directory.

    Returns:
        The updated Profile with the phone_id removed (or the
        unchanged existing Profile if phone_id_to_revoke wasn't in
        device_ids — the idempotent "not a member" return path).

    Raises:
        ValueError: profile_id / phone_id_to_revoke validation
            failure, OR the target profile is revoked (revoked
            profiles can't accept device-set mutations), OR the
            revoke would empty device_ids (last-device guard:
            removing the only device would make the profile
            unreachable — the master must rotate or revoke the
            entire profile, not its last device).
        FileNotFoundError: MasterIdentity hasn't been bootstrapped.
        KeyError: profile_id not found under the bootstrapped master.
    """
    if not profile_id or not profile_id.strip():
        raise ValueError("profile_id must be a non-empty string")
    if not phone_id_to_revoke or not phone_id_to_revoke.strip():
        raise ValueError("phone_id_to_revoke must be a non-empty string")
    profile_id_clean = profile_id.strip()
    phone_id_to_revoke_clean = phone_id_to_revoke.strip()

    mi = load_master_identity(state_dir=state_dir)
    if mi is None:
        raise FileNotFoundError(
            "MasterIdentity not bootstrapped; call bootstrap_master first"
        )

    # Locate the target profile.
    target_idx: int | None = None
    target: Profile | None = None
    for idx, existing in enumerate(mi.profiles):
        if existing.profile_id == profile_id_clean:
            target_idx = idx
            target = existing
            break
    if target is None or target_idx is None:
        raise KeyError(
            f"profile_id {profile_id_clean!r} not found under master "
            f"{mi.master_pubkey_hex[:16]}..."
        )

    # Revoked profiles can't accept device-set mutations.
    if target.revoked:
        raise ValueError(
            f"cannot revoke device from revoked profile "
            f"{profile_id_clean!r}; profile-level revocation is its "
            f"own operation"
        )

    # Idempotency: phone wasn't a member? return unchanged. The
    # bootloader's pre-flight catches this at the endpoint layer and
    # returns 200 already_not_a_member without queueing a phone
    # prompt; this guard is defense-in-depth for direct callers.
    if phone_id_to_revoke_clean not in target.device_ids:
        return target

    # Last-device guard: revoking the only device would leave the
    # profile unreachable (no paired device to sign future operations).
    # Refuse — the operator must rotate the profile or revoke it
    # entirely (a separate operation, not part of v1 C.6).
    if len(target.device_ids) == 1:
        raise ValueError(
            f"cannot revoke last device from profile "
            f"{profile_id_clean!r}; revoking the only paired device "
            f"would make the profile unreachable. Add a replacement "
            f"device via profile_add_device first, OR revoke the "
            f"entire profile via the (not-yet-implemented) "
            f"profile_revoke action."
        )

    # Construct the updated Profile with the phone_id removed.
    new_device_ids = tuple(
        d for d in target.device_ids if d != phone_id_to_revoke_clean
    )
    # Sanity check: the filter must have removed exactly one entry
    # (we'd have hit the idempotent return above if it wasn't a
    # member). Defense-in-depth against a future bug where the same
    # phone_id appears twice in device_ids (shouldn't happen — the
    # create_child_profile + profile_add_device dedup logic prevents
    # this — but if it does, remove BOTH copies for consistency).
    assert len(new_device_ids) < len(target.device_ids), (
        f"profile_revoke_device internal invariant violated: "
        f"device_ids didn't shrink after filtering out "
        f"{phone_id_to_revoke_clean!r}"
    )

    updated_profile = Profile(
        profile_id=target.profile_id,
        kind=target.kind,
        display_name=target.display_name,
        derivation=target.derivation,
        parent_profile_id=target.parent_profile_id,
        theme_hint=target.theme_hint,
        scim_provider=target.scim_provider,
        deny_actions_inherited=target.deny_actions_inherited,
        created_at_unix=target.created_at_unix,
        revoked=target.revoked,
        derived_pubkey_hex=target.derived_pubkey_hex,
        device_ids=new_device_ids,
        revoke_quorum_k=target.revoke_quorum_k,
    )

    # Replace the profile in the MasterIdentity's profiles tuple.
    updated_profiles = (
        mi.profiles[:target_idx]
        + (updated_profile,)
        + mi.profiles[target_idx + 1 :]
    )
    updated_mi = MasterIdentity(
        master_pubkey_hex=mi.master_pubkey_hex,
        master_profile_id=mi.master_profile_id,
        profiles=updated_profiles,
        label=mi.label,
    )
    save_master_identity(updated_mi, state_dir=state_dir)
    return updated_profile


def _next_profile_index(mi: MasterIdentity, coin_type: int) -> int:
    """Find the next available BIP-32 index in the given coin-type slot.

    Master profile always lives at index 0 of its slot. Subsequent
    profiles get indices 1, 2, 3, ... in creation order. If a profile
    has been deleted (which we don't currently support but might in
    v2.1+), the index it occupied is NOT reused — we always pick
    max(current_indices) + 1 to keep the BIP-32 paths historically
    stable.
    """
    used = {
        p.derivation.profile_index
        for p in mi.profiles
        if p.derivation.profile_coin_type == coin_type
    }
    if not used:
        return 0
    return max(used) + 1


# ---------------------------------------------------------------------------
# Read-side operations
# ---------------------------------------------------------------------------


def list_profiles(state_dir: Path | None = None) -> list[Profile]:
    """Return all profiles under the master as a list.

    Returns empty list if no MasterIdentity has been bootstrapped.
    The master profile is included in the returned list (it's a row
    like any other; the only thing special about it is parent_profile_id
    is None).

    Ordered by creation timestamp ascending; master first, then
    children in creation order. Callers wanting a specific order
    (e.g. by kind, by display_name) should sort the returned list
    themselves.
    """
    mi = load_master_identity(state_dir=state_dir)
    if mi is None:
        return []
    return sorted(mi.profiles, key=lambda p: p.created_at_unix)


def get_profile_by_id(
    profile_id: str,
    state_dir: Path | None = None,
) -> Profile | None:
    """Look up a single profile by its profile_id.

    Returns None if no MasterIdentity exists OR no profile matches
    the given id. O(N) over the profiles list (which stays small —
    master + a handful of children).
    """
    mi = load_master_identity(state_dir=state_dir)
    if mi is None:
        return None
    for p in mi.profiles:
        if p.profile_id == profile_id:
            return p
    return None


def get_master_pubkey_hex(state_dir: Path | None = None) -> str | None:
    """Return the master pubkey hex, or None if no master is bootstrapped.

    Convenience for downstream consumers that need the master pubkey
    for deduplication (e.g. a consumer's user-record public-key column
    per that consumer's own architectural commitments) — they
    can call this directly without parsing the full MasterIdentity.
    """
    mi = load_master_identity(state_dir=state_dir)
    return mi.master_pubkey_hex if mi is not None else None


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def mark_profile_revoked(
    profile_id: str,
    state_dir: Path | None = None,
) -> Profile:
    """Mark a child profile as revoked.

    Capability JWSes referencing the profile via parent_profile fail
    verification post-revoke. The Profile row stays in the blob
    (history preserved); a new profile with the same kind +
    display_name can be created afterwards.

    Master profile cannot be revoked while child profiles exist —
    operators must either revoke each child first OR run master-rotate
    (a future-wave operation that catastrophic-tier-rotates the entire
    tree under a new seed).

    Args:
        profile_id: the profile_id to revoke.
        state_dir: override the default bootloader state directory.

    Returns:
        The updated (now-revoked) Profile.

    Raises:
        FileNotFoundError: no MasterIdentity bootstrapped.
        KeyError: profile_id not found.
        ValueError: attempting to revoke the master while children
            exist.
    """
    mi = load_master_identity(state_dir=state_dir)
    if mi is None:
        raise FileNotFoundError("MasterIdentity not bootstrapped")

    target_idx = None
    for i, p in enumerate(mi.profiles):
        if p.profile_id == profile_id:
            target_idx = i
            break
    if target_idx is None:
        raise KeyError(f"profile_id {profile_id!r} not found")

    target = mi.profiles[target_idx]

    # Refuse to revoke master while children exist
    if target.profile_id == mi.master_profile_id:
        non_master_children = [
            p for p in mi.profiles
            if p.profile_id != mi.master_profile_id and not p.revoked
        ]
        if non_master_children:
            raise ValueError(
                f"cannot revoke master profile while "
                f"{len(non_master_children)} active child profile(s) exist; "
                f"revoke children first OR use master-rotate (future wave)"
            )

    # Build the updated row
    revoked_profile = Profile(
        profile_id=target.profile_id,
        kind=target.kind,
        display_name=target.display_name,
        derivation=target.derivation,
        parent_profile_id=target.parent_profile_id,
        theme_hint=target.theme_hint,
        scim_provider=target.scim_provider,
        deny_actions_inherited=target.deny_actions_inherited,
        created_at_unix=target.created_at_unix,
        revoked=True,
    )

    new_profiles = (
        mi.profiles[:target_idx]
        + (revoked_profile,)
        + mi.profiles[target_idx + 1 :]
    )
    updated = MasterIdentity(
        master_pubkey_hex=mi.master_pubkey_hex,
        master_profile_id=mi.master_profile_id,
        profiles=new_profiles,
        label=mi.label,
    )
    save_master_identity(updated, state_dir=state_dir)
    return revoked_profile


__all__ = [
    "MasterAlreadyBootstrappedError",
    "PROFILE_BIP32_PURPOSE",
    "PROFILE_COIN_TYPES",
    "CUSTOM_COIN_TYPE_FLOOR",
    "bootstrap_master",
    "create_child_profile",
    "list_profiles",
    "get_profile_by_id",
    "get_master_pubkey_hex",
    "mark_profile_revoked",
]
