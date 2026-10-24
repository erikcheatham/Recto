"""
MasterIdentity vault storage layer — Phase 2.0.B foundation.

Persists the operator's MasterIdentity blob (master pubkey + master
profile_id + list of child profiles) at `<state-dir>/master_identity.json`.
Atomic writes via tmpfile+rename, mode 0700 on POSIX hosts (Windows
inherits parent ACL), corruption-tolerant load.

This module is the Phase 2.0.B foundation that the rest of the
profiles-runtime layer (bootloader endpoint, capability JWT
parent_profile chain validation, phone-side approval UI) builds on.
The full v2.0 runtime ships across multiple sprints; this file is the
canonical home for "where the master identity actually lives on disk."

Hard rules in play:
  - #1 backward-compat: the on-disk JSON schema is additive only.
    Fields can be added without bumping the file format; readers
    tolerate unknown fields by ignoring them.
  - #9 plural-profiles corollary: every profile in the blob's
    profiles[] list derives from the master_pubkey_hex's underlying
    BIP-39 mnemonic via BIP-32 hardened derivation. Reader code
    never assumes the master is a "phone enclave master" specifically
    — it's whatever entity the operator-pubkey-hex represents.
  - Single-write-source: only `save_master_identity()` writes the
    file. All callers that mutate the MasterIdentity go through
    `recto.profile.manage`'s high-level operations, which call
    save_master_identity at the appropriate atomic boundary.

Design reference: ARCHITECTURE.md "Multi-profile identity:
personal-as-master-key hierarchy (DESIGN BANKED)" (2026-05-15 entry)
and recto/profile/SPEC.md.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from recto.bootloader.state import default_state_dir
from recto.profile.types import (
    MasterIdentity,
    Profile,
    ProfileDerivationPath,
)


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


_VAULT_FILENAME = "master_identity.json"


def master_identity_path(state_dir: Path | None = None) -> Path:
    """Resolve the canonical on-disk path for the MasterIdentity blob.

    Defaults to ``<bootloader-state-dir>/master_identity.json``. The
    bootloader state directory respects the same env var
    (``RECTO_BOOTLOADER_STATE_DIR``) and per-platform defaults that
    the rest of the bootloader uses — keeps profile storage co-located
    with the vault root, revocations list, and pending phone registry
    so a single `state_dir` override flows through every persistence
    layer.

    Callers can pass an explicit ``state_dir`` to override (used by
    tests + by operators who shard storage across multiple Recto
    instances on the same host).
    """
    if state_dir is None:
        state_dir = default_state_dir()
    return state_dir / _VAULT_FILENAME


# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------


def load_master_identity(state_dir: Path | None = None) -> MasterIdentity | None:
    """Read the MasterIdentity blob from disk.

    Returns ``None`` if the file doesn't exist (the operator hasn't
    yet bootstrapped a master). Returns the parsed MasterIdentity on
    success.

    Corruption tolerance: if the file exists but isn't valid JSON
    OR is missing required fields, returns ``None`` AND moves the
    corrupt file aside to ``master_identity.json.corrupt-<unix-ts>``
    so the operator can recover by re-bootstrapping. This mirrors
    how `vault_root.json` handles corruption — fail open rather than
    leaving the operator unable to use the system.

    Raises:
        FileNotFoundError: NOT raised — absence returns None.
        OSError: re-raised if file exists but can't be read (permission
            denied, etc.) so the operator gets a clear error rather
            than silently treating "permission denied" as "no master."
    """
    path = master_identity_path(state_dir)
    if not path.exists():
        return None

    try:
        raw_bytes = path.read_bytes()
    except OSError:
        # Permission / IO error — caller needs to know
        raise

    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _move_corrupt_file_aside(path, reason=f"JSON decode: {exc}")
        return None

    try:
        return _master_identity_from_dict(raw)
    except (KeyError, TypeError, ValueError) as exc:
        _move_corrupt_file_aside(path, reason=f"schema: {exc}")
        return None


def save_master_identity(
    mi: MasterIdentity,
    state_dir: Path | None = None,
) -> Path:
    """Persist the MasterIdentity blob to disk atomically.

    Writes via tmpfile + os.replace so a partial write never leaves
    the file half-populated on disk. On POSIX hosts the file is
    chmod'd 0700 after write (owner-read/write only); on Windows the
    parent directory's ACL is inherited.

    The state directory is created with mode 0700 if absent. Mirrors
    `StateStore`'s init pattern.

    Returns the path the blob was written to (useful for log lines
    and tests).

    Raises:
        OSError: if the directory can't be created or the file can't
            be written. Callers should treat this as fatal — a save
            failure means subsequent reads will return stale data.
    """
    path = master_identity_path(state_dir)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    payload = _master_identity_to_dict(mi)
    raw_bytes = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")

    # Atomic write: tmpfile in the same directory + os.replace
    fd, tmp_path_str = tempfile.mkstemp(
        prefix=".master_identity.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_path_str)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw_bytes)
            fh.flush()
            os.fsync(fh.fileno())
        # POSIX: chmod before rename so the destination inherits 0600
        # rather than the tmpfile's default 0600 (which is what mkstemp
        # gives us anyway, but explicit is better).
        if os.name == "posix":
            os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        # Best-effort cleanup of the orphaned tmpfile
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise

    return path


# ---------------------------------------------------------------------------
# Dict <-> dataclass conversion
# ---------------------------------------------------------------------------


def _master_identity_to_dict(mi: MasterIdentity) -> dict:
    """Serialize MasterIdentity to a JSON-friendly dict.

    Schema:
        {
            "schema_version": 1,
            "master_pubkey_hex": str,
            "master_profile_id": str,
            "label": str | null,
            "profiles": [
                {
                    "profile_id": str,
                    "kind": str,
                    "display_name": str,
                    "derivation": {"purpose": int, "profile_coin_type": int, "profile_index": int},
                    "parent_profile_id": str | null,
                    "theme_hint": str | null,
                    "scim_provider": str | null,
                    "deny_actions_inherited": [str, ...],
                    "created_at_unix": int,
                    "revoked": bool
                },
                ...
            ]
        }

    schema_version is 1 today. Reader tolerates unknown fields (forward-
    compat) and writer never removes fields (backward-compat).
    """
    return {
        "schema_version": 1,
        "master_pubkey_hex": mi.master_pubkey_hex,
        "master_profile_id": mi.master_profile_id,
        "label": mi.label,
        "profiles": [_profile_to_dict(p) for p in mi.profiles],
    }


def _profile_to_dict(p: Profile) -> dict:
    """Serialize a single Profile.

    The `derived_pubkey_hex` field (Phase 2.0.C wave C.1) is OMITTED
    from the serialized blob when None, to keep on-disk JSON for
    v2.0.B-era Profile rows byte-identical to what they were
    serialized as before the field existed. v2.0.C-and-later Profile
    rows carry the field with their derived secp256k1 pubkey.
    """
    out: dict = {
        "profile_id": p.profile_id,
        "kind": p.kind,
        "display_name": p.display_name,
        "derivation": {
            "purpose": p.derivation.purpose,
            "profile_coin_type": p.derivation.profile_coin_type,
            "profile_index": p.derivation.profile_index,
        },
        "parent_profile_id": p.parent_profile_id,
        "theme_hint": p.theme_hint,
        "scim_provider": p.scim_provider,
        "deny_actions_inherited": list(p.deny_actions_inherited),
        "created_at_unix": p.created_at_unix,
        "revoked": p.revoked,
    }
    if p.derived_pubkey_hex is not None:
        out["derived_pubkey_hex"] = p.derived_pubkey_hex
    # device_ids (Phase 2.0.C wave C.5): omit when empty so v2.0.B-era
    # rows that never received a device_ids field stay byte-identical
    # on round-trip. v2.0.C-and-later creates auto-populate the tuple
    # with the approving phone_id; profile_add_device appends.
    if p.device_ids:
        out["device_ids"] = list(p.device_ids)
    # revoke_quorum_k (Phase 2.0.C wave C.6): omit when == 1 (default)
    # so v2.0.B / v2.0.C-pre-C.6-era rows stay byte-identical on
    # round-trip. Values >=2 reserve K-of-N quorum aggregation for
    # v1.1; v1 (this wave) ships persistence + K=1 enforcement only.
    if p.revoke_quorum_k != 1:
        out["revoke_quorum_k"] = p.revoke_quorum_k
    return out


def _master_identity_from_dict(raw: dict) -> MasterIdentity:
    """Parse a dict (from on-disk JSON) into a typed MasterIdentity.

    Validates required fields are present. Raises KeyError / TypeError
    / ValueError on schema mismatches; the load() wrapper catches these
    and moves the corrupt file aside.
    """
    if not isinstance(raw, dict):
        raise TypeError(f"expected dict, got {type(raw).__name__}")

    # Pubkey + master profile id are required
    master_pubkey_hex = raw["master_pubkey_hex"]
    if not isinstance(master_pubkey_hex, str) or len(master_pubkey_hex) != 128:
        raise ValueError(
            f"master_pubkey_hex must be 128 hex chars (got len {len(master_pubkey_hex)})"
        )
    master_profile_id = raw["master_profile_id"]
    if not isinstance(master_profile_id, str) or not master_profile_id:
        raise ValueError("master_profile_id must be a non-empty string")

    label = raw.get("label")
    if label is not None and not isinstance(label, str):
        raise ValueError(f"label must be str or None, got {type(label).__name__}")

    profiles_raw = raw.get("profiles", [])
    if not isinstance(profiles_raw, list):
        raise ValueError(
            f"profiles must be a list, got {type(profiles_raw).__name__}"
        )

    profiles = tuple(_profile_from_dict(p) for p in profiles_raw)

    # Sanity: at least one profile must be present + match master_profile_id
    if not profiles:
        raise ValueError(
            "profiles list is empty; a MasterIdentity must contain at minimum "
            "the master profile row"
        )
    master_in_list = any(p.profile_id == master_profile_id for p in profiles)
    if not master_in_list:
        raise ValueError(
            f"master_profile_id={master_profile_id!r} not found in profiles list"
        )

    return MasterIdentity(
        master_pubkey_hex=master_pubkey_hex,
        master_profile_id=master_profile_id,
        profiles=profiles,
        label=label,
    )


def _profile_from_dict(raw: dict) -> Profile:
    """Parse a single profile dict into a typed Profile."""
    if not isinstance(raw, dict):
        raise TypeError(f"profile entry must be dict, got {type(raw).__name__}")

    deriv_raw = raw["derivation"]
    if not isinstance(deriv_raw, dict):
        raise TypeError(
            f"profile.derivation must be dict, got {type(deriv_raw).__name__}"
        )
    derivation = ProfileDerivationPath(
        purpose=int(deriv_raw["purpose"]),
        profile_coin_type=int(deriv_raw["profile_coin_type"]),
        profile_index=int(deriv_raw["profile_index"]),
    )

    deny_actions_raw = raw.get("deny_actions_inherited", [])
    if not isinstance(deny_actions_raw, list):
        raise TypeError(
            f"deny_actions_inherited must be list, "
            f"got {type(deny_actions_raw).__name__}"
        )

    # derived_pubkey_hex (Phase 2.0.C wave C.1): absent in v2.0.B-era
    # rows; reader tolerates the absence and defaults to None. v2.0.C-
    # and-later rows carry the field with their derived secp256k1
    # pubkey. Shape validation here is light (hex chars + length); the
    # full secp256k1-point-validity check runs at write time in the
    # bootloader's profile_create verify path.
    derived_pubkey_hex_raw = raw.get("derived_pubkey_hex")
    if derived_pubkey_hex_raw is not None:
        if not isinstance(derived_pubkey_hex_raw, str):
            raise ValueError(
                f"derived_pubkey_hex must be str or null, got "
                f"{type(derived_pubkey_hex_raw).__name__}"
            )
        if len(derived_pubkey_hex_raw) != 128:
            raise ValueError(
                f"derived_pubkey_hex must be 128 hex chars (got len "
                f"{len(derived_pubkey_hex_raw)})"
            )
        try:
            bytes.fromhex(derived_pubkey_hex_raw)
        except ValueError as exc:
            raise ValueError(
                f"derived_pubkey_hex contains non-hex chars: {exc}"
            ) from exc

    # revoke_quorum_k (Phase 2.0.C wave C.6): absent in v2.0.B /
    # v2.0.C-pre-C.6-era rows; reader tolerates the absence and
    # defaults to 1 (any-single-device-signs semantics). When present
    # must be a positive int.
    revoke_quorum_k_raw = raw.get("revoke_quorum_k", 1)
    if not isinstance(revoke_quorum_k_raw, int) or revoke_quorum_k_raw < 1:
        raise ValueError(
            f"revoke_quorum_k must be a positive int (>= 1), got "
            f"{revoke_quorum_k_raw!r}"
        )

    # device_ids (Phase 2.0.C wave C.5): absent in v2.0.B-era rows;
    # reader tolerates the absence and defaults to an empty tuple.
    # Shape validation: each entry must be a non-empty string (phone_id
    # is a UUID4 string; an empty string would be a serialization bug).
    device_ids_raw = raw.get("device_ids", [])
    if not isinstance(device_ids_raw, list):
        raise TypeError(
            f"device_ids must be list, got {type(device_ids_raw).__name__}"
        )
    device_ids_validated: list[str] = []
    for entry in device_ids_raw:
        if not isinstance(entry, str):
            raise ValueError(
                f"device_ids entries must be str, got {type(entry).__name__}"
            )
        if not entry:
            raise ValueError(
                "device_ids entries must be non-empty strings"
            )
        device_ids_validated.append(entry)

    return Profile(
        profile_id=str(raw["profile_id"]),
        kind=str(raw["kind"]),
        display_name=str(raw["display_name"]),
        derivation=derivation,
        parent_profile_id=raw.get("parent_profile_id"),
        theme_hint=raw.get("theme_hint"),
        scim_provider=raw.get("scim_provider"),
        deny_actions_inherited=tuple(str(d) for d in deny_actions_raw),
        created_at_unix=int(raw.get("created_at_unix", 0)),
        revoked=bool(raw.get("revoked", False)),
        derived_pubkey_hex=derived_pubkey_hex_raw,
        device_ids=tuple(device_ids_validated),
        revoke_quorum_k=revoke_quorum_k_raw,
    )


# ---------------------------------------------------------------------------
# Corruption handling
# ---------------------------------------------------------------------------


def _move_corrupt_file_aside(path: Path, *, reason: str) -> None:
    """Rename a corrupt master_identity.json aside for operator recovery.

    Creates ``<path>.corrupt-<unix-ts>`` next to the original so the
    operator can inspect what was there. Best-effort: if the rename
    fails, log to stderr but don't crash — the caller is about to
    return None and the operator's next bootstrap will re-create the
    file from scratch.
    """
    import sys
    import time

    aside = path.with_name(f"{path.name}.corrupt-{int(time.time())}")
    try:
        path.rename(aside)
        print(
            f"recto.profile.store: master_identity.json corrupt ({reason}); "
            f"moved aside to {aside}",
            file=sys.stderr,
        )
    except OSError as exc:
        print(
            f"recto.profile.store: master_identity.json corrupt ({reason}); "
            f"could not move aside: {exc}",
            file=sys.stderr,
        )


__all__ = [
    "load_master_identity",
    "save_master_identity",
    "master_identity_path",
]
