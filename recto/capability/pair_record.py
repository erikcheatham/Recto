"""
Pairing record: the canonical tuple a phone signs when binding to a
consumer account, and the verifier that admits a grant only for that
exact tuple.

The pairing code is a human alias, not the act. The grant's
``cap.scope.payload_sha256`` must equal the fingerprint of the whole
tuple, computed identically on phone, bootloader and consumer.

Pure stdlib.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from recto.capability.types import CapabilityClaims

PAIR_ACTION = "devices:pair"
UNPAIR_ACTION = "devices:unpair"

# The signed window may never exceed this many seconds (nbf..exp).
PAIR_WINDOW_CEILING_SECONDS = 3600

# The signed fields, sorted.
PAIR_RECORD_FIELDS = ("bootloader_id", "code", "not_after", "phone_pubkey", "user_id")

_PUBKEY_HEX = re.compile(r"^[0-9a-f]{128}$")


class PairRefused(ValueError):
    """A named refusal. ``name`` is stable; ``detail`` may change."""

    def __init__(self, name: str, detail: str = "") -> None:
        super().__init__(f"{name}: {detail}" if detail else name)
        self.name = name
        self.detail = detail


# Refusal names.
RECORD_PUBKEY_MALFORMED = "record_pubkey_malformed"
RECORD_FIELD_EMPTY = "record_field_empty"
RECORD_NOT_AFTER_MALFORMED = "record_not_after_malformed"
RECORD_EXPIRED = "record_expired"
GRANT_ACTION_NOT_PAIR = "grant_action_not_pair"
GRANT_SCOPE_MISSING_FINGERPRINT = "grant_scope_missing_fingerprint"
GRANT_SCOPE_FINGERPRINT_MISMATCH = "grant_scope_fingerprint_mismatch"
GRANT_CODE_MISMATCH = "grant_code_mismatch"
GRANT_SIGNER_NOT_RECORD_PHONE = "grant_signer_not_record_phone"
GRANT_WINDOW_EXCEEDS_CEILING = "grant_window_exceeds_ceiling"
GRANT_AUDIENCE_NOT_BOOTLOADER = "grant_audience_not_bootloader"


@dataclass(frozen=True)
class PairRecord:
    """``phone_pubkey``: 128 lowercase hex (X||Y, no 0x04). ``not_after``:
    unix seconds. ``code``: the typed alias, case-preserved."""

    bootloader_id: str
    user_id: str
    phone_pubkey: str
    code: str
    not_after: int

    def __post_init__(self) -> None:
        for name in ("bootloader_id", "user_id", "code"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise PairRefused(RECORD_FIELD_EMPTY, name)
        if not isinstance(self.phone_pubkey, str) or not _PUBKEY_HEX.match(self.phone_pubkey):
            raise PairRefused(
                RECORD_PUBKEY_MALFORMED,
                "expected 128 lowercase hex chars (X||Y, no 0x04 prefix)",
            )
        if isinstance(self.not_after, bool) or not isinstance(self.not_after, int) or self.not_after <= 0:
            raise PairRefused(RECORD_NOT_AFTER_MALFORMED, "expected positive unix seconds")

    def to_dict(self) -> dict[str, Any]:
        return {
            "bootloader_id": self.bootloader_id,
            "code": self.code,
            "not_after": self.not_after,
            "phone_pubkey": self.phone_pubkey,
            "user_id": self.user_id,
        }

    def canonical_bytes(self) -> bytes:
        """Sorted keys, no whitespace, UTF-8 — the package's canonical form."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def fingerprint(self) -> str:
        """SHA-256 hex of ``canonical_bytes()`` — signed as ``cap.scope.payload_sha256``."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PairRecord":
        """Build from a wire dict. Only the pubkey is normalised (case,
        0x/04 prefix); anything else mismatching is a refusal."""
        pubkey = d.get("phone_pubkey")
        if isinstance(pubkey, str):
            pubkey = pubkey.strip().lower()
            if pubkey.startswith("0x"):
                pubkey = pubkey[2:]
            if len(pubkey) == 130 and pubkey.startswith("04"):
                pubkey = pubkey[2:]
        not_after = d.get("not_after")
        if isinstance(not_after, str) and not_after.isdigit():
            not_after = int(not_after)
        return cls(
            bootloader_id=d.get("bootloader_id"),  # type: ignore[arg-type]
            user_id=d.get("user_id"),  # type: ignore[arg-type]
            phone_pubkey=pubkey,  # type: ignore[arg-type]
            code=d.get("code"),  # type: ignore[arg-type]
            not_after=not_after,  # type: ignore[arg-type]
        )


def verify_pair_grant(
    claims: CapabilityClaims,
    record: PairRecord,
    *,
    signer_pubkey_hex: str,
    bootloader_id: str,
    now: int,
    action: str = PAIR_ACTION,
) -> str:
    """Admit ``claims`` as a grant for exactly ``record`` or raise
    ``PairRefused``. Returns the fingerprint.

    ``claims`` must already have passed ``verify_jws``; ``signer_pubkey_hex``
    is the recovered key. Checks: action, audience, signer == record phone,
    record not expired, window <= ceiling, ``payload_sha256`` == fingerprint,
    and ``pairing_code`` (if present) == record code.
    """
    if action not in claims.cap.allow_actions:
        raise PairRefused(GRANT_ACTION_NOT_PAIR, f"allow_actions={claims.cap.allow_actions!r}")

    if bootloader_id not in claims.aud:
        raise PairRefused(GRANT_AUDIENCE_NOT_BOOTLOADER, f"aud={claims.aud!r}")

    signer = signer_pubkey_hex.strip().lower()
    if signer.startswith("0x"):
        signer = signer[2:]
    if len(signer) == 130 and signer.startswith("04"):
        signer = signer[2:]
    if signer != record.phone_pubkey:
        raise PairRefused(GRANT_SIGNER_NOT_RECORD_PHONE)

    if now >= record.not_after:
        raise PairRefused(RECORD_EXPIRED, f"not_after={record.not_after} now={now}")

    if claims.exp - claims.nbf > PAIR_WINDOW_CEILING_SECONDS:
        raise PairRefused(
            GRANT_WINDOW_EXCEEDS_CEILING,
            f"exp-nbf={claims.exp - claims.nbf} > {PAIR_WINDOW_CEILING_SECONDS}",
        )

    expected = record.fingerprint()
    pinned = claims.cap.scope.payload_sha256
    if not pinned:
        raise PairRefused(GRANT_SCOPE_MISSING_FINGERPRINT)
    if pinned.strip().lower() != expected:
        raise PairRefused(GRANT_SCOPE_FINGERPRINT_MISMATCH)

    alias = claims.cap.scope.pairing_code
    if alias is not None and alias != record.code:
        raise PairRefused(GRANT_CODE_MISMATCH)

    return expected
