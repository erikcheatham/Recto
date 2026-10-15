"""
Connection act record: the canonical tuple an operator signs on the phone to
enable, disable or delete one connection, and the verifier that admits a
grant only for that exact tuple.

The phone card shows the grant's actions, scope services, audience, validity
and purpose, and only a short prefix of ``cap.scope.payload_sha256``. So the
purpose of a connection act is not free text: it is this module's rendering of
the tuple, and a grant whose purpose differs is refused. Every field of the act
is then on the card and signed.

One grant = one action, one use, at most ACT_WINDOW_SECONDS. The grant window
is never re-stamped at card-open (no ``grant_ttl_seconds``): ``not_after`` is
the grant's ``exp`` and the purpose names it.

Pure stdlib.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from recto.capability.types import CapabilityClaims
from recto.connections.types import normalize_connection_key

# verb -> the one action a grant for it carries.
ACT_ACTIONS: dict[str, str] = {
    "enable": "connections:enable",
    "disable": "connections:disable",
    "delete": "connections:delete",
}
ACTION_PREFIX = "connections:"

# The signed window (iat..exp) may never exceed this.
ACT_WINDOW_SECONDS = 300
# The phone card shows the purpose cut at this many characters.
PURPOSE_MAX_CHARS = 240

# The signed fields, sorted.
ACT_RECORD_FIELDS = ("bootloader_id", "key", "not_after", "service", "verb")

# Scope fields a connection grant may carry; every other scope field must be empty.
_SCOPE_FIELDS_ADMITTED = ("services", "payload_sha256")

# Refusal names.
RECORD_FIELD_EMPTY = "record_field_empty"
RECORD_KEY_MALFORMED = "record_key_malformed"
RECORD_VERB_UNKNOWN = "record_verb_unknown"
RECORD_NOT_AFTER_MALFORMED = "record_not_after_malformed"
RECORD_FIELDS_UNEXPECTED = "record_fields_unexpected"
PURPOSE_TOO_LONG = "purpose_too_long"
ACTION_NOT_ADMITTED = "action_not_admitted"
GROUPS_NOT_ADMITTED = "groups_not_admitted"
NOT_SINGLE_USE = "not_single_use"
AUDIENCE_MISMATCH = "audience_mismatch"
WINDOW_EXCEEDS_CEILING = "window_exceeds_ceiling"
TUPLE_MISMATCH = "tuple_mismatch"
PAYLOAD_MISMATCH = "payload_mismatch"
PURPOSE_MISMATCH = "purpose_mismatch"
SCOPE_SERVICE_DENIED = "scope_service_denied"
SCOPE_NOT_ADMITTED = "scope_not_admitted"
PROFILE_NOT_ADMITTED = "profile_not_admitted"


class ActRefused(ValueError):
    """A named refusal. ``name`` is stable; ``detail`` may change and never
    carries a value from the store."""

    def __init__(self, name: str, detail: str = "") -> None:
        super().__init__(f"{name}: {detail}" if detail else name)
        self.name = name
        self.detail = detail


def _utc_minute(unix: int) -> str:
    return time.strftime("%Y-%m-%d %H:%MZ", time.gmtime(unix))


@dataclass(frozen=True)
class ActRecord:
    """``key``: a connection key exactly as stored (never normalised here: a
    key that would normalise differently is refused). ``not_after``: unix
    seconds, equal to the grant's ``exp``."""

    bootloader_id: str
    service: str
    key: str
    verb: str
    not_after: int

    def __post_init__(self) -> None:
        for name in ("bootloader_id", "service", "key", "verb"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise ActRefused(RECORD_FIELD_EMPTY, name)
        try:
            normalized = normalize_connection_key(self.key)
        except ValueError:
            raise ActRefused(RECORD_KEY_MALFORMED, "not a connection key") from None
        if normalized != self.key:
            raise ActRefused(RECORD_KEY_MALFORMED, "a key is named exactly as stored")
        if self.verb not in ACT_ACTIONS:
            raise ActRefused(RECORD_VERB_UNKNOWN, f"expected one of {sorted(ACT_ACTIONS)}")
        if isinstance(self.not_after, bool) or not isinstance(self.not_after, int) or self.not_after <= 0:
            raise ActRefused(RECORD_NOT_AFTER_MALFORMED, "expected positive unix seconds")
        if len(self.purpose()) > PURPOSE_MAX_CHARS:
            raise ActRefused(PURPOSE_TOO_LONG, f"the card shows {PURPOSE_MAX_CHARS} characters")

    @property
    def action(self) -> str:
        return ACT_ACTIONS[self.verb]

    def to_dict(self) -> dict[str, Any]:
        return {
            "bootloader_id": self.bootloader_id,
            "key": self.key,
            "not_after": self.not_after,
            "service": self.service,
            "verb": self.verb,
        }

    def canonical_bytes(self) -> bytes:
        """Sorted keys, no whitespace, UTF-8 — the package's canonical form."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def fingerprint(self) -> str:
        """SHA-256 hex of ``canonical_bytes()`` — signed as ``cap.scope.payload_sha256``."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def purpose(self) -> str:
        """The one purpose a grant for this act may carry: every field, in words."""
        return (f"Vault {self.verb.upper()}: {self.service}/{self.key} on {self.bootloader_id}"
                f" - until {_utc_minute(self.not_after)}")

    @classmethod
    def from_dict(cls, d: Any) -> "ActRecord":
        """Build from a wire dict. Nothing is normalised; an unknown field is a
        refusal (a field the phone does not sign is a field an attacker may
        choose)."""
        if not isinstance(d, dict):
            raise ActRefused(RECORD_FIELD_EMPTY, "the record must be an object")
        extra = sorted(set(d) - set(ACT_RECORD_FIELDS))
        if extra:
            raise ActRefused(RECORD_FIELDS_UNEXPECTED, f"fields {extra!r}")
        return cls(
            bootloader_id=d.get("bootloader_id"),  # type: ignore[arg-type]
            service=d.get("service"),  # type: ignore[arg-type]
            key=d.get("key"),  # type: ignore[arg-type]
            verb=d.get("verb"),  # type: ignore[arg-type]
            not_after=d.get("not_after"),  # type: ignore[arg-type]
        )


def names_connection_act(claims: CapabilityClaims) -> bool:
    """True when the claims name any connections:* action, on either side."""
    return any(a.startswith(ACTION_PREFIX) for a in (*claims.cap.allow_actions, *claims.cap.deny_actions))


def verify_act_grant(claims: CapabilityClaims, record: ActRecord, *, bootloader_id: str) -> str:
    """Admit ``claims`` as a grant for exactly ``record`` or raise
    ``ActRefused``. Returns the fingerprint.

    Runs twice: at the request, before the card is queued (the claims are the
    requester's), and at the act (the claims have passed ``verify_jws``
    against the operator's key and the jti is spent). Time bounds against the
    clock are the caller's (``verify_jws`` at the act; the request route's own
    check at the request).
    """
    cap = claims.cap
    if cap.groups:
        raise ActRefused(GROUPS_NOT_ADMITTED, "a connection grant names its one action, never a group")
    if len(cap.allow_actions) != 1 or cap.deny_actions or not cap.allow_actions[0].startswith(ACTION_PREFIX):
        raise ActRefused(ACTION_NOT_ADMITTED, f"allow_actions={cap.allow_actions!r} deny_actions={cap.deny_actions!r}")
    if cap.allow_actions[0] not in ACT_ACTIONS.values():
        raise ActRefused(ACTION_NOT_ADMITTED, f"{cap.allow_actions[0]!r} is not a connection act")
    if claims.max_uses != 1:
        raise ActRefused(NOT_SINGLE_USE, f"max_uses={claims.max_uses!r}")
    if claims.parent_profile is not None:
        raise ActRefused(PROFILE_NOT_ADMITTED, "a connection act is signed by the operator's own key")
    if claims.aud != [bootloader_id]:
        raise ActRefused(AUDIENCE_MISMATCH, "the grant names this bootloader, and only it")
    if claims.exp - claims.iat > ACT_WINDOW_SECONDS or claims.exp <= claims.iat:
        raise ActRefused(WINDOW_EXCEEDS_CEILING, f"exp-iat={claims.exp - claims.iat} > {ACT_WINDOW_SECONDS}")

    if cap.allow_actions[0] != record.action:
        raise ActRefused(TUPLE_MISMATCH, "the grant's action is not the record's verb")
    if record.bootloader_id != bootloader_id:
        raise ActRefused(TUPLE_MISMATCH, "the record names another bootloader")
    if record.not_after != claims.exp:
        raise ActRefused(TUPLE_MISMATCH, "the record's not_after is not the grant's exp")

    pinned = cap.scope.payload_sha256
    if not isinstance(pinned, str) or pinned.strip().lower() != record.fingerprint():
        raise ActRefused(PAYLOAD_MISMATCH, "cap.scope.payload_sha256 is not the record's fingerprint")
    if claims.purpose != record.purpose():
        raise ActRefused(PURPOSE_MISMATCH, "the purpose is not the record's rendering")
    if cap.scope.services != [record.service]:
        raise ActRefused(SCOPE_SERVICE_DENIED, "cap.scope.services names the record's service, and only it")
    for f in dataclasses.fields(cap.scope):
        if f.name in _SCOPE_FIELDS_ADMITTED:
            continue
        if getattr(cap.scope, f.name) not in (None, [], {}, ""):
            raise ActRefused(SCOPE_NOT_ADMITTED, f"cap.scope.{f.name} is set")
    return record.fingerprint()


__all__ = [
    "ACT_ACTIONS",
    "ACT_RECORD_FIELDS",
    "ACT_WINDOW_SECONDS",
    "PURPOSE_MAX_CHARS",
    "ActRecord",
    "ActRefused",
    "names_connection_act",
    "verify_act_grant",
]
