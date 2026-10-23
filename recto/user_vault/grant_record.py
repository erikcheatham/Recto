"""
User-vault grant and revoke records: the canonical tuples a user's BOUND phone signs to let one agent use one of the
user's keys until a date, and to take that back.

A GRANT is standing until its ``not_after`` or its revocation - never single use. It names, all as opaque handles or
slot names (the placeholder rule: Recto never holds a platform's user data):
  ``bootloader_id`` - this bootloader;  ``consumer`` - the platform, as it is bound;  ``subject`` - the platform's
  opaque handle for the user;  ``agent_handle`` - the platform's opaque handle for the agent (one agent: no wildcard);
  ``key`` - the user-vault slot (e.g. ``user-ai-xai``);  ``scope`` - the platform's word for what the use is for, shown
  on the card;  ``not_after`` - unix seconds;  ``nonce`` - makes two grants for the same tuple two grants.
The grant's id is its fingerprint: SHA-256 hex of the canonical bytes (sorted keys, no whitespace, UTF-8).

A REVOKE names ``bootloader_id``, ``consumer``, ``subject``, the ``grant_id`` it takes back and a ``nonce``.

A REVOKE-KEY ("stop all") names ``bootloader_id``, ``consumer``, ``subject``, the ``key`` whose every live grant ends,
a short ``not_after`` (the act's own window, at most ``ACT_WINDOW_SECONDS`` ahead) and a ``nonce``; the server marks it
used, so one signature ends the grants live when it arrives and never a later one.

A GRANTS LIST request names ``bootloader_id``, the ``phone_id`` asking, ``issued_at`` and a ``nonce``: the bound
phone reads its subjects' live grants from the bootloader by its own signature, so a revoke never needs the platform
(hard rule 15.aa).

Both are signed by the identity key of the phone the (consumer, subject) is bound to (hard rule 15.n), over a
domain-tagged message - ``recto-user-vault-grant-v1|`` or ``recto-user-vault-revoke-v1|`` followed by the canonical
bytes - so neither signature can pass for the other or for any other act. The server finds the bound phone; this
module checks shape, window and signature and refuses by name (hard rules 15.s-15.v).

Pure stdlib apart from the signature check the caller passes in.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from recto.subject_handle import normalize_subject
from recto.user_vault.types import normalize_user_vault_key

GRANT_PREFIX = "recto-user-vault-grant-v1|"
REVOKE_PREFIX = "recto-user-vault-revoke-v1|"
REVOKE_KEY_PREFIX = "recto-user-vault-revoke-key-v1|"
GRANTS_LIST_PREFIX = "recto-user-vault-grants-v1|"

# A stop-all signature lives this long at most; a grants-list request is fresh within this skew.
ACT_WINDOW_SECONDS = 600
LIST_SKEW_SECONDS = 120

# The window a phone card offers by default, and the longest the bootloader admits.
GRANT_DEFAULT_SECONDS = 90 * 86400
GRANT_MAX_SECONDS = 365 * 86400

GRANT_RECORD_FIELDS = ("agent_handle", "bootloader_id", "consumer", "key", "nonce", "not_after", "scope", "subject")
REVOKE_RECORD_FIELDS = ("bootloader_id", "consumer", "grant_id", "nonce", "subject")
REVOKE_KEY_RECORD_FIELDS = ("bootloader_id", "consumer", "key", "nonce", "not_after", "subject")
GRANTS_LIST_FIELDS = ("bootloader_id", "issued_at", "nonce", "phone_id")

_SCOPE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_GRANT_ID_RE = re.compile(r"^[0-9a-f]{64}$")

# Refusal names (stable).
RECORD_INVALID = "grant_record_invalid"
RECORD_FIELDS_UNEXPECTED = "grant_record_fields_unexpected"
AGENT_HANDLE_INVALID = "grant_agent_handle_invalid"
BOOTLOADER_MISMATCH = "grant_bootloader_mismatch"
EXPIRED = "grant_expired"
TOO_LONG = "grant_too_long"
SIGNATURE_INVALID = "grant_signature_invalid"
ACT_WINDOW_INVALID = "grant_act_window_invalid"
LIST_STALE = "grant_list_stale"


class GrantRefused(ValueError):
    """A named refusal. ``name`` is stable; ``detail`` may change and never carries a stored value."""

    def __init__(self, name: str, detail: str = "") -> None:
        super().__init__(f"{name}: {detail}" if detail else name)
        self.name = name
        self.detail = detail


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise GrantRefused(RECORD_INVALID, f"{name} must be a non-empty string without surrounding space")
    return value


def _canonical(d: dict[str, Any]) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _from_wire(d: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(d, dict):
        raise GrantRefused(RECORD_INVALID, "the record must be an object")
    extra = sorted(set(d) - set(fields))
    if extra:
        raise GrantRefused(RECORD_FIELDS_UNEXPECTED, f"fields {extra!r}")
    missing = sorted(set(fields) - set(d))
    if missing:
        raise GrantRefused(RECORD_INVALID, f"missing {missing!r}")
    return d


@dataclass(frozen=True)
class GrantRecord:
    bootloader_id: str
    consumer: str
    subject: str
    agent_handle: str
    key: str
    scope: str
    not_after: int
    nonce: str

    def __post_init__(self) -> None:
        for name in ("bootloader_id", "consumer", "subject", "agent_handle", "key", "scope", "nonce"):
            _text(getattr(self, name), name)
        try:
            if normalize_subject(self.subject) != self.subject:
                raise ValueError
        except ValueError:
            raise GrantRefused(RECORD_INVALID, "subject must be an opaque handle of 43 base64url characters") from None
        # One agent, as its opaque handle: a wildcard, an empty or a raw id is refused (hard rule 15.v).
        try:
            if normalize_subject(self.agent_handle) != self.agent_handle:
                raise ValueError
        except ValueError:
            raise GrantRefused(AGENT_HANDLE_INVALID, "agent_handle must name ONE agent as a 43-character handle") from None
        try:
            if normalize_user_vault_key(self.key) != self.key:
                raise ValueError
        except ValueError:
            raise GrantRefused(RECORD_INVALID, "key must be a user-vault slot name exactly as stored") from None
        if not _SCOPE_RE.match(self.scope):
            raise GrantRefused(RECORD_INVALID, "scope must be 1-64 of [A-Za-z0-9_.:-]")
        if not _NONCE_RE.match(self.nonce):
            raise GrantRefused(RECORD_INVALID, "nonce must be 16-64 base64url characters")
        if isinstance(self.not_after, bool) or not isinstance(self.not_after, int) or self.not_after <= 0:
            raise GrantRefused(RECORD_INVALID, "not_after must be positive unix seconds")

    def to_dict(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in GRANT_RECORD_FIELDS}

    def canonical_bytes(self) -> bytes:
        return _canonical(self.to_dict())

    def grant_id(self) -> str:
        """SHA-256 hex of the canonical bytes - the grant's id and its revocation name."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def signed_message(self) -> bytes:
        return GRANT_PREFIX.encode("ascii") + self.canonical_bytes()

    @classmethod
    def from_dict(cls, d: Any) -> "GrantRecord":
        d = _from_wire(d, GRANT_RECORD_FIELDS)
        return cls(**{f: d[f] for f in GRANT_RECORD_FIELDS})


@dataclass(frozen=True)
class RevokeRecord:
    bootloader_id: str
    consumer: str
    subject: str
    grant_id: str
    nonce: str

    def __post_init__(self) -> None:
        for name in ("bootloader_id", "consumer", "subject", "grant_id", "nonce"):
            _text(getattr(self, name), name)
        try:
            if normalize_subject(self.subject) != self.subject:
                raise ValueError
        except ValueError:
            raise GrantRefused(RECORD_INVALID, "subject must be an opaque handle of 43 base64url characters") from None
        if not _GRANT_ID_RE.match(self.grant_id):
            raise GrantRefused(RECORD_INVALID, "grant_id must be 64 lowercase hex characters")
        if not _NONCE_RE.match(self.nonce):
            raise GrantRefused(RECORD_INVALID, "nonce must be 16-64 base64url characters")

    def to_dict(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in REVOKE_RECORD_FIELDS}

    def canonical_bytes(self) -> bytes:
        return _canonical(self.to_dict())

    def signed_message(self) -> bytes:
        return REVOKE_PREFIX.encode("ascii") + self.canonical_bytes()

    @classmethod
    def from_dict(cls, d: Any) -> "RevokeRecord":
        d = _from_wire(d, REVOKE_RECORD_FIELDS)
        return cls(**{f: d[f] for f in REVOKE_RECORD_FIELDS})


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GrantRefused(RECORD_INVALID, f"{name} must be positive unix seconds")
    return value


@dataclass(frozen=True)
class RevokeKeyRecord:
    """"Stop all" for one key: every live grant of (consumer, subject, key) ends in one signature."""

    bootloader_id: str
    consumer: str
    subject: str
    key: str
    not_after: int
    nonce: str

    def __post_init__(self) -> None:
        for name in ("bootloader_id", "consumer", "subject", "key", "nonce"):
            _text(getattr(self, name), name)
        try:
            if normalize_subject(self.subject) != self.subject:
                raise ValueError
        except ValueError:
            raise GrantRefused(RECORD_INVALID, "subject must be an opaque handle of 43 base64url characters") from None
        try:
            if normalize_user_vault_key(self.key) != self.key:
                raise ValueError
        except ValueError:
            raise GrantRefused(RECORD_INVALID, "key must be a user-vault slot name exactly as stored") from None
        if not _NONCE_RE.match(self.nonce):
            raise GrantRefused(RECORD_INVALID, "nonce must be 16-64 base64url characters")
        _positive_int(self.not_after, "not_after")

    def to_dict(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in REVOKE_KEY_RECORD_FIELDS}

    def canonical_bytes(self) -> bytes:
        return _canonical(self.to_dict())

    def act_id(self) -> str:
        """SHA-256 hex of the canonical bytes - the name the server marks used."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def signed_message(self) -> bytes:
        return REVOKE_KEY_PREFIX.encode("ascii") + self.canonical_bytes()

    @classmethod
    def from_dict(cls, d: Any) -> "RevokeKeyRecord":
        d = _from_wire(d, REVOKE_KEY_RECORD_FIELDS)
        return cls(**{f: d[f] for f in REVOKE_KEY_RECORD_FIELDS})


@dataclass(frozen=True)
class GrantsListRequest:
    """The bound phone asks for its subjects' live grants, by its own signature."""

    bootloader_id: str
    phone_id: str
    issued_at: int
    nonce: str

    def __post_init__(self) -> None:
        for name in ("bootloader_id", "phone_id", "nonce"):
            _text(getattr(self, name), name)
        if not _NONCE_RE.match(self.nonce):
            raise GrantRefused(RECORD_INVALID, "nonce must be 16-64 base64url characters")
        _positive_int(self.issued_at, "issued_at")

    def to_dict(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in GRANTS_LIST_FIELDS}

    def signed_message(self) -> bytes:
        return GRANTS_LIST_PREFIX.encode("ascii") + _canonical(self.to_dict())

    @classmethod
    def from_dict(cls, d: Any) -> "GrantsListRequest":
        d = _from_wire(d, GRANTS_LIST_FIELDS)
        return cls(**{f: d[f] for f in GRANTS_LIST_FIELDS})


# A signature check: (message, signature_b64u) -> bool, bound by the caller to the bound phone's key and algorithm.
Verifier = Callable[[bytes, str], bool]


def verify_grant(record: GrantRecord, signature_b64u: Any, *, bootloader_id: str, now: int, verify: Verifier) -> str:
    """Admit ``record`` signed by the bound phone or raise ``GrantRefused``. Returns the grant id.

    The window is checked against the clock here: a grant already past its ``not_after`` (hard rule 15.t), or reaching
    further than ``GRANT_MAX_SECONDS`` from now, is refused at admission. The signature is checked last, against the
    key the CALLER bound into ``verify`` - the subject's bound phone and no other (hard rule 15.s)."""
    if record.bootloader_id != bootloader_id:
        raise GrantRefused(BOOTLOADER_MISMATCH, "the record names another bootloader")
    if record.not_after <= now:
        raise GrantRefused(EXPIRED, "not_after is already past")
    if record.not_after > now + GRANT_MAX_SECONDS:
        raise GrantRefused(TOO_LONG, f"a grant reaches at most {GRANT_MAX_SECONDS // 86400} days")
    if not isinstance(signature_b64u, str) or not signature_b64u or not verify(record.signed_message(), signature_b64u):
        raise GrantRefused(SIGNATURE_INVALID, "the signature does not verify against the subject's bound phone")
    return record.grant_id()


def verify_revoke(record: RevokeRecord, signature_b64u: Any, *, bootloader_id: str, verify: Verifier) -> str:
    """Admit ``record`` signed by the bound phone or raise ``GrantRefused``. Returns the grant id it revokes."""
    if record.bootloader_id != bootloader_id:
        raise GrantRefused(BOOTLOADER_MISMATCH, "the record names another bootloader")
    if not isinstance(signature_b64u, str) or not signature_b64u or not verify(record.signed_message(), signature_b64u):
        raise GrantRefused(SIGNATURE_INVALID, "the signature does not verify against the subject's bound phone")
    return record.grant_id


def verify_revoke_key(record: RevokeKeyRecord, signature_b64u: Any, *, bootloader_id: str, now: int,
                      verify: Verifier) -> str:
    """Admit a "stop all" signed by the bound phone or raise ``GrantRefused``. Returns its act id. The act's own window
    is short (``ACT_WINDOW_SECONDS``): with the server marking the id used, a captured signature ends nothing later."""
    if record.bootloader_id != bootloader_id:
        raise GrantRefused(BOOTLOADER_MISMATCH, "the record names another bootloader")
    if record.not_after <= now or record.not_after > now + ACT_WINDOW_SECONDS:
        raise GrantRefused(ACT_WINDOW_INVALID, f"a stop-all lives at most {ACT_WINDOW_SECONDS} seconds and not past")
    if not isinstance(signature_b64u, str) or not signature_b64u or not verify(record.signed_message(), signature_b64u):
        raise GrantRefused(SIGNATURE_INVALID, "the signature does not verify against the subject's bound phone")
    return record.act_id()


def verify_grants_list(request: GrantsListRequest, signature_b64u: Any, *, bootloader_id: str, now: int,
                       verify: Verifier) -> None:
    """Admit a grants-list read signed by the asking phone or raise ``GrantRefused``."""
    if request.bootloader_id != bootloader_id:
        raise GrantRefused(BOOTLOADER_MISMATCH, "the request names another bootloader")
    if abs(now - request.issued_at) > LIST_SKEW_SECONDS:
        raise GrantRefused(LIST_STALE, f"issued_at must be within {LIST_SKEW_SECONDS} seconds of the bootloader's clock")
    if not isinstance(signature_b64u, str) or not signature_b64u or not verify(request.signed_message(), signature_b64u):
        raise GrantRefused(SIGNATURE_INVALID, "the signature does not verify against the asking phone")


__all__ = [
    "ACT_WINDOW_SECONDS", "GRANT_DEFAULT_SECONDS", "GRANT_MAX_SECONDS", "GRANT_PREFIX", "GRANTS_LIST_PREFIX",
    "LIST_SKEW_SECONDS", "REVOKE_KEY_PREFIX", "REVOKE_PREFIX",
    "GrantRecord", "GrantRefused", "GrantsListRequest", "RevokeKeyRecord", "RevokeRecord",
    "verify_grant", "verify_grants_list", "verify_revoke", "verify_revoke_key",
]
