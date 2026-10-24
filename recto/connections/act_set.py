"""
The store side of a phone-signed vault SET.

The operator types (or pastes) the value at the desk. The record the phone
signs carries only ``value_sha256``, the SHA-256 hex of the value's UTF-8
bytes, and the card shows its first 12 hex (``recto.connections.act_record``).
The value travels beside the grant to the act route, and is stored only here,
only when SHA-256 over its exact UTF-8 bytes equals the signed digest
(compared in constant time). It is written through ``set_connection``, the
same store call the operator-token upsert makes, so a set stores exactly what
that route stores: the value in the vault, ``has_secret`` and
``rotated_at_unix`` on the row, and nothing else changed.

A set writes the value and nothing else. On an existing row the display name,
category, config, health URL and enabled flag are kept; a new row takes the
store's defaults (display name = the key, category ``uncategorized``,
enabled). Every field a set acts on is in its signed record and on its card.

A refusal is an ``ActRefused`` with a stable name. Its detail, its message and
its exception chain never carry the value, a piece of it, or its digest.

Pure stdlib apart from the store it writes to.
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

from recto.connections.act_record import SET_VERB, ActRecord, ActRefused
from recto.connections.manage import SecretSourceFactory, set_connection
from recto.connections.types import ConnectionMeta
from recto.secrets.base import SecretSourceError

# A connection's value is one credential: an API key or token (tens to
# hundreds of bytes), a signed URL (hundreds), at the outside a PEM private key
# or a service-account JSON document (2-4 KB). 16 KiB holds the largest of
# those four times over and bounds what one act can make the store encrypt and
# write. Counted in UTF-8 bytes, the form that is hashed and stored.
VALUE_MAX_BYTES = 16 * 1024

# Refusal names.
VALUE_NOT_ADMITTED = "value_not_admitted"
VALUE_MISSING = "value_missing"
VALUE_NOT_STRING = "value_not_string"
VALUE_EMPTY = "value_empty"
VALUE_TOO_LARGE = "value_too_large"
VALUE_NOT_STORABLE = "value_not_storable"
VALUE_FINGERPRINT_MISMATCH = "value_fingerprint_mismatch"
VALUE_STORE_FAILED = "value_store_failed"


def value_sha256(value: str) -> str:
    """SHA-256 hex (lowercase) of ``value``'s UTF-8 bytes: the digest a set's
    record signs. Raises UnicodeEncodeError for a string with no UTF-8 form;
    ``check_act_value`` refuses such a value by name instead."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utf8(value: str) -> bytes | None:
    # The encoder's error holds the whole string; let none of it escape, not
    # even as an exception's context.
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        return None


def check_act_value(record: ActRecord, value: Any) -> str | None:
    """The value a verified ``record`` may act with, or ``ActRefused``.

    Any verb but set: no value (``None``, i.e. absent) is the only answer, and
    the return is None. A set: a non-empty string of at most VALUE_MAX_BYTES
    UTF-8 bytes whose SHA-256 is ``record.value_sha256``; the return is the
    value, unchanged.
    """
    if record.verb != SET_VERB:
        if value is not None:
            raise ActRefused(VALUE_NOT_ADMITTED, f"a {record.verb} carries no value")
        return None
    if value is None:
        raise ActRefused(VALUE_MISSING, "a set carries its value beside the grant")
    if not isinstance(value, str):
        raise ActRefused(VALUE_NOT_STRING, f"expected a string, got {type(value).__name__}")
    if not value:
        raise ActRefused(VALUE_EMPTY, "an empty value is never stored; a delete removes one")
    if len(value) > VALUE_MAX_BYTES:
        raise ActRefused(VALUE_TOO_LARGE, f"the store takes at most {VALUE_MAX_BYTES} bytes")
    raw = _utf8(value)
    if raw is None:
        raise ActRefused(VALUE_NOT_STORABLE, "the value has no UTF-8 form")
    if len(raw) > VALUE_MAX_BYTES:
        raise ActRefused(VALUE_TOO_LARGE, f"the store takes at most {VALUE_MAX_BYTES} bytes")
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), record.value_sha256 or ""):
        raise ActRefused(VALUE_FINGERPRINT_MISMATCH, "sha256(value) is not the record's value_sha256")
    return value


def apply_set(
    connections_path: str | Path,
    record: ActRecord,
    value: Any,
    *,
    secret_source_factory: SecretSourceFactory | None = None,
) -> ConnectionMeta:
    """Store a set's value: ``check_act_value``, then ``set_connection`` with
    the value and no other field. ``record`` has passed ``verify_act_grant``
    (and its grant is spent). Returns the row's secret-free metadata.

    ``secret_source_factory``: None takes the store's own default backend.
    """
    checked = check_act_value(record, value)
    if checked is None:
        raise ActRefused(VALUE_NOT_ADMITTED, f"only a set stores a value; this record is a {record.verb}")
    kwargs: dict[str, Any] = {}
    if secret_source_factory is not None:
        kwargs["secret_source_factory"] = secret_source_factory
    failed: str | None = None
    try:
        return set_connection(Path(connections_path), service=record.service, key=record.key, secret=checked, **kwargs)
    except SecretSourceError as exc:
        failed = type(exc).__name__
    raise ActRefused(VALUE_STORE_FAILED, f"the store refused the write ({failed})")


__all__ = [
    "VALUE_MAX_BYTES",
    "apply_set",
    "check_act_value",
    "value_sha256",
]
