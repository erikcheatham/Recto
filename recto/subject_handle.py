"""Subject handles - the opaque name a consuming platform gives one of its users.

Recto stores and signs HANDLES, never a platform's user data. A consuming
platform mints one subject per (user, consumer) - in practice a keyed hash of
its own user id under a key only the platform holds - and sends that handle
wherever Recto needs to tell two users apart: the member pairing code, the
device-pairing record, the user vault. The platform keeps the mapping from
handle to meaning; nothing in this tree can reverse it, and nothing here
inspects it beyond its grammar.

THE GRAMMAR is exactly 43 base64url characters, unpadded - the encoding of 32
bytes (an HMAC-SHA256 output). The shape is checked; the content is never
interpreted. A value in any other shape - a GUID, an email, a short or padded
token - is refused, so a platform cannot hand Recto its raw user id by
accident (hard rule 15.m).

Handles are case-sensitive on the wire. Where a handle names something on a
filesystem that may fold case (the dpapi-machine blobs on a Windows host), use
`subject_storage_id`: the lowercase hex of the 32 decoded bytes, which is
case-safe and one-to-one with the handle.
"""
from __future__ import annotations

import base64
import re

SUBJECT_LENGTH = 43

_SUBJECT_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def normalize_subject(subject: object) -> str:
    """Validate a subject handle and return it unchanged (stripped).

    Raises ValueError on anything that is not exactly 43 base64url characters
    decoding to 32 bytes. Handles become JSON map keys and, through
    `subject_storage_id`, secret-name components, so this gate is a security
    boundary, not a formality."""
    if not isinstance(subject, str):
        raise ValueError(f"subject must be a string (got {type(subject).__name__})")
    s = subject.strip()
    if not _SUBJECT_RE.match(s):
        raise ValueError(
            f"subject must be an opaque handle of {SUBJECT_LENGTH} base64url characters "
            f"(got {len(s)} characters)"
        )
    try:
        raw = base64.urlsafe_b64decode(s + "=")
    except (ValueError, TypeError) as exc:  # pragma: no cover - the regex admits only decodable text
        raise ValueError("subject is not valid base64url") from exc
    if len(raw) != 32:  # pragma: no cover - 43 chars always decode to 32 bytes
        raise ValueError("subject must encode 32 bytes")
    # The last character carries 2 bits of padding; a non-canonical spelling
    # (those bits set) would be a second handle for the same 32 bytes.
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != s:
        raise ValueError("subject is not the canonical base64url spelling of 32 bytes")
    return s


def subject_storage_id(subject: str) -> str:
    """The case-safe storage form of a normalized subject: 64 lowercase hex
    characters (its 32 bytes). One-to-one with the handle, so two handles that
    differ only in case never share a file on a case-folding filesystem."""
    return base64.urlsafe_b64decode(normalize_subject(subject) + "=").hex()


__all__ = ["SUBJECT_LENGTH", "normalize_subject", "subject_storage_id"]
