"""
User-vault grant requests: the card a platform raises on its user's BOUND phone to ask for a grant, or to ask that one
be revoked (hard rule 15.z).

The request is the platform's PROPOSAL. The phone renders it, the person decides, and the phone signs the grant or the
revoke itself and submits it to ``/v0.4/user-vault/grant`` or ``/revoke``. The request only rings the phone.

IN MEMORY ONLY. A request - and above all its purpose text and the agent's display name, which are the platform's
words about its own user - is never written to the state store, a sidecar or a log. A restart loses every open request
and the platform raises it again. Each text is capped and refused when it carries a control or format character. A
request lives ``REQUEST_WINDOW_SECONDS`` and resolves as admitted, denied or expired. A resolved request is answered
for one more window so the platform can read the outcome, and then it is gone.

Fences: a request rings only the phone the (consumer, subject) is bound to (the server finds it); one open request per
(consumer, subject, agent handle, key); at most ``RAISES_PER_HOUR`` raises per subject.
"""
from __future__ import annotations

import secrets
import threading
import time
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Callable

from recto.user_vault.grant_record import GrantRefused

REQUEST_WINDOW_SECONDS = 300
RAISES_PER_HOUR = 10
PURPOSE_MAX = 280
AGENT_NAME_MAX = 64

ACTION_GRANT = "grant"
ACTION_REVOKE = "revoke"

# Refusal names (stable).
REQUEST_INVALID = "grant_request_invalid"
REQUEST_OPEN = "grant_request_open"
RATE_LIMITED = "grant_request_rate_limited"


def clean_text(value: Any, name: str, cap: int) -> str | None:
    """The platform's words, checked: absent or empty is None; over ``cap`` characters, or carrying a control or format
    character (a bidi override can make a card read one way and mean another), is refused."""
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise GrantRefused(REQUEST_INVALID, f"{name} must be a string")
    if len(value) > cap:
        raise GrantRefused(REQUEST_INVALID, f"{name} is at most {cap} characters")
    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in value):
        raise GrantRefused(REQUEST_INVALID, f"{name} may not carry control or format characters")
    return value.strip() or None


@dataclass
class GrantRequest:
    request_id: str
    action: str
    phone_id: str
    agent_id: str
    consumer: str
    subject: str
    agent_handle: str
    key: str
    scope: str
    not_after: int
    requested_at: int
    expires_at: int
    purpose: str | None = None
    agent_name: str | None = None
    grant_id: str | None = None          # a revoke request: the grant it names
    admitted_at: int | None = None       # a revoke request: when that grant was admitted
    status: str = "open"                 # open | admitted | denied | revoked | expired
    resolved_grant_id: str | None = None
    resolved_not_after: int | None = None

    def slot(self) -> tuple[str, str, str, str]:
        return (self.consumer, self.subject, self.agent_handle, self.key)


class GrantRequestBook:
    """The open requests, in this process's memory and nowhere else."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._by_id: dict[str, GrantRequest] = {}
        self._raises: dict[tuple[str, str], deque[int]] = defaultdict(deque)

    def _now(self) -> int:
        return int(self._clock())

    def _sweep(self, now: int) -> None:
        for rid, r in list(self._by_id.items()):
            if r.status == "open" and now >= r.expires_at:
                r.status = "expired"
            if r.status != "open" and now >= r.expires_at + REQUEST_WINDOW_SECONDS:
                del self._by_id[rid]

    def raise_request(self, *, action: str, phone_id: str, agent_id: str, consumer: str, subject: str,
                      agent_handle: str, key: str, scope: str, not_after: int, purpose: str | None,
                      agent_name: str | None, grant_id: str | None = None,
                      admitted_at: int | None = None) -> GrantRequest:
        now = self._now()
        with self._lock:
            self._sweep(now)
            times = self._raises[(consumer, subject)]
            while times and times[0] <= now - 3600:
                times.popleft()
            if len(times) >= RAISES_PER_HOUR:
                raise GrantRefused(RATE_LIMITED, f"at most {RAISES_PER_HOUR} requests an hour for one subject")
            for r in self._by_id.values():
                if r.status == "open" and r.slot() == (consumer, subject, agent_handle, key):
                    raise GrantRefused(REQUEST_OPEN, "a request for this agent and key is already on the phone")
            times.append(now)
            req = GrantRequest(
                request_id="uvreq-" + secrets.token_hex(16), action=action, phone_id=phone_id, agent_id=agent_id,
                consumer=consumer, subject=subject, agent_handle=agent_handle, key=key, scope=scope,
                not_after=not_after, requested_at=now, expires_at=now + REQUEST_WINDOW_SECONDS,
                purpose=purpose, agent_name=agent_name, grant_id=grant_id, admitted_at=admitted_at,
            )
            self._by_id[req.request_id] = req
            return req

    def open_for_phone(self, phone_id: str) -> list[GrantRequest]:
        now = self._now()
        with self._lock:
            self._sweep(now)
            return sorted((r for r in self._by_id.values() if r.status == "open" and r.phone_id == phone_id),
                          key=lambda r: r.requested_at)

    def get(self, request_id: str) -> GrantRequest | None:
        with self._lock:
            self._sweep(self._now())
            return self._by_id.get(request_id)

    def resolve_grant(self, consumer: str, subject: str, agent_handle: str, key: str, grant_id: str,
                      not_after: int) -> None:
        """A grant for the slot was admitted: an open grant request for it resolves, the text dropped."""
        with self._lock:
            for r in self._by_id.values():
                if r.status == "open" and r.action == ACTION_GRANT and r.slot() == (consumer, subject, agent_handle,
                                                                                     key):
                    r.status, r.resolved_grant_id, r.resolved_not_after = "admitted", grant_id, not_after
                    r.purpose = r.agent_name = None

    def resolve_revoke(self, grant_ids: set[str]) -> None:
        """Grants were revoked: an open revoke request naming one resolves, the text dropped."""
        with self._lock:
            for r in self._by_id.values():
                if r.status == "open" and r.action == ACTION_REVOKE and r.grant_id in grant_ids:
                    r.status = "revoked"
                    r.purpose = r.agent_name = None

    def deny(self, request_id: str) -> bool:
        with self._lock:
            self._sweep(self._now())
            r = self._by_id.get(request_id)
            if r is None or r.status != "open":
                return False
            r.status = "denied"
            r.purpose = r.agent_name = None
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)


__all__ = [
    "ACTION_GRANT", "ACTION_REVOKE", "AGENT_NAME_MAX", "PURPOSE_MAX", "RAISES_PER_HOUR", "REQUEST_WINDOW_SECONDS",
    "GrantRequest", "GrantRequestBook", "clean_text",
]
