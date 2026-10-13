"""THE OWNER SLOTS (hard rule 14.4, amended) - the parts of the owner-slot rules that are not request handling.

- The approval card's binding: what an owner phone's approval of a new owner key is a signature over.
- The wrong-code limiter: a pairing code is six digits, so failed redemptions over the public edge are counted per
  public client, and a code that sat through too many of them is never redeemed over the edge.
- The store lock: a serving process holds an exclusive lock on its file-backend state dir, so the host CLI never
  edits a registry a live server will overwrite from memory.
"""

from __future__ import annotations

import errno
import hashlib
import heapq
import ipaddress
import json
import logging
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import IO, Any

OWNER_ENROLL_PREFIX = "recto-owner-enroll-v1"
# How long an approval card waits on the approver's queue.
OWNER_CARD_TTL_SECONDS = 300
# How long an approval, once given, waits for the new phone's second pass.
OWNER_APPROVAL_TTL_SECONDS = 900
# Two different keys asking for one owner slot inside this window refuse each other.
OWNER_CONTEST_WINDOW_SECONDS = 900

# Wrong pairing codes. A request that came through the public edge carries the client's address in the edge's
# client-address header (CF-Connecting-IP when fronted by Cloudflare; the edge sets it and a caller cannot remove it).
# A request without it came over a private route or loopback and is never counted or locked; any other ingress must
# sit behind a proxy that sets the header. A header that is empty, blank or repeated is counted in one shared bucket. Each public client gets
# WRONG_CODE_LIMIT failures per window: an IPv4 address, or an IPv6 /64 (one subscriber holds a whole /64; an
# IPv4-mapped or NAT64 address counts as its IPv4 address). The bootloader never refuses every client - that would let
# any stranger stop all pairing - so the bound across clients is per CODE: a code that has sat through
# CODE_PUBLIC_EXPOSURE_BUDGET public wrong guesses since it was minted is burned on its next public redemption (the
# chance a guesser hits it stays under budget / 10^6), and a fresh code redeems. Past WRONG_CODE_PUBLIC_ALERT failures
# in a window the bootloader logs a warning, at most once a minute, with the window's count at that moment; requests
# refused by the per-client limit are reported the same way, never one line each.
PUBLIC_CLIENT_HEADER = "CF-Connecting-IP"
MALFORMED_CLIENT = "(malformed client header)"
WRONG_CODE_LIMIT = 5
WRONG_CODE_WINDOW_SECONDS = 900
WRONG_CODE_PUBLIC_ALERT = 100
WRONG_CODE_ALERT_INTERVAL_SECONDS = 60
CODE_PUBLIC_EXPOSURE_BUDGET = 1000
# The longest a pairing code lives (the mint endpoint's ceiling and the startup code's TTL).
CODE_MAX_TTL_SECONDS = 3600
# A code that redeemed recently answers "already used" and is not counted (a phone re-sends its spent code).
SPENT_CODE_MEMORY_SECONDS = 3600
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

STORE_LOCK_NAME = "bootloader.lock"


def grouped_ref(ref: str) -> str:
    """pk_0123456789abcdef -> pk_0123 4567 89ab cdef: the form both screens show, so a person can compare them."""
    if not ref.startswith("pk_"):
        return ref
    h = ref[len("pk_"):]
    return "pk_" + " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def owner_enroll_digest(
    *,
    bootloader_id: str,
    slot: str,
    incoming_pubkey: str,
    incoming_ref: str,
    approver_ref: str,
    occupant_ref: str | None,
    request_id: str,
    not_after: int,
) -> bytes:
    """The 32 bytes an approver signs: SHA-256 over a domain-separated canonical JSON of everything the approval
    binds. Built and checked only by the server, through its own card - never accepted as a free-standing blob."""
    body: dict[str, Any] = {
        "v": OWNER_ENROLL_PREFIX,
        "bootloader_id": bootloader_id,
        "slot": slot,
        "incoming_pubkey": incoming_pubkey,
        "incoming_ref": incoming_ref,
        "approver_ref": approver_ref,
        "occupant_ref": occupant_ref,
        "request_id": request_id,
        "not_after": int(not_after),
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()


class CodeAttemptLimiter:
    """Failed pairing-code redemptions over the public edge. ``lock`` is held by the caller across the check, the
    redemption and the count, so a burst cannot outrun the count and a refused attempt never spends a good code; every
    method also takes it itself (it is re-entrant), so a mint thread's stamp never races a redemption. A failure is
    amortized O(1): it enters one deque in arrival order and leaves it once, when it ages out of the window - nothing is
    evicted early, so a blocked client never gets fresh guesses back. A stamp is O(log n): stamps live as long as their
    own codes, so they leave a heap in the order they are due."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._events: deque[tuple[float, str]] = deque()      # (t, bucket): the window's public failures, oldest first
        self._counts: dict[str, int] = {}                     # bucket -> failures in the window
        self._total = 0                                        # every public failure since start, never trimmed
        self._marks: deque[tuple[float, int]] = deque()       # (t, _total then), at most one a minute, an hour back
        self._stamps: dict[str, tuple[int, float]] = {}        # code -> (_total at mint, forget after)
        self._stamp_order: list[tuple[float, str]] = []     # a heap of (forget at, code)
        self._spent: dict[str, float] = {}
        self._spent_order: deque[tuple[float, str]] = deque()
        self._alerted_at = float("-inf")
        self._refused = 0
        self._refused_alerted_at = float("-inf")

    def _trim(self, now: float) -> None:
        horizon = now - WRONG_CODE_WINDOW_SECONDS
        while self._events and self._events[0][0] <= horizon:
            _, bucket = self._events.popleft()
            left = self._counts[bucket] - 1
            if left:
                self._counts[bucket] = left
            else:
                del self._counts[bucket]
        # A mark is kept one mark interval past the hour, so the oldest mark sits at or before every live code's mint.
        while self._marks and self._marks[0][0] <= now - CODE_MAX_TTL_SECONDS - 60:
            self._marks.popleft()
        while self._stamp_order and self._stamp_order[0][0] <= now:
            t, code = heapq.heappop(self._stamp_order)
            if self._stamps.get(code, (0, None))[1] == t:
                del self._stamps[code]
        while self._spent_order and self._spent_order[0][0] <= now - SPENT_CODE_MEMORY_SECONDS:
            t, code = self._spent_order.popleft()
            if self._spent.get(code) == t:
                del self._spent[code]

    @staticmethod
    def bucket(client: str) -> str:
        """One bucket per IPv4 address and per IPv6 /64; an IPv4-mapped or NAT64 address is its IPv4 address, so one
        client's two spellings share one count. Anything that is not an address is its own lower-cased string."""
        value = client.strip()
        try:
            ip = ipaddress.ip_address(value)
            if ip.version == 6:
                if ip.ipv4_mapped is not None:
                    return str(ip.ipv4_mapped)
                if ip in _NAT64:
                    return str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
                return str(ipaddress.ip_network(f"{ip}/64", strict=False))
            return str(ip)
        except ValueError:
            return value.lower()

    def blocked(self, client: str | None) -> bool:
        if client is None:
            return False
        with self.lock:
            self._trim(time.time())
            return self._counts.get(self.bucket(client), 0) >= WRONG_CODE_LIMIT

    def record_refusal(self) -> None:
        """A request the per-client limit refused: counted for the log only - never a failure, so a blocked client can
        neither extend its own block nor drain any code's budget, and never one log line per request."""
        with self.lock:
            now = time.time()
            self._refused += 1
            if now - self._refused_alerted_at >= WRONG_CODE_ALERT_INTERVAL_SECONDS:
                logging.getLogger("recto.bootloader.codes").warning(
                    "%d requests refused by the wrong-code limit since the last report", self._refused)
                self._refused_alerted_at = now
                self._refused = 0

    def record_failure(self, client: str | None) -> None:
        if client is None:
            return
        with self.lock:
            now = time.time()
            self._trim(now)
            if not self._marks or now - self._marks[-1][0] >= 60:
                self._marks.append((now, self._total))
            self._total += 1
            bucket = self.bucket(client)
            self._events.append((now, bucket))
            self._counts[bucket] = self._counts.get(bucket, 0) + 1
            n = len(self._events)
            if n >= WRONG_CODE_PUBLIC_ALERT and now - self._alerted_at >= WRONG_CODE_ALERT_INTERVAL_SECONDS:
                self._alerted_at = now
                logging.getLogger("recto.bootloader.codes").warning(
                    "%d wrong pairing codes from %d public clients in the last %d s - someone may be guessing codes",
                    n, len(self._counts), WRONG_CODE_WINDOW_SECONDS)

    def stamp(self, code: str, expires_at: float | None = None) -> None:
        """At mint: the code's exposure counts the public failures from now on, for as long as the code lives."""
        with self.lock:
            now = time.time()
            self._trim(now)
            forget = max(float(expires_at) if expires_at is not None else now + CODE_MAX_TTL_SECONDS, now) + 60
            self._stamps[code] = (self._total, forget)
            heapq.heappush(self._stamp_order, (forget, code))

    def exposed(self, code: str) -> bool:
        """True when the code has sat through CODE_PUBLIC_EXPOSURE_BUDGET public failures. A code minted where this
        limiter did not see it (another instance) counts every public failure since the oldest mark - the last hour
        and a minute, kept to the minute - so a code of the mint endpoint's longest life is never counted looser
        than one stamped here."""
        with self.lock:
            self._trim(time.time())
            stamped = self._stamps.get(code)
            if stamped is not None:
                base = stamped[0]
            else:
                base = self._marks[0][1] if self._marks else self._total
            return self._total - base >= CODE_PUBLIC_EXPOSURE_BUDGET

    def record_spent(self, code: str) -> None:
        with self.lock:
            now = time.time()
            self._spent[code] = now
            self._spent_order.append((now, code))

    def was_spent(self, code: str) -> bool:
        with self.lock:
            self._trim(time.time())
            return code in self._spent


class StoreLockUnavailable(OSError):
    """The state dir cannot be locked at all (a filesystem without locks, a dir that cannot be made) - never read as
    "another process holds it"."""


def void_owner_enrolls_for(store: Any, phone_id: str) -> None:
    """A removed phone's approvals, and the requests that name it as the occupant, are refused in the same locked act
    that removes it - so neither comes back if the same key pairs again. The records are kept (the contest window reads
    them) and their cards are withdrawn. The caller holds the registry lock."""
    for rec in store.list_owner_enrolls():
        if rec.get("state") != "refused" and phone_id in (rec.get("approved_by"), rec.get("occupant_ref")):
            refused = dict(rec)
            refused["state"] = "refused"
            store.put_owner_enroll(refused)   # the refusal lands first: a card that fails to go never revives it
            for card_id in (rec.get("cards") or {}):
                try:
                    store.take_pending(card_id)
                except OSError as exc:   # the file store already dropped the card in memory
                    logging.getLogger("recto.bootloader.state").warning(
                        "pending.json not written after withdrawing an owner card (%s) - the next save rewrites it",
                        exc.strerror)


class StoreLock:
    """An exclusive, non-blocking OS lock on <state_dir>/bootloader.lock."""

    def __init__(self, handle: IO[bytes], path: Path) -> None:
        self._handle = handle
        self.path = path

    def release(self) -> None:
        if self._handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            self._handle.close()
            self._handle = None  # type: ignore[assignment]


def _os_lock(state_dir: Path) -> StoreLock | None:
    path = state_dir / STORE_LOCK_NAME
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        handle = open(path, "a+b")
    except OSError as exc:
        raise StoreLockUnavailable(exc.errno, f"cannot lock {path}: {exc.strerror}") from exc
    try:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK, errno.EDEADLK):
            return None   # held by another process (or another handle here)
        # A filesystem that cannot lock is not a held lock.
        raise StoreLockUnavailable(exc.errno, f"cannot lock {path}: {exc.strerror}") from exc
    return StoreLock(handle, path)


# The dirs this process serves: one OS lock each, shared by every server in the process (a test may run two on one
# dir; production runs one). The host CLI never shares it.
_SERVED: dict[str, list[Any]] = {}
_SERVED_GUARD = threading.Lock()


class ServerStoreLock:
    """A serving process's hold on its state dir, for the server's lifetime; the OS lock goes with the last holder."""

    def __init__(self, key: str) -> None:
        self._key: str | None = key

    def release(self) -> None:
        with _SERVED_GUARD:
            key, self._key = self._key, None
            if key is None or key not in _SERVED:
                return
            entry = _SERVED[key]
            entry[1] -= 1
            if entry[1] <= 0:
                del _SERVED[key]
                entry[0].release()


def acquire_server_store_lock(state_dir: Path) -> ServerStoreLock | None:
    """The server's hold: shared within this process, exclusive against every other process and the host CLI. None
    when another process holds the dir."""
    key = str(Path(state_dir).resolve()).lower() if os.name == "nt" else str(Path(state_dir).resolve())
    with _SERVED_GUARD:
        entry = _SERVED.get(key)
        if entry is None:
            lock = _os_lock(Path(state_dir))
            if lock is None:
                return None
            entry = _SERVED[key] = [lock, 0]
        entry[1] += 1
        return ServerStoreLock(key)


def acquire_store_lock(state_dir: Path) -> StoreLock | None:
    """The host CLI's exclusive lock, or None while any server - in this process or another - holds the dir."""
    key = str(Path(state_dir).resolve()).lower() if os.name == "nt" else str(Path(state_dir).resolve())
    with _SERVED_GUARD:
        if key in _SERVED:
            return None
    return _os_lock(Path(state_dir))
