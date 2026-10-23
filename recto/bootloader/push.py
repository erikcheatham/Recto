"""Silent-push wake senders -- the production replacement for tight polling.

Production-scale wave C (docs/production-scale-brief.md, layer 3): at
consumer scale the phone-side polling loop can't be the primary
notification path -- N paired phones polling ``GET /v0.4/pending`` every
few seconds is almost pure waste. This module gives the bootloader a
SEND side for the push tokens phones already supply at registration
(``push_token`` + ``push_platform`` on ``POST /v0.4/register``, rotated
via ``POST /v0.4/manage/push_token``): when a request is queued for a
phone, the bootloader fires a SILENT wake push; the phone wakes and
fetches its pending queue over the normal authenticated channel.

Two hard properties, non-negotiable:

1. **Push payloads carry NO request content.** Not the operation
   description, not the service name, not hashes -- only a bare
   "check your pending queue" marker. Push transports are third-party
   infrastructure (Apple / Google); Recto's threat model treats them as
   delivery hints, never as data channels. The phone always fetches the
   real request over the paired bootloader channel.
2. **Push is best-effort and never blocks or fails a request.** The
   dispatcher swallows + logs every send failure; polling remains the
   fallback path (foregrounded app, push outage, token rotation lag).

Config values (APNs .p8 signing key, FCM service-account JSON) are
SECRET MATERIAL -- resolve them through a SecretSource at config-build
time (Key Vault in production); never inline them in service.yaml.

Install with ``pip install recto[push]`` (httpx with HTTP/2 -- APNs is
HTTP/2-only; FCM rides the same client).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("recto.bootloader.push")

#: Platform discriminators -- byte-for-byte the values the phone app's
#: PushPlatform constants send on the wire.
PLATFORM_APNS = "apns"
PLATFORM_FCM = "fcm"


def _import_httpx() -> Any:
    try:
        import httpx
    except ImportError as exc:
        raise ImportError(
            "push senders require the optional push extra: "
            "pip install recto[push]"
        ) from exc
    return httpx


def _import_jwt() -> Any:
    try:
        import jwt
    except ImportError as exc:
        raise ImportError(
            "push senders require pyjwt[crypto] (installed by "
            "recto[v0_4]) for provider-auth token minting"
        ) from exc
    return jwt


class PushSendError(Exception):
    """A push send failed. The dispatcher logs and continues -- this
    never propagates into a request path."""


class PushSender(ABC):
    """One platform's silent-wake sender."""

    @property
    @abstractmethod
    def platform(self) -> str:
        """Platform discriminator this sender serves ("apns" / "fcm")."""

    @abstractmethod
    def send_wake(self, push_token: str, *, request_id: str) -> None:
        """Fire one silent wake push. ``request_id`` is used ONLY for
        log correlation -- it is never placed in the push payload.

        Raises PushSendError on failure (dispatcher catches).
        """


@dataclass(frozen=True)
class ApnsConfig:
    """APNs provider-token auth config.

    ``p8_key_pem`` is the CONTENT of the .p8 signing key (resolve via a
    SecretSource); ``team_id`` + ``key_id`` come from the Apple
    Developer portal; ``bundle_id`` is the phone app's bundle id
    (becomes the ``apns-topic`` header); ``use_sandbox`` selects the
    sandbox gateway for development-signed builds.
    """

    team_id: str
    key_id: str
    p8_key_pem: str
    bundle_id: str
    use_sandbox: bool = False


class ApnsPushSender(PushSender):
    """APNs HTTP/2 sender using provider-token (JWT ES256) auth.

    Provider JWTs are cached ~50 minutes (Apple accepts 20-60 min).
    The wake push is ``content-available: 1`` at priority 5 with
    ``apns-push-type: background`` -- Apple's canonical silent-wake
    shape.
    """

    _TOKEN_LIFETIME_SECONDS = 50 * 60

    def __init__(self, config: ApnsConfig, *, client: Any = None):
        self._cfg = config
        self._jwt_value: str | None = None
        self._jwt_minted_at = 0.0
        self._jwt_lock = threading.Lock()
        if client is not None:
            self._client = client
        else:
            httpx = _import_httpx()
            self._client = httpx.Client(http2=True, timeout=10.0)

    @property
    def platform(self) -> str:
        return PLATFORM_APNS

    @property
    def _base_url(self) -> str:
        return (
            "https://api.sandbox.push.apple.com"
            if self._cfg.use_sandbox
            else "https://api.push.apple.com"
        )

    def _provider_jwt(self) -> str:
        with self._jwt_lock:
            now = time.time()
            if (
                self._jwt_value is not None
                and now - self._jwt_minted_at < self._TOKEN_LIFETIME_SECONDS
            ):
                return self._jwt_value
            jwt_mod = _import_jwt()
            self._jwt_value = jwt_mod.encode(
                {"iss": self._cfg.team_id, "iat": int(now)},
                self._cfg.p8_key_pem,
                algorithm="ES256",
                headers={"kid": self._cfg.key_id},
            )
            self._jwt_minted_at = now
            return self._jwt_value

    def send_wake(self, push_token: str, *, request_id: str) -> None:
        url = f"{self._base_url}/3/device/{push_token}"
        headers = {
            "authorization": f"bearer {self._provider_jwt()}",
            "apns-topic": self._cfg.bundle_id,
            "apns-push-type": "background",
            "apns-priority": "5",
        }
        # Payload rule 1: bare wake marker only -- no request content.
        payload = {"aps": {"content-available": 1}, "recto": "pending_wake"}
        try:
            resp = self._client.post(url, headers=headers, json=payload)
        except Exception as exc:
            raise PushSendError(f"apns send failed: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise PushSendError(
                f"apns send returned {resp.status_code} "
                f"(request {request_id})"
            )


@dataclass(frozen=True)
class FcmConfig:
    """FCM HTTP v1 config. ``service_account_json`` is the CONTENT of a
    Google service-account key file with the ``cloudmessaging.messages``
    permission (resolve via a SecretSource)."""

    project_id: str
    service_account_json: str


class FcmPushSender(PushSender):
    """FCM HTTP v1 sender using service-account OAuth2 (JWT-bearer).

    Access tokens are cached until ~5 minutes before expiry. The wake
    push is a data-only message at high priority -- FCM's silent-wake
    shape (no ``notification`` block, so nothing is displayed).
    """

    _SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
    _TOKEN_URL = "https://oauth2.googleapis.com/token"

    def __init__(self, config: FcmConfig, *, client: Any = None):
        self._cfg = config
        self._sa = json.loads(config.service_account_json)
        self._access_token: str | None = None
        self._token_expires_at = 0.0
        self._token_lock = threading.Lock()
        if client is not None:
            self._client = client
        else:
            httpx = _import_httpx()
            self._client = httpx.Client(timeout=10.0)

    @property
    def platform(self) -> str:
        return PLATFORM_FCM

    def _oauth_token(self) -> str:
        with self._token_lock:
            now = time.time()
            if self._access_token is not None and now < self._token_expires_at:
                return self._access_token
            jwt_mod = _import_jwt()
            assertion = jwt_mod.encode(
                {
                    "iss": self._sa["client_email"],
                    "scope": self._SCOPE,
                    "aud": self._TOKEN_URL,
                    "iat": int(now),
                    "exp": int(now) + 3600,
                },
                self._sa["private_key"],
                algorithm="RS256",
            )
            resp = self._client.post(
                self._TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": assertion,
                },
            )
            if resp.status_code != 200:
                raise PushSendError(
                    f"fcm oauth token exchange returned {resp.status_code}"
                )
            body = resp.json()
            self._access_token = body["access_token"]
            self._token_expires_at = now + float(body.get("expires_in", 3600)) - 300
            return self._access_token

    def send_wake(self, push_token: str, *, request_id: str) -> None:
        url = (
            f"https://fcm.googleapis.com/v1/projects/"
            f"{self._cfg.project_id}/messages:send"
        )
        # Payload rule 1: bare wake marker only -- no request content.
        message = {
            "message": {
                "token": push_token,
                "data": {"recto": "pending_wake"},
                "android": {"priority": "HIGH"},
            }
        }
        try:
            resp = self._client.post(
                url,
                headers={"authorization": f"Bearer {self._oauth_token()}"},
                json=message,
            )
        except PushSendError:
            raise
        except Exception as exc:
            raise PushSendError(f"fcm send failed: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise PushSendError(
                f"fcm send returned {resp.status_code} (request {request_id})"
            )


class PushDispatcher:
    """Routes wake pushes to the right platform sender, asynchronously.

    ``notify(phone, request_id)`` is safe to call from any request
    handler: it returns immediately (daemon thread does the send) and
    NEVER raises -- push is best-effort by design (hard property 2).
    Phones without a registered token are silently skipped (poll-only).
    """

    def __init__(self, senders: list[PushSender]):
        self._senders = {s.platform: s for s in senders}

    @property
    def platforms(self) -> list[str]:
        return sorted(self._senders.keys())

    def notify(self, phone: Any, request_id: str) -> None:
        token = getattr(phone, "push_token", None)
        platform = getattr(phone, "push_platform", None)
        if not token or not platform:
            return
        sender = self._senders.get(platform)
        if sender is None:
            logger.debug(
                "no push sender registered for platform %r (phone %s)",
                platform,
                getattr(phone, "phone_id", "?"),
            )
            return
        threading.Thread(
            target=self._send_logged,
            args=(sender, token, request_id, getattr(phone, "phone_id", "?")),
            daemon=True,
            name=f"recto-push-{platform}",
        ).start()

    def _send_logged(
        self, sender: PushSender, token: str, request_id: str, phone_id: str
    ) -> None:
        try:
            sender.send_wake(token, request_id=request_id)
        except Exception as exc:  # noqa: BLE001 - hard property 2
            logger.warning(
                "push wake failed (platform=%s phone=%s request=%s): %s",
                sender.platform,
                phone_id,
                request_id,
                exc,
            )
