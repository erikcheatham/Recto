"""Tests for Phase 5 Wave C part 1: capability-gated vault secret reads
and the public manifest distribution endpoint.

Covers two new endpoints on the bootloader:

1. ``GET /v0.4/capability/manifest`` -- public; returns the canonical
   capability action manifest JSON. ETag-cached via the manifest's
   `version` field. Verifiers fetch this once and cache via standard
   HTTP cache semantics; agents that need to compute foundation-count
   breakdowns server-side fetch too.

2. ``POST /v0.4/secrets/read`` -- capability-gated. Body:
   ``{capability_jws, service, secret_name}``. Bootloader verifies the
   JWS against ``cfg.capability_operator_pubkey``, evaluates
   ``secret:read`` against the JWT's scope, then looks up the secret
   in the operator-supplied ``cfg.capability_vault_secrets`` map.

Test-only JWS minting uses the ``cryptography`` library's secp256k1
support to produce a valid ES256K signature -- the production
capability mint flow remains phone-enclave-only (
``recto/capability/jwt.py::mint_jws`` still raises NotImplementedError).
The test mint helper exists to exercise the real ``verify_jws`` path
in the bootloader against real signatures.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import (
    BootloaderConfig,
    BootloaderHandler,
    ChallengeStore,
    create_server,
)
from recto.bootloader.state import StateStore
from recto.capability.jwt import build_signing_input
from recto.capability.manifest import load_manifest
from recto.capability.types import (
    ActionManifest,
    CapabilityClaims,
    CapabilityClause,
    CapabilityLimits,
    CapabilityScope,
)


# Read the canonical manifest version once at module load. The
# `_starter_claims` fixture and any other JWT-shape helper that pins
# `registry_version` MUST use this constant — `resolve_actions` in
# `recto.capability.manifest` strict-checks
# `clause.registry_version == manifest.version` and any mismatch
# fails closed with `scope_denied`. Pinning a literal like
# "2026-05-05" breaks the moment the manifest gets bumped (it has,
# multiple times: 2026-05-15 added agents:create, 2026-05-16 added
# the profile:* family). Reading dynamically keeps the test
# fixtures aligned with the canonical manifest.
_MANIFEST_VERSION: str = json.loads(
    (Path(__file__).parent.parent / "recto" / "capability" / "manifest_v1.json")
    .read_text(encoding="utf-8")
)["version"]


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ---------------------------------------------------------------------------
# Test-only JWS minting helper (uses `cryptography` for ES256K sign).
# Production mint flow stays phone-enclave-only.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def operator_keypair():
    """Generate a secp256k1 keypair for the test operator. Returns
    ``(private_int, public_bytes_64)`` where public_bytes_64 is the
    uncompressed X||Y form (no 0x04 prefix) -- the same format
    ``recto.ethereum.recover_public_key`` returns + that
    ``BootloaderConfig.capability_operator_pubkey`` expects.
    """
    pytest.importorskip("cryptography")
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    priv_int = priv.private_numbers().private_value
    pub_nums = priv.public_key().public_numbers()
    pub_bytes = pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
    return (priv_int, pub_bytes)


def _mint_jws(claims: CapabilityClaims, priv_int: int) -> str:
    """Mint a test-only ES256K-signed JWS from a CapabilityClaims +
    secp256k1 private key int. Mirrors what the phone enclave does
    in production, just using `cryptography` instead of the Secure
    Enclave / StrongBox.
    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    digest, header_b64, payload_b64 = build_signing_input(claims)

    # Reconstruct the private key from the int.
    priv = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())

    # Sign the SHA-256 digest. cryptography returns a DER-encoded
    # signature; decode to (r, s) and pack as 64-byte raw r||s for
    # JWS ES256K.
    sig_der = priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(sig_der)

    # Low-s canonicalization (matches the C# EthSigningOps.SignWithRecovery
    # convention; some verifiers reject high-s signatures). secp256k1 N:
    SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s

    sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{header_b64}.{payload_b64}.{_b64u_encode(sig_bytes)}"


# ---------------------------------------------------------------------------
# Manifest fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def template_manifest() -> ActionManifest:
    """Load the template manifest shipped with recto.capability."""
    return load_manifest(
        Path(__file__).parent.parent / "recto" / "capability" / "manifest_v1.json"
    )


def _starter_claims(
    *,
    exp_offset_seconds: int = 86400,
    services: list[str] | None = None,
    groups: list[str] | None = None,
    deny_actions: list[str] | None = None,
) -> CapabilityClaims:
    """Darwin v1 starter capability with darwin:secret-reads (which
    includes the `secret:read` action). Default scope.services is
    empty (no per-service narrowing); pass `services=["..."]` to
    test the narrowing path.
    """
    now = int(time.time())
    return CapabilityClaims(
        iss="phone:operator:enclave",
        sub="agent:darwin@staging",
        aud=["consumer-app", "recto:vault"],
        iat=now,
        nbf=now,
        exp=now + exp_offset_seconds,
        jti=f"cap_test_{now}_{exp_offset_seconds}",
        cap=CapabilityClause(
            tier=1,
            registry_version=_MANIFEST_VERSION,
            groups=groups if groups is not None else ["darwin:secret-reads"],
            scope=CapabilityScope(
                env=["staging"],
                services=services if services is not None else [],
                repos=[],
            ),
            allow_actions=[],
            deny_actions=deny_actions if deny_actions is not None else [],
            limits=CapabilityLimits(
                per_hour={},
                per_day={},
                per_session={},
            ),
        ),
        purpose="Test capability for Wave C part 1",
    )


# ---------------------------------------------------------------------------
# Live HTTP fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def gate_server(tmp_path: Path, operator_keypair, template_manifest):
    """Spin a real BootloaderHandler with capability-manifest +
    capability-vault-secrets configured. Yields ctx dict with the
    base_url + operator keypair + populated secret map for tests.
    """
    priv_int, pub_bytes = operator_keypair
    state = StateStore(state_dir=tmp_path)

    vault_secrets = {
        ("consumer-app", "STRIPE_KEY"): "sk_test_consumer_stripe",
        ("consumer-app", "RESEND_TOKEN"): "re_test_consumer_resend",
        ("recto:vault", "ROOT_TOKEN"): "root-token-fixture",
    }

    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-gate-bootloader",
        challenges=ChallengeStore(),
        ssl_context=None,
        capability_operator_pubkey=pub_bytes,
        capability_manifest=template_manifest,
        capability_vault_secrets=vault_secrets,
    )
    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": base_url,
            "priv_int": priv_int,
            "pub_bytes": pub_bytes,
            "manifest": template_manifest,
            "vault_secrets": vault_secrets,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _http_get(
    url: str, headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    req = urlrequest.Request(url, headers=headers or {}, method="GET")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _http_post_json(
    url: str, body: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urlrequest.Request(url, data=data, headers=h, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# GET /v0.4/capability/manifest
# ---------------------------------------------------------------------------


class TestCapabilityManifestEndpoint:
    def test_manifest_endpoint_returns_canonical_json(self, gate_server):
        ctx = gate_server
        status, headers, body_bytes = _http_get(
            f"{ctx['base_url']}/v0.4/capability/manifest"
        )
        assert status == 200
        body = json.loads(body_bytes.decode("utf-8"))
        assert body["version"] == ctx["manifest"].version
        # Every action in the loaded manifest is in the response.
        for key, defn in ctx["manifest"].actions.items():
            assert body["actions"][key]["count"] == defn.count
            assert body["actions"][key]["description"] == defn.description
        # Every group survives.
        for key, defn in ctx["manifest"].groups.items():
            assert body["groups"][key]["actions"] == list(defn.actions)

    def test_manifest_endpoint_serves_etag(self, gate_server):
        ctx = gate_server
        status, headers, _ = _http_get(
            f"{ctx['base_url']}/v0.4/capability/manifest"
        )
        assert status == 200
        # ETag is the manifest's version, quoted per RFC 7232.
        assert headers["ETag"] == f'"{ctx["manifest"].version}"'
        assert "no-cache" not in headers.get("Cache-Control", "")

    def test_manifest_endpoint_returns_304_on_match(self, gate_server):
        ctx = gate_server
        # First fetch to get the ETag.
        _, headers, _ = _http_get(
            f"{ctx['base_url']}/v0.4/capability/manifest"
        )
        etag = headers["ETag"]
        # Re-fetch with If-None-Match.
        status, _, body = _http_get(
            f"{ctx['base_url']}/v0.4/capability/manifest",
            headers={"If-None-Match": etag},
        )
        assert status == 304
        # 304 has empty body.
        assert body == b""

    def test_manifest_endpoint_returns_404_when_unconfigured(self, tmp_path):
        # Server with NO manifest configured.
        state = StateStore(state_dir=tmp_path)
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=state,
            bootloader_id="t", challenges=ChallengeStore(),
            ssl_context=None,
            # capability_manifest left at None default
        )
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, _, _ = _http_get(
                f"http://{host}:{port}/v0.4/capability/manifest"
            )
            assert status == 404
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)

    def test_manifest_endpoint_loads_from_path_kwarg(self, tmp_path):
        # capability_manifest_path takes the path; create_server
        # loads it via load_manifest at startup.
        manifest_path = (
            Path(__file__).parent.parent / "recto" / "capability" / "manifest_v1.json"
        )
        state = StateStore(state_dir=tmp_path)
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=state,
            bootloader_id="t", challenges=ChallengeStore(),
            ssl_context=None,
            capability_manifest_path=str(manifest_path),
        )
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, _, body_bytes = _http_get(
                f"http://{host}:{port}/v0.4/capability/manifest"
            )
            assert status == 200
            body = json.loads(body_bytes.decode("utf-8"))
            # Read the canonical manifest's version at test time
            # rather than pinning a literal -- the manifest gets
            # bumped over time and this test only verifies "the
            # path I passed is what gets served", not the contents.
            with open(manifest_path, encoding="utf-8") as fh:
                expected_version = json.load(fh)["version"]
            assert body["version"] == expected_version
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)


# ---------------------------------------------------------------------------
# POST /v0.4/secrets/read -- happy path + auth failures
# ---------------------------------------------------------------------------


class TestSecretReadEndpoint:
    def test_happy_path_returns_secret_value(self, gate_server):
        ctx = gate_server
        # Mint a valid capability JWS with darwin:secret-reads (which
        # includes secret:read action).
        claims = _starter_claims()
        jws = _mint_jws(claims, ctx["priv_int"])
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": jws,
                "service": "consumer-app",
                "secret_name": "STRIPE_KEY",
            },
        )
        assert status == 200, body
        assert body["value"] == "sk_test_consumer_stripe"
        assert body["service"] == "consumer-app"
        assert body["secret_name"] == "STRIPE_KEY"
        assert body["jti"] == claims.jti

    def test_no_jws_returns_400(self, gate_server):
        ctx = gate_server
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {"service": "consumer-app", "secret_name": "STRIPE_KEY"},
        )
        assert status == 400
        assert "capability_jws" in body["detail"]

    def test_garbage_jws_returns_401(self, gate_server):
        ctx = gate_server
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": "not.a.real.jws",
                "service": "consumer-app",
                "secret_name": "STRIPE_KEY",
            },
        )
        assert status == 401
        assert body["error"] == "capability_jws_invalid"

    def test_signature_under_wrong_key_returns_401(self, gate_server):
        """A JWS signed by a different secp256k1 key (not the operator's)
        must be rejected at signature verification."""
        ctx = gate_server
        # Generate a different keypair; mint with that.
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec
        rogue = ec.generate_private_key(ec.SECP256K1(), default_backend())
        rogue_int = rogue.private_numbers().private_value

        claims = _starter_claims()
        bad_jws = _mint_jws(claims, rogue_int)
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": bad_jws,
                "service": "consumer-app",
                "secret_name": "STRIPE_KEY",
            },
        )
        assert status == 401
        assert body["error"] == "capability_jws_invalid"

    def test_expired_jws_returns_401(self, gate_server):
        ctx = gate_server
        claims = _starter_claims(exp_offset_seconds=-3600)  # 1h in the past
        jws = _mint_jws(claims, ctx["priv_int"])
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": jws,
                "service": "consumer-app",
                "secret_name": "STRIPE_KEY",
            },
        )
        assert status == 401
        assert body["error"] == "capability_jws_invalid"

    def test_revoked_jti_returns_401(self, gate_server, tmp_path,
                                      operator_keypair, template_manifest):
        """A jti present in capability_revocation_jtis is rejected
        even when the JWS signature is valid + scope is fine."""
        priv_int, pub_bytes = operator_keypair

        # Mint a claim first so we know its jti, then build a server
        # whose revocation set contains exactly that jti.
        claims = _starter_claims()
        jws = _mint_jws(claims, priv_int)

        state = StateStore(state_dir=tmp_path)
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=state,
            bootloader_id="t", challenges=ChallengeStore(),
            ssl_context=None,
            capability_operator_pubkey=pub_bytes,
            capability_manifest=template_manifest,
            capability_vault_secrets={
                ("consumer-app", "STRIPE_KEY"): "sk_test",
            },
            capability_revocation_jtis={claims.jti},
        )
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, body = _http_post_json(
                f"http://{host}:{port}/v0.4/secrets/read",
                {
                    "capability_jws": jws,
                    "service": "consumer-app",
                    "secret_name": "STRIPE_KEY",
                },
            )
            assert status == 401
            assert body["error"] == "capability_revoked"
            assert body["jti"] == claims.jti
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)


# ---------------------------------------------------------------------------
# POST /v0.4/secrets/read -- scope-evaluation failures
# ---------------------------------------------------------------------------


class TestSecretReadScopeEnforcement:
    def test_scope_lacking_secret_read_returns_403(self, gate_server):
        """A capability that only includes darwin:doc-edits (no
        secret:read) must be denied."""
        ctx = gate_server
        claims = _starter_claims(groups=["darwin:doc-edits"])
        jws = _mint_jws(claims, ctx["priv_int"])
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": jws,
                "service": "consumer-app",
                "secret_name": "STRIPE_KEY",
            },
        )
        assert status == 403
        assert body["error"] == "scope_denied"

    def test_explicit_deny_on_secret_read_returns_403(self, gate_server):
        """Scope includes darwin:secret-reads (which has secret:read)
        but deny_actions explicitly removes secret:read -- must be
        403."""
        ctx = gate_server
        claims = _starter_claims(deny_actions=["secret:read"])
        jws = _mint_jws(claims, ctx["priv_int"])
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": jws,
                "service": "consumer-app",
                "secret_name": "STRIPE_KEY",
            },
        )
        assert status == 403
        assert body["error"] == "scope_denied"

    def test_scope_services_narrowing_blocks_other_service(self, gate_server):
        """When clause.scope.services is non-empty, the requested
        service must be in the list. Capability scoped to
        ["consumer-app"] should block a request for ("recto:vault",
        "ROOT_TOKEN")."""
        ctx = gate_server
        claims = _starter_claims(services=["consumer-app"])
        jws = _mint_jws(claims, ctx["priv_int"])
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": jws,
                "service": "recto:vault",
                "secret_name": "ROOT_TOKEN",
            },
        )
        assert status == 403
        assert body["error"] == "scope_service_denied"

    def test_scope_services_narrowing_allows_listed_service(self, gate_server):
        """Same scoped capability should ALLOW a request for the
        listed service."""
        ctx = gate_server
        claims = _starter_claims(services=["consumer-app"])
        jws = _mint_jws(claims, ctx["priv_int"])
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": jws,
                "service": "consumer-app",
                "secret_name": "STRIPE_KEY",
            },
        )
        assert status == 200
        assert body["value"] == "sk_test_consumer_stripe"


# ---------------------------------------------------------------------------
# POST /v0.4/secrets/read -- not-found + 404 behavior
# ---------------------------------------------------------------------------


class TestSecretReadLookup:
    def test_unknown_secret_returns_404(self, gate_server):
        ctx = gate_server
        claims = _starter_claims()
        jws = _mint_jws(claims, ctx["priv_int"])
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": jws,
                "service": "consumer-app",
                "secret_name": "DOES_NOT_EXIST",
            },
        )
        assert status == 404
        assert body["error"] == "secret_not_found"
        assert body["service"] == "consumer-app"
        assert body["secret_name"] == "DOES_NOT_EXIST"


# ---------------------------------------------------------------------------
# Endpoint disabled when no vault secrets configured
# ---------------------------------------------------------------------------


class TestSecretReadDisabledWhenNoSecrets:
    def test_endpoint_returns_404_when_vault_empty(self, tmp_path,
                                                    operator_keypair,
                                                    template_manifest):
        priv_int, pub_bytes = operator_keypair
        state = StateStore(state_dir=tmp_path)
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=state,
            bootloader_id="t", challenges=ChallengeStore(),
            ssl_context=None,
            capability_operator_pubkey=pub_bytes,
            capability_manifest=template_manifest,
            # capability_vault_secrets left empty
        )
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            claims = _starter_claims()
            jws = _mint_jws(claims, priv_int)
            status, body = _http_post_json(
                f"http://{host}:{port}/v0.4/secrets/read",
                {
                    "capability_jws": jws,
                    "service": "consumer-app",
                    "secret_name": "STRIPE_KEY",
                },
            )
            assert status == 404
            assert body["error"] == "unknown_endpoint"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)

    def test_endpoint_returns_503_when_pubkey_missing(self, tmp_path,
                                                       template_manifest):
        """Vault secrets configured but operator pubkey isn't --
        return 503 to make the misconfiguration loud rather than
        silently 404'ing or accepting any signature."""
        state = StateStore(state_dir=tmp_path)
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=state,
            bootloader_id="t", challenges=ChallengeStore(),
            ssl_context=None,
            # capability_operator_pubkey left None
            capability_manifest=template_manifest,
            capability_vault_secrets={
                ("consumer-app", "STRIPE_KEY"): "sk_test",
            },
        )
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, body = _http_post_json(
                f"http://{host}:{port}/v0.4/secrets/read",
                {
                    "capability_jws": "x.y.z",
                    "service": "consumer-app",
                    "secret_name": "STRIPE_KEY",
                },
            )
            assert status == 503
            assert body["error"] == "operator_pubkey_not_configured"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)
