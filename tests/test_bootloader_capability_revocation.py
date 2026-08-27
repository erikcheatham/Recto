"""Tests for Phase 5 Wave C part 2: persistent capability revocation.

Three layers:

1. ``StateStore`` round-trip: ``add_revocation`` / ``is_revoked`` /
   ``list_revocations`` survive disk persistence and a fresh
   StateStore reload from the same state_dir.

2. New HTTP endpoints:
   - ``POST /v0.4/capability/revoke`` -- operator-token-gated.
     Adds a jti to the persistent revocation list. Idempotent.
   - ``GET /v0.4/capability/revocations`` -- public, ETag-cached.
     Verifiers fetch on a short cadence (default max-age=30s) and
     cache locally to bound revoke-to-honor latency.

3. Verifier integration: ``POST /v0.4/secrets/read`` migrated from
   the in-memory ``cfg.capability_revocation_jtis`` set to
   ``cfg.state.is_revoked(jti)``. A jti revoked via the new
   endpoint is rejected at the next secret-read attempt.

Auto-prune: revocation entries past their ``original_exp_unix`` are
dropped on every read (since a JWT past its own exp is already
universally rejected by ``verify_jws``, the revocation record is no
longer needed). Tested via direct StateStore manipulation since
mocking ``time.time()`` mid-HTTP-loop is fragile.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import (
    BootloaderHandler,
    ChallengeStore,
    create_server,
)
from recto.bootloader.state import (
    RevocationEntry,
    StateStore,
)


# Canonical manifest version, read once at module load. The resolver
# (`recto.capability.manifest.resolve_actions`) strict-checks
# `clause.registry_version == manifest.version`, so pinning a
# literal like "2026-05-05" breaks the moment the manifest gets
# bumped. The gate-server fixture loads the canonical manifest from
# disk, so the JWT clause must use whatever version that file is at.
_MANIFEST_VERSION: str = json.loads(
    (Path(__file__).parent.parent / "recto" / "capability" / "manifest_v1.json")
    .read_text(encoding="utf-8")
)["version"]
from recto.capability.jwt import build_signing_input
from recto.capability.manifest import load_manifest
from recto.capability.types import (
    ActionManifest,
    CapabilityClaims,
    CapabilityClause,
    CapabilityLimits,
    CapabilityScope,
)


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Test-only ES256K mint helper (mirrored from
# test_bootloader_capability_gate.py -- DRY would consolidate but we
# keep them parallel so each test module is independent)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def operator_keypair():
    """Generate a secp256k1 keypair for the test operator."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    priv_int = priv.private_numbers().private_value
    pub_nums = priv.public_key().public_numbers()
    pub_bytes = pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
    return (priv_int, pub_bytes)


def _mint_jws(claims: CapabilityClaims, priv_int: int) -> str:
    """Mint a test-only ES256K JWS."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    digest, header_b64, payload_b64 = build_signing_input(claims)
    priv = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())
    sig_der = priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(sig_der)
    SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
    sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{header_b64}.{payload_b64}.{_b64u_encode(sig_bytes)}"


@pytest.fixture(scope="session")
def template_manifest() -> ActionManifest:
    return load_manifest(
        Path(__file__).parent.parent / "recto" / "capability" / "manifest_v1.json"
    )


def _starter_claims(*, exp_offset_seconds: int = 86400, jti: str | None = None) -> CapabilityClaims:
    now = int(time.time())
    return CapabilityClaims(
        iss="phone:operator:enclave",
        sub="agent:darwin@staging",
        aud=["consumer-app"],
        iat=now,
        nbf=now,
        exp=now + exp_offset_seconds,
        jti=jti or f"cap_test_{now}_{exp_offset_seconds}",
        cap=CapabilityClause(
            tier=1,
            registry_version=_MANIFEST_VERSION,
            groups=["darwin:secret-reads"],
            scope=CapabilityScope(env=[], services=[], repos=[]),
            allow_actions=[],
            deny_actions=[],
            limits=CapabilityLimits(
                per_hour={}, per_day={}, per_session={},
            ),
        ),
        purpose="Wave C part 2 test capability",
    )


# ---------------------------------------------------------------------------
# StateStore-level: RevocationEntry persistence + auto-prune
# ---------------------------------------------------------------------------


class TestRevocationStateStore:
    @pytest.fixture
    def store(self, tmp_path: Path) -> StateStore:
        return StateStore(state_dir=tmp_path)

    def test_add_and_check(self, store: StateStore) -> None:
        now = int(time.time())
        store.add_revocation(RevocationEntry(
            jti="cap_X",
            revoked_at_unix=now,
            original_exp_unix=now + 3600,
            reason="test",
        ))
        assert store.is_revoked("cap_X") is True
        assert store.is_revoked("cap_Y") is False

    def test_add_is_idempotent(self, store: StateStore) -> None:
        now = int(time.time())
        first = RevocationEntry(
            jti="cap_X", revoked_at_unix=now,
            original_exp_unix=now + 3600, reason="first",
        )
        second = RevocationEntry(
            jti="cap_X", revoked_at_unix=now + 10,
            original_exp_unix=now + 7200, reason="second-attempt",
        )
        store.add_revocation(first)
        store.add_revocation(second)  # No-op; first wins
        listed = store.list_revocations()
        assert len(listed) == 1
        assert listed[0].reason == "first"
        assert listed[0].original_exp_unix == now + 3600

    def test_list_returns_sorted(self, store: StateStore) -> None:
        now = int(time.time())
        for jti in ["cap_C", "cap_A", "cap_B"]:
            store.add_revocation(RevocationEntry(
                jti=jti, revoked_at_unix=now,
                original_exp_unix=now + 3600, reason=None,
            ))
        listed = store.list_revocations()
        assert [e.jti for e in listed] == ["cap_A", "cap_B", "cap_C"]

    def test_persistence_survives_fresh_store(self, tmp_path: Path) -> None:
        now = int(time.time())
        # First store: add revocation, let it persist to disk.
        s1 = StateStore(state_dir=tmp_path)
        s1.add_revocation(RevocationEntry(
            jti="cap_persistent",
            revoked_at_unix=now,
            original_exp_unix=now + 3600,
            reason="persist-me",
        ))
        # Fresh store on same dir: should re-read from revocations.json.
        s2 = StateStore(state_dir=tmp_path)
        assert s2.is_revoked("cap_persistent") is True
        listed = s2.list_revocations()
        assert len(listed) == 1
        assert listed[0].reason == "persist-me"

    def test_expired_entries_auto_purge_on_read(
        self, store: StateStore
    ) -> None:
        now = int(time.time())
        store.add_revocation(RevocationEntry(
            jti="cap_active",
            revoked_at_unix=now,
            original_exp_unix=now + 3600,  # active
            reason=None,
        ))
        store.add_revocation(RevocationEntry(
            jti="cap_expired",
            revoked_at_unix=now - 7200,
            original_exp_unix=now - 3600,  # 1h ago
            reason="should-purge",
        ))
        # is_revoked() purges before checking
        assert store.is_revoked("cap_active") is True
        assert store.is_revoked("cap_expired") is False
        listed = store.list_revocations()
        assert {e.jti for e in listed} == {"cap_active"}

    def test_expired_entries_not_loaded_from_disk(self, tmp_path: Path) -> None:
        """Entries past original_exp_unix at load time are skipped."""
        now = int(time.time())
        # Manually craft a revocations.json with one expired + one active.
        revocations_path = tmp_path / "revocations.json"
        revocations_path.write_text(json.dumps({
            "revocations": [
                {
                    "jti": "cap_already_expired",
                    "revoked_at_unix": now - 7200,
                    "original_exp_unix": now - 3600,
                    "reason": "should-skip",
                },
                {
                    "jti": "cap_still_active",
                    "revoked_at_unix": now,
                    "original_exp_unix": now + 3600,
                    "reason": None,
                },
            ],
        }), encoding="utf-8")
        s = StateStore(state_dir=tmp_path)
        assert s.is_revoked("cap_already_expired") is False
        assert s.is_revoked("cap_still_active") is True


# ---------------------------------------------------------------------------
# Live HTTP fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def gate_server(tmp_path: Path, operator_keypair, template_manifest):
    """Live bootloader with all Wave C surfaces wired: vault gate +
    manifest + revocation endpoints + the operator-token gate.
    """
    priv_int, pub_bytes = operator_keypair
    state = StateStore(state_dir=tmp_path)
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state,
        bootloader_id="t", challenges=ChallengeStore(),
        ssl_context=None,
        capability_operator_pubkey=pub_bytes,
        capability_manifest=template_manifest,
        capability_vault_secrets={
            ("consumer-app", "STRIPE_KEY"): "sk_test_value",
        },
        capability_operator_token="operator-secret-token-fixture",
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
            "state": state,
            "operator_token": "operator-secret-token-fixture",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _http_get(url: str, headers: dict[str, str] | None = None):
    req = urlrequest.Request(url, headers=headers or {}, method="GET")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _http_post_json(url, body, headers=None):
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
# POST /v0.4/capability/revoke
# ---------------------------------------------------------------------------


class TestRevokeEndpoint:
    def test_happy_path_revokes_jti(self, gate_server):
        ctx = gate_server
        now = int(time.time())
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/revoke",
            {
                "jti": "cap_to_revoke_1",
                "original_exp_unix": now + 3600,
                "reason": "agent compromised",
            },
            headers={"X-Recto-Operator-Token": ctx["operator_token"]},
        )
        assert status == 200, body
        assert body["revoked"] is True
        assert body["jti"] == "cap_to_revoke_1"
        assert body["already_revoked"] is False
        # Confirm it landed in the StateStore.
        assert ctx["state"].is_revoked("cap_to_revoke_1") is True

    def test_idempotent_revoke(self, gate_server):
        ctx = gate_server
        now = int(time.time())
        body_args = {
            "jti": "cap_double_revoke",
            "original_exp_unix": now + 3600,
        }
        first = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/revoke", body_args,
            headers={"X-Recto-Operator-Token": ctx["operator_token"]},
        )
        second = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/revoke", body_args,
            headers={"X-Recto-Operator-Token": ctx["operator_token"]},
        )
        assert first[0] == 200
        assert first[1]["already_revoked"] is False
        assert second[0] == 200
        assert second[1]["already_revoked"] is True

    def test_missing_operator_token_returns_401(self, gate_server):
        ctx = gate_server
        now = int(time.time())
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/revoke",
            {"jti": "x", "original_exp_unix": now + 3600},
        )
        assert status == 401
        assert body["error"] == "operator_token_required"

    def test_wrong_operator_token_returns_401(self, gate_server):
        ctx = gate_server
        now = int(time.time())
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/revoke",
            {"jti": "x", "original_exp_unix": now + 3600},
            headers={"X-Recto-Operator-Token": "wrong-token"},
        )
        assert status == 401
        assert body["error"] == "operator_token_invalid"

    def test_missing_jti_returns_400(self, gate_server):
        ctx = gate_server
        now = int(time.time())
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/revoke",
            {"original_exp_unix": now + 3600},
            headers={"X-Recto-Operator-Token": ctx["operator_token"]},
        )
        assert status == 400
        assert "jti" in body["detail"]

    def test_missing_original_exp_returns_400(self, gate_server):
        ctx = gate_server
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/revoke",
            {"jti": "x"},
            headers={"X-Recto-Operator-Token": ctx["operator_token"]},
        )
        assert status == 400
        assert "original_exp_unix" in body["detail"]

    def test_endpoint_disabled_when_no_operator_token(self, tmp_path):
        """No operator token configured -> endpoint returns 404."""
        state = StateStore(state_dir=tmp_path)
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=state,
            bootloader_id="t", challenges=ChallengeStore(),
            ssl_context=None,
            # capability_operator_token left None
        )
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            now = int(time.time())
            status, body = _http_post_json(
                f"http://{host}:{port}/v0.4/capability/revoke",
                {"jti": "x", "original_exp_unix": now + 3600},
                headers={"X-Recto-Operator-Token": "anything"},
            )
            assert status == 404
            assert body["error"] == "unknown_endpoint"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)


# ---------------------------------------------------------------------------
# GET /v0.4/capability/revocations
# ---------------------------------------------------------------------------


class TestRevocationsEndpoint:
    def test_empty_list_when_no_revocations(self, gate_server):
        ctx = gate_server
        status, headers, body_bytes = _http_get(
            f"{ctx['base_url']}/v0.4/capability/revocations"
        )
        assert status == 200
        body = json.loads(body_bytes.decode("utf-8"))
        assert body["revocations"] == []
        # ETag is served even for an empty list.
        assert headers["ETag"]
        assert "max-age=30" in headers.get("Cache-Control", "")

    def test_lists_revocations_after_revoke(self, gate_server):
        ctx = gate_server
        now = int(time.time())
        # Revoke 2 JTIs.
        for jti in ["cap_A", "cap_B"]:
            _http_post_json(
                f"{ctx['base_url']}/v0.4/capability/revoke",
                {
                    "jti": jti,
                    "original_exp_unix": now + 3600,
                    "reason": f"reason-for-{jti}",
                },
                headers={"X-Recto-Operator-Token": ctx["operator_token"]},
            )
        # Fetch list.
        status, headers, body_bytes = _http_get(
            f"{ctx['base_url']}/v0.4/capability/revocations"
        )
        assert status == 200
        body = json.loads(body_bytes.decode("utf-8"))
        assert len(body["revocations"]) == 2
        # Sorted by jti.
        jtis = [r["jti"] for r in body["revocations"]]
        assert jtis == sorted(jtis)
        # Reasons preserved.
        for r in body["revocations"]:
            assert r["reason"] == f"reason-for-{r['jti']}"

    def test_etag_supports_if_none_match(self, gate_server):
        ctx = gate_server
        # Add one revocation.
        now = int(time.time())
        _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/revoke",
            {"jti": "cap_etag", "original_exp_unix": now + 3600},
            headers={"X-Recto-Operator-Token": ctx["operator_token"]},
        )
        # First fetch.
        _, headers1, _ = _http_get(
            f"{ctx['base_url']}/v0.4/capability/revocations"
        )
        etag = headers1["ETag"]
        # Re-fetch with If-None-Match.
        status, headers2, body = _http_get(
            f"{ctx['base_url']}/v0.4/capability/revocations",
            headers={"If-None-Match": etag},
        )
        assert status == 304
        assert body == b""

    def test_etag_changes_on_new_revocation(self, gate_server):
        """Adding a revocation invalidates downstream caches via a
        new ETag."""
        ctx = gate_server
        # Initial empty list.
        _, headers0, _ = _http_get(
            f"{ctx['base_url']}/v0.4/capability/revocations"
        )
        etag_empty = headers0["ETag"]
        # Add a revocation.
        now = int(time.time())
        _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/revoke",
            {"jti": "cap_invalidates_etag", "original_exp_unix": now + 3600},
            headers={"X-Recto-Operator-Token": ctx["operator_token"]},
        )
        # Re-fetch.
        _, headers1, _ = _http_get(
            f"{ctx['base_url']}/v0.4/capability/revocations"
        )
        etag_one = headers1["ETag"]
        assert etag_empty != etag_one


# ---------------------------------------------------------------------------
# Verifier integration: /v0.4/secrets/read sees state-store revocations
# ---------------------------------------------------------------------------


class TestSecretReadHonorsRevocation:
    def test_revoked_via_endpoint_blocks_secret_read(self, gate_server):
        """Revoke a JTI via the new endpoint, then attempt to use that
        JWT for /v0.4/secrets/read -- should be 401."""
        ctx = gate_server
        # Mint a JWT.
        claims = _starter_claims(jti="cap_will_be_revoked")
        jws = _mint_jws(claims, ctx["priv_int"])
        # Confirm the JWT works first.
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": jws,
                "service": "consumer-app",
                "secret_name": "STRIPE_KEY",
            },
        )
        assert status == 200
        assert body["value"] == "sk_test_value"
        # Revoke the JTI.
        _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/revoke",
            {
                "jti": "cap_will_be_revoked",
                "original_exp_unix": claims.exp,
                "reason": "compromised",
            },
            headers={"X-Recto-Operator-Token": ctx["operator_token"]},
        )
        # Re-attempt. Should be blocked.
        status2, body2 = _http_post_json(
            f"{ctx['base_url']}/v0.4/secrets/read",
            {
                "capability_jws": jws,
                "service": "consumer-app",
                "secret_name": "STRIPE_KEY",
            },
        )
        assert status2 == 401
        assert body2["error"] == "capability_revoked"
        assert body2["jti"] == "cap_will_be_revoked"

    def test_test_convenience_kwarg_seeds_state_store(
        self, tmp_path, operator_keypair, template_manifest
    ):
        """Wave C part 1's capability_revocation_jtis kwarg now seeds
        the StateStore. Verify a JTI in that kwarg is rejected at
        secret-read."""
        priv_int, pub_bytes = operator_keypair
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
            capability_revocation_jtis={"cap_seeded_revoked"},
        )
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            claims = _starter_claims(jti="cap_seeded_revoked")
            jws = _mint_jws(claims, priv_int)
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
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)
