"""Tests for Phase 2.0.C wave C.6: the bootloader's HTTP surface for
profile_revoke_device (per-profile device-set mutations — removing a
phone from device_ids).

Covers three new endpoints + the _handle_respond profile_revoke_device
branch:

1. ``POST /v0.4/profile/<profile_id>/revoke-device`` — agent-token-
   authenticated. Pre-flight checks: profile exists + not revoked +
   revoke_quorum_k == 1 (reject K>=2 with quorum_not_yet_implemented)
   + phone_id_to_revoke is registered + phone_id_to_revoke IS in
   device_ids (else idempotent ``already_not_member`` 200) +
   last-device guard.
2. ``GET /v0.4/profile/revoke-device-result/<request_id>`` — agent-
   token + ownership pin; single-use poll.
3. ``POST /v0.4/respond/<request_id>`` (profile_revoke_device branch)
   — master phone posts a master-attestation signature over the
   canonical-JSON encoding of (action, profile_id, phone_id_to_revoke,
   revoked_at_unix, request_id, master_pubkey_hex); bootloader
   verifies + calls ``profile.manage.profile_revoke_device`` to
   remove the phone from device_ids.

At v1 only K=1 master-only signing is wired end-to-end. K-of-N
aggregation across non-master paired devices is banked for v1.1.

Self-contained helpers (duplicated from test_bootloader_profile_
add_device.py rather than cross-imported because cross-importing
pytest fixtures across test modules is fragile).
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

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import (
    PhoneRegistration,
    ProfileRevokeDeviceResult,
    StateStore,
)
from recto.profile.manage import (
    bootstrap_master,
    create_child_profile,
    get_profile_by_id,
    mark_profile_revoked,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


AGENT_ID = "test-revdev-agent"
AGENT_TOKEN = "test-revdev-token-" + "x" * 16


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _agent_headers(*, agent_id: str = AGENT_ID, agent_token: str = AGENT_TOKEN) -> dict[str, str]:
    return {
        "X-Recto-Agent-Id": agent_id,
        "X-Recto-Agent-Token": agent_token,
    }


def _http_post(
    url: str,
    body: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8")
    req = urlrequest.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}


def _http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    req = urlrequest.Request(url, method="GET", headers=headers or {})
    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}


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


def _sign_master_attestation(digest_32: bytes, priv_int: int) -> bytes:
    """Produce 64-byte raw r||s master attestation over a 32-byte digest."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    priv = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())
    sig_der = priv.sign(digest_32, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(sig_der)
    SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# Server fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def revdev_server(tmp_path: Path, operator_keypair):
    """Bootloader fixture with bootstrapped master + one child profile
    + multiple paired phones (master + two non-master devices already
    in the profile's device_ids tuple)."""
    priv_int, pub_bytes = operator_keypair
    pub_hex = pub_bytes.hex()

    mi = bootstrap_master(
        master_pubkey_hex=pub_hex,
        display_name="Test master",
        state_dir=tmp_path,
    )

    state = StateStore(state_dir=tmp_path)

    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    def _make_phone(label: str) -> tuple[PhoneRegistration, Any]:
        ed_priv = ed25519.Ed25519PrivateKey.generate()
        ed_pub_bytes = ed_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        phone = PhoneRegistration.new(
            public_key_b64u=_b64u_encode(ed_pub_bytes),
            supported_algorithms=("ed25519",),
            device_label=label,
        )
        state.register_phone(phone)
        return phone, ed_priv

    master_phone, master_ed_priv = _make_phone("test-master-phone")
    laptop_phone, laptop_ed_priv = _make_phone("test-laptop")
    pixel_phone, pixel_ed_priv = _make_phone("test-pixel")
    # An UNAFFILIATED phone that's registered but NOT on this profile,
    # for testing the "phone_id_to_revoke not in device_ids" path.
    other_phone, other_ed_priv = _make_phone("test-other")

    child = create_child_profile(
        kind="personal:child",
        display_name="Test Personal Child",
        derived_pubkey_hex=bytes(range(0, 64)).hex(),
        device_ids=(master_phone.phone_id, laptop_phone.phone_id, pixel_phone.phone_id),
        state_dir=tmp_path,
    )

    # A SINGLE-DEVICE profile to exercise the last-device guard.
    single_dev_child = create_child_profile(
        kind="work",
        display_name="Single-device test",
        derived_pubkey_hex=bytes(range(64, 128)).hex(),
        device_ids=(master_phone.phone_id,),
        state_dir=tmp_path,
    )

    # A K=2 profile to exercise the quorum_not_yet_implemented gate.
    k2_child = create_child_profile(
        kind="school",
        display_name="K=2 quorum test",
        derived_pubkey_hex=bytes([0xAB] * 64).hex(),
        device_ids=(master_phone.phone_id, laptop_phone.phone_id),
        revoke_quorum_k=2,
        state_dir=tmp_path,
    )

    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-revdev-bootloader",
        challenges=ChallengeStore(),
        ssl_context=None,
        capability_operator_pubkey=pub_bytes,
        capability_agent_tokens={AGENT_ID: AGENT_TOKEN},
    )
    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": base_url,
            "state_dir": tmp_path,
            "priv_int": priv_int,
            "pub_bytes": pub_bytes,
            "master_phone_id": master_phone.phone_id,
            "master_ed_priv": master_ed_priv,
            "laptop_phone_id": laptop_phone.phone_id,
            "pixel_phone_id": pixel_phone.phone_id,
            "other_phone_id": other_phone.phone_id,
            "child_profile_id": child.profile_id,
            "single_dev_child_profile_id": single_dev_child.profile_id,
            "k2_child_profile_id": k2_child.profile_id,
            "state": state,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _approve_revoke_device(
    ctx: dict[str, Any],
    request_id: str,
    payload_hash_b64u: str,
    cap_payload_b64: str,
    *,
    override_cap_signature_b64u: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Simulate the master phone approving a profile_revoke_device.

    Phone signs SHA-256(canonical_json_bytes) with the operator master
    secp256k1 key. Also signs the payload_hash_b64u bytes with the
    registered Ed25519 paired-phone key.
    """
    pad = "=" * (-len(cap_payload_b64) % 4)
    signing_input_bytes = base64.urlsafe_b64decode(cap_payload_b64 + pad)
    digest = hashlib.sha256(signing_input_bytes).digest()
    raw_sig = _sign_master_attestation(digest, ctx["priv_int"])
    cap_sig_b64u = (
        override_cap_signature_b64u
        if override_cap_signature_b64u is not None
        else _b64u_encode(raw_sig)
    )

    pad = "=" * (-len(payload_hash_b64u) % 4)
    hash_bytes = base64.urlsafe_b64decode(payload_hash_b64u + pad)
    ed_priv = ctx["master_ed_priv"]
    ed_sig = ed_priv.sign(hash_bytes)
    sig_b64u = _b64u_encode(ed_sig)

    return _http_post(
        f"{ctx['base_url']}/v0.4/respond/{request_id}",
        {
            "decision": "approved",
            "signature_b64u": sig_b64u,
            "cap_signature_b64u": cap_sig_b64u,
        },
    )


# ---------------------------------------------------------------------------
# Endpoint auth + body validation
# ---------------------------------------------------------------------------


def test_post_requires_agent_auth(revdev_server):
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["laptop_phone_id"],
        },
    )
    assert code == 401
    assert body["error"] == "agent_auth_required"


def test_post_wrong_token_401(revdev_server):
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["laptop_phone_id"],
        },
        headers=_agent_headers(agent_token="wrong"),
    )
    assert code == 401
    assert body["error"] == "agent_auth_failed"


def test_post_missing_master_phone_id_400(revdev_server):
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {"phone_id_to_revoke": ctx["laptop_phone_id"]},
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_missing_phone_id_to_revoke_400(revdev_server):
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {"master_phone_id": ctx["master_phone_id"]},
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_unregistered_master_phone_400(revdev_server):
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": "nonexistent-phone",
            "phone_id_to_revoke": ctx["laptop_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_unregistered_phone_to_revoke_400(revdev_server):
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": "nonexistent-phone-id",
        },
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_unknown_profile_400(revdev_server):
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/00000000-0000-0000-0000-000000000000/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["laptop_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_revoked_profile_rejected(revdev_server):
    """Revoked profile can't accept device-set mutations."""
    ctx = revdev_server
    mark_profile_revoked(ctx["child_profile_id"], state_dir=ctx["state_dir"])
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["laptop_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_k2_quorum_rejected_with_clear_error(revdev_server):
    """K=2 profile: pre-flight rejects with quorum_not_yet_implemented."""
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['k2_child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["laptop_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 400
    assert body["error"] == "quorum_not_yet_implemented"
    assert body["revoke_quorum_k"] == 2


def test_post_already_not_member_idempotent(revdev_server):
    """phone_id_to_revoke not in device_ids → 200 already_not_member."""
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["other_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 200, body
    assert body["status"] == "already_not_member"
    assert body["profile_id"] == ctx["child_profile_id"]
    assert body["phone_id_to_revoke"] == ctx["other_phone_id"]


def test_post_last_device_guard_400(revdev_server):
    """Profile with only 1 device → cannot revoke (would brick profile)."""
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['single_dev_child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["master_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 400
    assert body["error"] == "last_device_guard"


def test_post_201_queues_request(revdev_server):
    """Valid request returns 201 with request_id + result_url."""
    ctx = revdev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["laptop_phone_id"],
            "revoker_label": "Master phone",
        },
        headers=_agent_headers(),
    )
    assert code == 201, body
    assert "request_id" in body
    assert body["profile_id"] == ctx["child_profile_id"]
    assert body["phone_id_to_revoke"] == ctx["laptop_phone_id"]
    assert body["result_url"].startswith("/v0.4/profile/revoke-device-result/")


# ---------------------------------------------------------------------------
# GET result endpoint
# ---------------------------------------------------------------------------


def test_get_result_requires_agent_auth(revdev_server):
    ctx = revdev_server
    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/revoke-device-result/some-id",
    )
    assert code == 401


def test_get_result_pending_while_in_flight(revdev_server):
    ctx = revdev_server
    _, post_body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["laptop_phone_id"],
        },
        headers=_agent_headers(),
    )
    request_id = post_body["request_id"]
    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/revoke-device-result/{request_id}",
        headers=_agent_headers(),
    )
    assert code == 200
    assert body["status"] == "pending"


def test_get_result_404_when_unknown(revdev_server):
    ctx = revdev_server
    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/revoke-device-result/00000000-0000-0000-0000-000000000000",
        headers=_agent_headers(),
    )
    assert code == 404


# ---------------------------------------------------------------------------
# End-to-end approval flow
# ---------------------------------------------------------------------------


def test_full_approval_removes_from_device_ids(revdev_server):
    """POST → simulate phone approval → GET shows approved + Profile.
    device_ids no longer contains the revoked phone."""
    ctx = revdev_server
    _, post_body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["laptop_phone_id"],
        },
        headers=_agent_headers(),
    )
    request_id = post_body["request_id"]

    pendings = ctx["state"].list_pending_for_phone(ctx["master_phone_id"])
    queued = next(p for p in pendings if p.request_id == request_id)
    assert queued.kind == "profile_revoke_device"
    assert queued.revdev_profile_id == ctx["child_profile_id"]
    assert queued.revdev_phone_id_to_revoke == ctx["laptop_phone_id"]
    assert queued.cap_payload_b64 is not None

    code, resp_body = _approve_revoke_device(
        ctx,
        request_id,
        queued.payload_hash_b64u,
        queued.cap_payload_b64,
    )
    assert code == 200, resp_body
    assert resp_body.get("resolved") is True

    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/revoke-device-result/{request_id}",
        headers=_agent_headers(),
    )
    assert code == 200, body
    assert body["status"] == "approved"
    assert body["profile_id"] == ctx["child_profile_id"]
    assert body["phone_id_revoked"] == ctx["laptop_phone_id"]

    updated = get_profile_by_id(
        ctx["child_profile_id"], state_dir=ctx["state_dir"]
    )
    assert ctx["laptop_phone_id"] not in updated.device_ids
    assert ctx["master_phone_id"] in updated.device_ids
    assert ctx["pixel_phone_id"] in updated.device_ids


def test_full_denial_does_not_modify_device_ids(revdev_server):
    ctx = revdev_server
    _, post_body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["laptop_phone_id"],
        },
        headers=_agent_headers(),
    )
    request_id = post_body["request_id"]
    code, _ = _http_post(
        f"{ctx['base_url']}/v0.4/respond/{request_id}",
        {"decision": "denied", "reason": "operator declined"},
    )
    assert code == 200

    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/revoke-device-result/{request_id}",
        headers=_agent_headers(),
    )
    assert code == 200
    assert body["status"] == "denied"
    assert body["reason"] == "operator declined"

    p = get_profile_by_id(
        ctx["child_profile_id"], state_dir=ctx["state_dir"]
    )
    assert ctx["laptop_phone_id"] in p.device_ids


def test_bad_signature_signature_error(revdev_server):
    ctx = revdev_server
    _, post_body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/revoke-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "phone_id_to_revoke": ctx["laptop_phone_id"],
        },
        headers=_agent_headers(),
    )
    request_id = post_body["request_id"]
    pendings = ctx["state"].list_pending_for_phone(ctx["master_phone_id"])
    queued = next(p for p in pendings if p.request_id == request_id)

    bad_sig = _b64u_encode(b"\x00" * 64)
    code, _ = _approve_revoke_device(
        ctx,
        request_id,
        queued.payload_hash_b64u,
        queued.cap_payload_b64,
        override_cap_signature_b64u=bad_sig,
    )
    assert code == 400

    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/revoke-device-result/{request_id}",
        headers=_agent_headers(),
    )
    assert code == 200
    assert body["status"] == "signature_error"
    p = get_profile_by_id(
        ctx["child_profile_id"], state_dir=ctx["state_dir"]
    )
    assert ctx["laptop_phone_id"] in p.device_ids


# ---------------------------------------------------------------------------
# PendingRequest construction validation
# ---------------------------------------------------------------------------


class TestPendingRequestConstruction:
    def test_new_profile_revoke_device_rejects_empty_profile_id(self):
        from recto.bootloader.state import PendingRequest

        with pytest.raises(ValueError, match="revdev_profile_id"):
            PendingRequest.new_profile_revoke_device(
                service="recto",
                secret="profile",
                phone_id="phone-1",
                operation_description="test",
                payload_hash_b64u="abc",
                child_pid=0,
                child_argv0="(test)",
                revdev_profile_id="",
                revdev_phone_id_to_revoke="ph-target",
            )

    def test_new_profile_revoke_device_rejects_empty_phone_id_to_revoke(self):
        from recto.bootloader.state import PendingRequest

        with pytest.raises(ValueError, match="revdev_phone_id_to_revoke"):
            PendingRequest.new_profile_revoke_device(
                service="recto",
                secret="profile",
                phone_id="phone-1",
                operation_description="test",
                payload_hash_b64u="abc",
                child_pid=0,
                child_argv0="(test)",
                revdev_profile_id="p-1",
                revdev_phone_id_to_revoke="",
            )

    def test_new_profile_revoke_device_constructs_with_all_fields(self):
        from recto.bootloader.state import PendingRequest

        req = PendingRequest.new_profile_revoke_device(
            service="recto",
            secret="profile",
            phone_id="master-phone",
            operation_description="revoke laptop",
            payload_hash_b64u="abcde",
            child_pid=42,
            child_argv0="(test)",
            revdev_profile_id="profile-uuid",
            revdev_phone_id_to_revoke="laptop-uuid",
            revdev_revoker_label="Master phone",
            ttl_seconds=300,
        )
        assert req.kind == "profile_revoke_device"
        assert req.revdev_profile_id == "profile-uuid"
        assert req.revdev_phone_id_to_revoke == "laptop-uuid"
        assert req.revdev_revoker_label == "Master phone"


# ---------------------------------------------------------------------------
# StateStore put/get/take semantics
# ---------------------------------------------------------------------------


class TestStateStoreResults:
    def test_put_get_round_trip(self, tmp_path: Path):
        state = StateStore(state_dir=tmp_path)
        now = int(time.time())
        result = ProfileRevokeDeviceResult(
            request_id="req-1",
            status="approved",
            profile_id="p-1",
            phone_id_revoked="ph-2",
            reason=None,
            resolved_at_unix=now,
            expires_at_unix=now + 600,
        )
        state.put_profile_revoke_device_result(result)
        fetched = state.get_profile_revoke_device_result("req-1")
        assert fetched == result

    def test_take_is_single_use(self, tmp_path: Path):
        state = StateStore(state_dir=tmp_path)
        now = int(time.time())
        state.put_profile_revoke_device_result(ProfileRevokeDeviceResult(
            request_id="req-2",
            status="approved",
            profile_id="p-1",
            phone_id_revoked="ph-2",
            reason=None,
            resolved_at_unix=now,
            expires_at_unix=now + 600,
        ))
        first = state.take_profile_revoke_device_result("req-2")
        second = state.take_profile_revoke_device_result("req-2")
        assert first is not None
        assert second is None

    def test_expired_results_purged(self, tmp_path: Path):
        state = StateStore(state_dir=tmp_path)
        now = int(time.time())
        state.put_profile_revoke_device_result(ProfileRevokeDeviceResult(
            request_id="req-3",
            status="approved",
            profile_id="p-1",
            phone_id_revoked="ph-2",
            reason=None,
            resolved_at_unix=now - 10,
            expires_at_unix=now - 1,
        ))
        fetched = state.get_profile_revoke_device_result("req-3")
        assert fetched is None
