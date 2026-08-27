"""Tests for Phase 2.0.C wave C.5: the bootloader's HTTP surface for
profile_add_device (per-profile device sets).

Covers three new endpoints + the _handle_respond profile_add_device branch:

1. ``POST /v0.4/profile/<profile_id>/add-device`` — agent-token-authenticated;
   queues a profile_add_device PendingRequest on the operator's master
   phone with the target profile_id + new_phone_id. Returns request_id +
   result_url. Pre-flight checks: profile exists + not revoked + new_phone_id
   registered + new_phone_id not already in device_ids (idempotent
   ``already_member`` if so).
2. ``GET /v0.4/profile/add-device-result/<request_id>`` — agent-token +
   ownership pin; single-use poll for the post-approval result.
3. ``POST /v0.4/respond/<request_id>`` (profile_add_device branch) — phone
   posts a master-attestation signature over the canonical-JSON encoding
   of (profile_id + new_phone_id + added_at_unix + request_id); bootloader
   verifies against ``cfg.capability_operator_pubkey``, atomic-writes the
   appended phone_id via ``profile.manage.profile_add_device``, stashes
   a ProfileAddDeviceResult.

Partial-failure design (Milan Jovanović commitments A-C, same as
profile_create):
* A — caller-authored idempotency key: candidate_request_id (URL-bound)
  re-used = re-prompt avoided.
* B — persist last; result is derived: master_identity.json is source
  of truth.
* C — never claim success when persist failed: signature_error +
  "persist_error:" prefix on disk-write failure.

Reuses helpers from test_bootloader_profile_create.py (operator_keypair
fixture, _sign_master_attestation, _http_post/_http_get, _b64u_encode,
_agent_headers) to keep test infrastructure DRY.
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
    ProfileAddDeviceResult,
    StateStore,
)
from recto.profile.manage import (
    bootstrap_master,
    create_child_profile,
    get_profile_by_id,
    profile_add_device,
)


# ---------------------------------------------------------------------------
# Helpers (self-contained — duplicated from test_bootloader_profile_create.py
# rather than cross-imported because cross-importing pytest fixtures across
# test modules is fragile)
# ---------------------------------------------------------------------------


AGENT_ID = "test-adddev-agent"
AGENT_TOKEN = "test-adddev-token-" + "x" * 16


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
# Server fixture — sister of profile_server but pre-creates a child profile
# ---------------------------------------------------------------------------


@pytest.fixture
def adddev_server(tmp_path: Path, operator_keypair):  # noqa: F811
    """Bootloader fixture with bootstrapped master + one child profile +
    two paired phones (master phone + new device). Tests POST against
    `/v0.4/profile/<child_profile_id>/add-device`, appending new_phone
    to child's device_ids.
    """
    priv_int, pub_bytes = operator_keypair
    pub_hex = pub_bytes.hex()

    mi = bootstrap_master(
        master_pubkey_hex=pub_hex,
        display_name="Test master",
        state_dir=tmp_path,
    )

    state = StateStore(state_dir=tmp_path)

    # Register two phones: master_phone (signs add-device attestation)
    # and new_phone (the device being added).
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
    new_phone, new_ed_priv = _make_phone("test-new-device")

    # Create a child profile to add devices to. master_phone is its
    # initial device (the phone that approved the create).
    child = create_child_profile(
        kind="personal:child",
        display_name="Test Personal Child",
        derived_pubkey_hex=bytes(range(0, 64)).hex(),
        device_ids=(master_phone.phone_id,),
        state_dir=tmp_path,
    )

    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-adddev-bootloader",
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
            "new_phone_id": new_phone.phone_id,
            "new_ed_priv": new_ed_priv,
            "child_profile_id": child.profile_id,
            "state": state,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _approve_add_device(
    ctx: dict[str, Any],
    request_id: str,
    payload_hash_b64u: str,
    cap_payload_b64: str,
    *,
    override_cap_signature_b64u: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Simulate the master phone approving a profile_add_device request.

    Phone signs SHA-256(canonical_json_bytes) with the operator's
    secp256k1 master key (test-fake here via _sign_master_attestation).
    Also signs the payload_hash_b64u bytes with the registered Ed25519
    paired-phone key (envelope auth proof).
    """
    # secp256k1 master attestation over SHA-256(cap_payload bytes)
    pad = "=" * (-len(cap_payload_b64) % 4)
    signing_input_bytes = base64.urlsafe_b64decode(cap_payload_b64 + pad)
    digest = hashlib.sha256(signing_input_bytes).digest()
    raw_sig = _sign_master_attestation(digest, ctx["priv_int"])
    cap_sig_b64u = (
        override_cap_signature_b64u
        if override_cap_signature_b64u is not None
        else _b64u_encode(raw_sig)
    )

    # Ed25519 envelope sig over the payload_hash bytes
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


def test_post_add_device_requires_agent_auth(adddev_server):
    """Missing X-Recto-Agent-Id + X-Recto-Agent-Token = 401."""
    ctx = adddev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "new_phone_id": ctx["new_phone_id"],
        },
    )
    assert code == 401
    assert body["error"] == "agent_auth_required"


def test_post_add_device_wrong_token_401(adddev_server):
    """Wrong agent token = 401."""
    ctx = adddev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "new_phone_id": ctx["new_phone_id"],
        },
        headers=_agent_headers(agent_token="wrong-token"),
    )
    assert code == 401
    assert body["error"] == "agent_auth_failed"


def test_post_add_device_missing_master_phone_id_400(adddev_server):
    ctx = adddev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {"new_phone_id": ctx["new_phone_id"]},
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_add_device_missing_new_phone_id_400(adddev_server):
    ctx = adddev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {"master_phone_id": ctx["master_phone_id"]},
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_add_device_unregistered_master_phone_400(adddev_server):
    ctx = adddev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": "nonexistent-phone-id",
            "new_phone_id": ctx["new_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_add_device_unregistered_new_phone_400(adddev_server):
    ctx = adddev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "new_phone_id": "nonexistent-new-phone-id",
        },
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_add_device_same_master_and_new_400(adddev_server):
    """master_phone_id == new_phone_id is rejected."""
    ctx = adddev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "new_phone_id": ctx["master_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_add_device_unknown_profile_400(adddev_server):
    """profile_id not found under master = 400."""
    ctx = adddev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/00000000-0000-0000-0000-000000000000/add-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "new_phone_id": ctx["new_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 400


def test_post_add_device_already_member_200_idempotent(adddev_server):
    """new_phone_id already in profile.device_ids → 200 already_member,
    NOT a queued request."""
    ctx = adddev_server
    # master_phone_id is already in child's device_ids (set at create)
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": ctx["new_phone_id"],
            "new_phone_id": ctx["master_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 200, body
    assert body["status"] == "already_member"
    assert body["profile_id"] == ctx["child_profile_id"]
    assert body["new_phone_id"] == ctx["master_phone_id"]


def test_post_add_device_201_queues_request(adddev_server):
    """Valid request returns 201 with request_id + result_url."""
    ctx = adddev_server
    code, body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "new_phone_id": ctx["new_phone_id"],
        },
        headers=_agent_headers(),
    )
    assert code == 201, body
    assert "request_id" in body
    assert body["profile_id"] == ctx["child_profile_id"]
    assert body["new_phone_id"] == ctx["new_phone_id"]
    assert body["result_url"].startswith("/v0.4/profile/add-device-result/")


# ---------------------------------------------------------------------------
# GET result endpoint
# ---------------------------------------------------------------------------


def test_get_result_requires_agent_auth(adddev_server):
    ctx = adddev_server
    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/add-device-result/some-request-id",
    )
    assert code == 401


def test_get_result_pending_while_in_flight(adddev_server):
    """POST → GET → status="pending" while operator hasn't approved."""
    ctx = adddev_server
    _, post_body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "new_phone_id": ctx["new_phone_id"],
        },
        headers=_agent_headers(),
    )
    request_id = post_body["request_id"]
    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/add-device-result/{request_id}",
        headers=_agent_headers(),
    )
    assert code == 200
    assert body["status"] == "pending"


def test_get_result_404_when_unknown_request(adddev_server):
    ctx = adddev_server
    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/add-device-result/00000000-0000-0000-0000-000000000000",
        headers=_agent_headers(),
    )
    assert code == 404


# ---------------------------------------------------------------------------
# End-to-end approval flow (THE happy path)
# ---------------------------------------------------------------------------


def test_full_approval_appends_to_device_ids(adddev_server):
    """POST → simulate phone approval → GET shows approved +
    Profile.device_ids contains the new phone."""
    ctx = adddev_server
    # 1. POST queue
    _, post_body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "new_phone_id": ctx["new_phone_id"],
        },
        headers=_agent_headers(),
    )
    request_id = post_body["request_id"]

    # 2. Pull the queued PendingRequest to extract cap_payload_b64
    pendings = ctx["state"].list_pending_for_phone(ctx["master_phone_id"])
    queued = next(p for p in pendings if p.request_id == request_id)
    assert queued.kind == "profile_add_device"
    assert queued.addev_profile_id == ctx["child_profile_id"]
    assert queued.addev_new_phone_id == ctx["new_phone_id"]
    assert queued.cap_payload_b64 is not None

    # 3. Simulate phone approval
    code, resp_body = _approve_add_device(
        ctx,
        request_id,
        queued.payload_hash_b64u,
        queued.cap_payload_b64,
    )
    assert code == 200, resp_body
    assert resp_body.get("resolved") is True

    # 4. GET result endpoint
    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/add-device-result/{request_id}",
        headers=_agent_headers(),
    )
    assert code == 200, body
    assert body["status"] == "approved", body
    assert body["profile_id"] == ctx["child_profile_id"]
    assert body["new_phone_id"] == ctx["new_phone_id"]

    # 5. Profile.device_ids contains the new phone
    updated = get_profile_by_id(
        ctx["child_profile_id"], state_dir=ctx["state_dir"]
    )
    assert updated is not None
    assert ctx["new_phone_id"] in updated.device_ids
    assert ctx["master_phone_id"] in updated.device_ids


def test_full_denial_does_not_modify_device_ids(adddev_server):
    """POST → simulate denial → GET shows denied + device_ids unchanged."""
    ctx = adddev_server
    _, post_body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "new_phone_id": ctx["new_phone_id"],
        },
        headers=_agent_headers(),
    )
    request_id = post_body["request_id"]

    # Simulate denial
    code, _ = _http_post(
        f"{ctx['base_url']}/v0.4/respond/{request_id}",
        {"decision": "denied", "reason": "operator declined"},
    )
    assert code == 200

    # GET shows denied
    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/add-device-result/{request_id}",
        headers=_agent_headers(),
    )
    assert code == 200
    assert body["status"] == "denied"
    assert body["reason"] == "operator declined"

    # Profile.device_ids unchanged
    p = get_profile_by_id(
        ctx["child_profile_id"], state_dir=ctx["state_dir"]
    )
    assert ctx["new_phone_id"] not in p.device_ids


def test_bad_signature_signature_error(adddev_server):
    """Approval with wrong cap_signature → signature_error."""
    ctx = adddev_server
    _, post_body = _http_post(
        f"{ctx['base_url']}/v0.4/profile/{ctx['child_profile_id']}/add-device",
        {
            "master_phone_id": ctx["master_phone_id"],
            "new_phone_id": ctx["new_phone_id"],
        },
        headers=_agent_headers(),
    )
    request_id = post_body["request_id"]
    pendings = ctx["state"].list_pending_for_phone(ctx["master_phone_id"])
    queued = next(p for p in pendings if p.request_id == request_id)

    # Use a garbage cap_signature (64 bytes of zeros — won't recover to operator)
    bad_sig = _b64u_encode(b"\x00" * 64)
    code, _ = _approve_add_device(
        ctx,
        request_id,
        queued.payload_hash_b64u,
        queued.cap_payload_b64,
        override_cap_signature_b64u=bad_sig,
    )
    # Approval fails (400 from BootloaderError) but result is stored
    assert code == 400

    code, body = _http_get(
        f"{ctx['base_url']}/v0.4/profile/add-device-result/{request_id}",
        headers=_agent_headers(),
    )
    assert code == 200
    assert body["status"] == "signature_error"
    # Profile.device_ids unchanged
    p = get_profile_by_id(
        ctx["child_profile_id"], state_dir=ctx["state_dir"]
    )
    assert ctx["new_phone_id"] not in p.device_ids


# ---------------------------------------------------------------------------
# PendingRequest construction validation
# ---------------------------------------------------------------------------


class TestPendingRequestConstruction:
    def test_new_profile_add_device_rejects_empty_profile_id(self):
        from recto.bootloader.state import PendingRequest

        with pytest.raises(ValueError, match="addev_profile_id"):
            PendingRequest.new_profile_add_device(
                service="recto",
                secret="profile",
                phone_id="phone-1",
                operation_description="test",
                payload_hash_b64u="abc",
                child_pid=0,
                child_argv0="(test)",
                addev_profile_id="",
                addev_new_phone_id="new-phone",
            )

    def test_new_profile_add_device_rejects_empty_new_phone_id(self):
        from recto.bootloader.state import PendingRequest

        with pytest.raises(ValueError, match="addev_new_phone_id"):
            PendingRequest.new_profile_add_device(
                service="recto",
                secret="profile",
                phone_id="phone-1",
                operation_description="test",
                payload_hash_b64u="abc",
                child_pid=0,
                child_argv0="(test)",
                addev_profile_id="p-1",
                addev_new_phone_id="",
            )

    def test_new_profile_add_device_constructs_with_all_fields(self):
        from recto.bootloader.state import PendingRequest

        req = PendingRequest.new_profile_add_device(
            service="recto",
            secret="profile",
            phone_id="phone-1",
            operation_description="add device test",
            payload_hash_b64u="abcde",
            child_pid=42,
            child_argv0="(test)",
            addev_profile_id="profile-uuid",
            addev_new_phone_id="new-phone-uuid",
            addev_new_phone_label="Pixel 10",
            ttl_seconds=300,
        )
        assert req.kind == "profile_add_device"
        assert req.addev_profile_id == "profile-uuid"
        assert req.addev_new_phone_id == "new-phone-uuid"
        assert req.addev_new_phone_label == "Pixel 10"
        assert req.phone_id == "phone-1"


# ---------------------------------------------------------------------------
# StateStore put/get/take semantics
# ---------------------------------------------------------------------------


class TestStateStoreResults:
    def test_put_get_round_trip(self, tmp_path: Path):
        state = StateStore(state_dir=tmp_path)
        now = int(time.time())
        result = ProfileAddDeviceResult(
            request_id="req-1",
            status="approved",
            profile_id="p-1",
            new_phone_id="ph-2",
            reason=None,
            resolved_at_unix=now,
            expires_at_unix=now + 600,
        )
        state.put_profile_add_device_result(result)
        fetched = state.get_profile_add_device_result("req-1")
        assert fetched == result

    def test_take_is_single_use(self, tmp_path: Path):
        state = StateStore(state_dir=tmp_path)
        now = int(time.time())
        state.put_profile_add_device_result(ProfileAddDeviceResult(
            request_id="req-2",
            status="approved",
            profile_id="p-1",
            new_phone_id="ph-2",
            reason=None,
            resolved_at_unix=now,
            expires_at_unix=now + 600,
        ))
        first = state.take_profile_add_device_result("req-2")
        second = state.take_profile_add_device_result("req-2")
        assert first is not None
        assert second is None

    def test_expired_results_purged(self, tmp_path: Path):
        state = StateStore(state_dir=tmp_path)
        now = int(time.time())
        state.put_profile_add_device_result(ProfileAddDeviceResult(
            request_id="req-3",
            status="approved",
            profile_id="p-1",
            new_phone_id="ph-2",
            reason=None,
            resolved_at_unix=now - 10,
            expires_at_unix=now - 1,  # already expired
        ))
        fetched = state.get_profile_add_device_result("req-3")
        assert fetched is None
