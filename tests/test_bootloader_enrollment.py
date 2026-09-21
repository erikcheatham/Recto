"""GATE 2a -- enrollment must be attested, not asserted (the refusal half).

THE DEFECT, as the root-of-trust brief states it: *a phone is enrolled as
software-keyed BY SILENCE*. Three separate defaults on one path resolved a
missing algorithm to "ed25519":

    server.py  body.get("supported_algorithms", ["ed25519"])   absent field
    server.py  algos[0] if algos else "ed25519"                empty list
    sessions.py  algorithm: str = "ed25519"                    the verifier

and nothing validated the string against anything -- an unknown algorithm went
straight to verification and came back as an opaque signature failure.

WHAT THIS SUITE DOES AND DOES NOT COVER. It covers the REFUSAL: a phone that
cannot say what it signs with does not enroll. It does NOT cover ATTESTATION --
that is GATE 2b (Android KeyStore + iOS App Attest) and it is the half that
makes an algorithm name mean something. "ed25519" is sent by Android StrongBox
phones AND by the software fallback, so the string alone still does not
distinguish hardware from software. Closing enrollment-by-silence is necessary
and is not sufficient; do not read a green run here as a hardware guarantee.

THE POSITIVE CONTROL IS NOT DECORATION. Three of these tests assert a refusal,
and an endpoint that refused EVERYTHING would pass all three. Without
`test_a_well_formed_registration_still_succeeds` this suite cannot tell a
working gate from a broken endpoint. Same lesson as the GATE 0c probe and the
servicebus key-spelling probe, both 2026-08-17.
"""

from __future__ import annotations

import base64
import json
import threading
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.sessions import SUPPORTED_ALGORITHMS
from recto.bootloader.state import StateStore


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _post(url: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    req = urlrequest.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


def _get(url: str) -> tuple[int, dict[str, Any]]:
    try:
        with urlrequest.urlopen(url, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


@pytest.fixture
def server_ctx(tmp_path: Path):
    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore()
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="enrollment-test-bootloader",
        challenges=challenges,
        ssl_context=None,
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"base_url": f"http://{host}:{port}", "state": state,
               "challenges": challenges}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _register(ctx, *, algorithms: Any, omit: bool = False):
    """Mint a challenge, sign it for real, and POST a registration.

    The signature is always VALID. That is deliberate: every refusal below must
    be caused by the algorithm declaration and nothing else, so a test that goes
    red cannot be explained away as a bad proof.
    """
    code, _exp = ctx["challenges"].issue_pairing_code()
    status, chal = _get(
        f"{ctx['base_url']}/v0.4/registration_challenge?code={code}"
    )
    assert status == 200, f"challenge mint failed: {status} {chal}"
    challenge = chal["challenge_b64u"]

    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    body: dict[str, Any] = {
        "device_label": "enrollment-test-phone",
        "public_key_b64u": _b64u(pub_raw),
        "v0_4_protocol": 1,
        "registration_proof": {
            "challenge": challenge,
            "signature_b64u": _b64u(key.sign(challenge.encode("ascii"))),
        },
    }
    if not omit:
        body["supported_algorithms"] = algorithms
    return _post(f"{ctx['base_url']}/v0.4/register", body)


# --------------------------------------------------------------------------
# THE POSITIVE CONTROL -- read this one first.
# --------------------------------------------------------------------------

def test_a_well_formed_registration_still_succeeds(server_ctx):
    """Without this, the three refusals below prove nothing.

    An endpoint broken in any way refuses every request, and a suite of
    refusal-assertions goes green over it. This is the test that distinguishes
    "the gate works" from "nothing works".
    """
    status, body = _register(server_ctx, algorithms=["ed25519"])
    # 201 Created is the success code for enrollment; 200 accepted here only so
    # the control never goes red on a status-code convention rather than on the
    # thing it exists to detect.
    assert status in (200, 201), f"a valid ed25519 enrollment was refused: {body}"
    assert body.get("registered") is True, f"no registration confirmation: {body}"
    assert server_ctx["state"].list_phones(), "phone was not persisted"


# --------------------------------------------------------------------------
# THE GATE
# --------------------------------------------------------------------------

def test_enrollment_refuses_an_absent_algorithm_list(server_ctx):
    """RED-BUILD: restore the ["ed25519"] default on body.get() and this passes
    a registration that declares nothing at all."""
    status, body = _register(server_ctx, algorithms=None, omit=True)
    assert status >= 400, (
        "a phone that declared NO algorithm was enrolled. It is now recorded as "
        "ed25519 -- the software path -- purely because it said nothing."
    )
    assert not server_ctx["state"].list_phones(), "refused, but still persisted"


def test_enrollment_refuses_an_empty_algorithm_list(server_ctx):
    """The second default. `[]` is a phone actively declaring nothing, which is
    worse than omission, and it used to reach the same software fallback."""
    status, body = _register(server_ctx, algorithms=[])
    assert status >= 400, "an empty supported_algorithms list was accepted"
    assert not server_ctx["state"].list_phones()


def test_enrollment_refuses_an_algorithm_the_verifier_cannot_check(server_ctx):
    """NOT RED-BUILD VERIFIED, and the honest reason is worth stating.

    This test passes against the PRE-GATE-2a build too: verify_signature already
    rejected an algorithm it could not handle. So the vocabulary check does not
    close a hole here -- it moves the refusal EARLIER (before any crypto is
    attempted) and makes the message name the supported set instead of surfacing
    as a signature failure, which reads as a bad phone rather than a bad
    declaration.

    Kept because it pins that behaviour against regression. NOT counted as one
    of the gate's closures. The two closures are absent-list and empty-list, and
    those two DID go red on the reverted build.
    """
    status, body = _register(server_ctx, algorithms=["rot13"])
    assert status >= 400, "an unsupported algorithm name was accepted"
    detail = json.dumps(body).lower()
    assert "rot13" in detail or "algorithm" in detail, (
        f"refused, but the reason does not name the cause: {body}"
    )
    assert not server_ctx["state"].list_phones()


def test_the_vocabulary_is_declared_in_exactly_one_place(server_ctx):
    """SUPPORTED_ALGORITHMS is the thing that did not exist before GATE 2a.

    Its absence is why 'validated against nothing' was literally true. This
    asserts the constant holds what the verifier can actually check -- if a
    third algorithm is added to verify_signature without being added here,
    enrollment will refuse it and this test says why.
    """
    assert SUPPORTED_ALGORITHMS == ("ed25519", "ecdsa-p256")
    status, _ = _register(server_ctx, algorithms=["ecdsa-p256"])
    assert status >= 400, (
        "an ecdsa-p256 DECLARATION with an ed25519 SIGNATURE should fail "
        "verification -- the declaration is checked against the vocabulary, "
        "then the signature is checked against the declaration."
    )
