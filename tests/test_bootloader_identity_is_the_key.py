"""THE KEY IS THE IDENTITY (2026-09-21) -- a phone IS its keypair; the phone_id is a name for it.

THE DEFECT. `PhoneRegistration.new` minted `phone_id = uuid4()` on every registration, so the same
enclave key registering twice (an unpair + re-pair; a store re-verify) produced TWO records with two
ids, and every consumer keyed on the first id -- approval carding, push routing, the pending queue --
went dark without any error. Measured twice in one week on one phone. The id was an ADDRESS the phone
rented from its own storage; the identity was always the key.

THE FIX, in three parts, each with a test below:
  1. a NEW registration's phone_id IS its phone_ref (`pk_` + sha256(raw pubkey)[:16]) -- deterministic,
     derivable by anyone holding the pubkey, a credential for no one;
  2. registering a key the registry already holds is the SAME record -- one phone, the id it already
     had, the metadata refreshed;
  3. a LEGACY record (a Guid id from a pre-split phones.json) keeps its Guid forever (nothing that
     carded it re-points) and ALSO answers to its phone_ref.

Back-compat is the whole point of (3): the wire shape is unchanged (phone_id is still a string; the
phone persists whatever it is given), build-12 phones keep polling, and a re-pair of the genesis phone
changes no row anywhere.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import uuid
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import PhoneRegistration, StateStore, phone_ref_of


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _http(method: str, url: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urlrequest.Request(url, data=data, headers={"Content-Type": "application/json"}, method=method)
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


@pytest.fixture
def ctx(tmp_path: Path):
    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore()
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state,
        bootloader_id="identity-test-bootloader", challenges=challenges, ssl_context=None,
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"base_url": f"http://{host}:{port}", "state": state, "challenges": challenges,
               "state_dir": tmp_path}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _key() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, _b64u(pub_raw)


def _register(ctx, key: Ed25519PrivateKey, pub_b64u: str, *, label: str) -> tuple[int, dict[str, Any]]:
    code, _ = ctx["challenges"].issue_pairing_code()
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={code}")
    assert status == 200, f"challenge mint failed: {status} {chal}"
    challenge = chal["challenge_b64u"]
    return _http("POST", f"{ctx['base_url']}/v0.4/register", {
        "device_label": label,
        "public_key_b64u": pub_b64u,
        "supported_algorithms": ["ed25519"],
        "v0_4_protocol": 1,
        "registration_proof": {
            "challenge": challenge,
            "signature_b64u": _b64u(key.sign(challenge.encode("ascii"))),
        },
    })


def _expected_ref(pub_b64u: str) -> str:
    raw = base64.urlsafe_b64decode(pub_b64u + "=" * (-len(pub_b64u) % 4))
    return "pk_" + hashlib.sha256(raw).hexdigest()[:16]


# --------------------------------------------------------------------------
# 1. the id IS the reference
# --------------------------------------------------------------------------

def test_a_new_phone_id_is_its_phone_ref(ctx):
    key, pub = _key()
    status, body = _register(ctx, key, pub, label="pixel")
    assert status == 201, body
    assert body["phone_id"] == _expected_ref(pub), (
        "a fresh registration minted an address (a Guid) instead of naming the key"
    )
    assert body["phone_ref"] == body["phone_id"], "the reference half and the id half disagree"
    assert phone_ref_of(pub) == body["phone_id"], "the store's derivation differs from the wire's"


# --------------------------------------------------------------------------
# 2. the same key twice is ONE phone (the ghost's red-build)
# --------------------------------------------------------------------------

def test_the_same_key_registered_twice_is_one_phone(ctx):
    """RED-BUILD: restore `phone_id=str(uuid.uuid4())` in PhoneRegistration.new and this
    fails on the second assertion -- two records, two ids, and every lane keyed on the
    first goes dark. That was 2026-09-16 15:42Z and 2026-09-17 19:08Z."""
    key, pub = _key()
    s1, first = _register(ctx, key, pub, label="pixel (first pairing)")
    assert s1 == 201, first
    s2, second = _register(ctx, key, pub, label="pixel (re-paired)")
    assert s2 == 201, second

    phones = ctx["state"].list_phones()
    assert len(phones) == 1, f"one key, {len(phones)} records -- the ghost is back"
    assert second["phone_id"] == first["phone_id"], "a re-pair of the same key changed its id"
    assert phones[0].device_label == "pixel (re-paired)", "the re-registration did not refresh metadata"
    assert phones[0].public_key_b64u == pub


def test_two_different_keys_are_two_phones(ctx):
    """The positive control for the merge: it merges on the KEY, not on anything else."""
    k1, p1 = _key()
    k2, p2 = _key()
    _, a = _register(ctx, k1, p1, label="pixel")
    _, b = _register(ctx, k2, p2, label="iphone")
    assert a["phone_id"] != b["phone_id"]
    assert len(ctx["state"].list_phones()) == 2


# --------------------------------------------------------------------------
# 3. a legacy Guid record keeps its Guid and answers to its ref
# --------------------------------------------------------------------------

def _seed_legacy(state_dir: Path, pub_b64u: str) -> str:
    """A phones.json as a pre-split bootloader wrote it: a Guid id, no notion of a ref."""
    guid = str(uuid.uuid4())
    (state_dir / "phones.json").write_text(json.dumps({"phones": [{
        "phone_id": guid,
        "device_label": "pixel (legacy)",
        "public_key_b64u": pub_b64u,
        "supported_algorithms": ["ed25519"],
        "registered_at_unix": 1_700_000_000,
        "last_seen_unix": 1_700_000_000,
    }]}), encoding="utf-8")
    return guid


def test_a_legacy_guid_phone_resolves_by_its_ref_and_by_its_guid(tmp_path: Path):
    _, pub = _key()
    guid = _seed_legacy(tmp_path, pub)
    state = StateStore(state_dir=tmp_path)
    by_guid = state.get_phone(guid)
    by_ref = state.get_phone(phone_ref_of(pub))
    assert by_guid is not None, "the legacy record did not load"
    assert by_ref is by_guid or (by_ref is not None and by_ref.phone_id == guid), (
        "a legacy phone does not answer to its phone_ref -- the registries cannot re-key onto the ref"
    )
    assert state.get_phone("pk_0000000000000000") is None, "an unknown ref resolved to something"


def test_a_legacy_phone_that_re_registers_keeps_its_guid(ctx):
    """The carding lane survives the store update: genesis_phone_id in the harness, the bridge
    config, the push-token map -- every consumer keyed on the Guid keeps working, because the
    re-registration of the same key is the SAME record under the SAME id."""
    key, pub = _key()
    guid = _seed_legacy(ctx["state_dir"], pub)
    ctx["state"]._load()  # the fixture's store was created before the seed; reload as a restart would

    status, body = _register(ctx, key, pub, label="pixel (re-verified on 1.1.0)")
    assert status == 201, body
    assert body["phone_id"] == guid, (
        "a legacy phone re-registering was given a new id -- every lane keyed on its Guid just went dark"
    )
    assert body["phone_ref"] == phone_ref_of(pub)
    phones = ctx["state"].list_phones()
    assert [p.phone_id for p in phones] == [guid]
    assert phones[0].device_label == "pixel (re-verified on 1.1.0)"
    assert phones[0].registered_at_unix == 1_700_000_000, "the first pairing's date is the record's"

    # and it survives a restart: the file on disk carries one record under the Guid
    reloaded = StateStore(state_dir=ctx["state_dir"])
    assert [p.phone_id for p in reloaded.list_phones()] == [guid]
