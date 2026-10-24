"""GATE 5a -- the operator pubkey in config cannot silently replace the sealed one.

THE TAKEOVER THIS CLOSES, and it needed no stolen device. Until 2026-08-18
`create_server` read:

    if capability_operator_pubkey is None:
        capability_operator_pubkey = state.get_operator_pubkey()

with the comment *"Explicit kwarg still wins -- backward compat for deployments
that pass the pubkey directly."* The SEALED value in `vault_root.json` was a
FALLBACK. `capability_operator_pubkey` is constructor config, re-read on every
start, so a launcher passing a different key replaced the trust root silently:
no signature, no chain entry, no trace, no restart barrier. **Whoever controlled
the deploy controlled the operator.**

The brief's ruling (S OPERATOR IMMUTABILITY, operator 2026-08-17) is exact: *"On
disagreement between config and sealed state the bootloader REFUSES TO START.
Disagreement is fatal, never an update."*

WHAT THIS IS NOT. It is not all of GATE 5. `bootloader_id` is not yet derived
from the operator key set, and the tier-3 membership test is not built. The
1-of-N revoke takeover via `/v0.4/manage/phones/revoke` REMAINS OPEN -- a single
stolen device can still revoke the legitimate one. This closes the deploy-side
path only; do not read a green run as GATE 5 closed.

THE THIRD MEMBER ALREADY EXISTS AND IT IS NOT HARDWARE. Two devices cannot give
both theft-resistance and loss-resistance -- that part is arithmetic. The
resolution is the PASSPHRASE (operator ruling 2026-08-17): eight diceware words,
Argon2id to a keypair, pubkey sealed at genesis, and it signs through this same
`verify_signature` path. It is not a device, so it cannot be taken along with
the phone, and the written copy has never shared a location with the recovery
device. Tier-3 is a membership test over RECOVERY + PASSPHRASE carrying two
signatures. Older text naming a hardware token as the third member predates that
ruling and is superseded.

THE POSITIVE CONTROL IS `test_a_sealed_bootloader_starts_normally`. Three of
these assert a refusal or a warning, and a `create_server` broken in any way
would satisfy all three. Without a test that a LEGITIMATE start still works,
this file cannot tell "the gate holds" from "nothing starts".
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

import pytest

from recto.bootloader.server import BootloaderError, ChallengeStore, create_server
from recto.bootloader.state import StateStore

SEALED = bytes(range(64))                       # the legitimate operator
IMPOSTOR = bytes((b + 7) % 256 for b in SEALED)  # a launcher-supplied stranger


def _serve(tmp_path: Path, *, sealed: bytes | None, config_key: bytes | None):
    """Build a bootloader with a given sealed value and a given config kwarg.

    Returns the server (caller must close) or raises whatever create_server
    raises. The two inputs are the entire experiment: what the vault holds, and
    what the launcher claims.
    """
    state = StateStore(state_dir=tmp_path)
    if sealed is not None:
        state.put_operator_pubkey(sealed)
    kwargs = {}
    if config_key is not None:
        kwargs["capability_operator_pubkey"] = config_key
    return create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="immutability-test-bootloader",
        challenges=ChallengeStore(),
        ssl_context=None,
        **kwargs,
    )


def _close(server) -> None:
    try:
        server.server_close()
    except Exception:
        pass


# --------------------------------------------------------------------------
# THE POSITIVE CONTROL -- read this one first.
# --------------------------------------------------------------------------

def test_a_sealed_bootloader_starts_normally(tmp_path: Path):
    """A sealed vault and no kwarg is the ordinary production case.

    If this fails, every refusal below is meaningless -- a create_server that
    rejects everything would pass them all.
    """
    server = _serve(tmp_path, sealed=SEALED, config_key=None)
    try:
        from recto.bootloader.server import BootloaderHandler
        assert BootloaderHandler.config.capability_operator_pubkey == SEALED, (
            "the sealed value did not become the live trust root"
        )
    finally:
        _close(server)


def test_config_that_AGREES_with_the_seal_is_accepted(tmp_path: Path):
    """Agreement is not disagreement. A launcher restating the sealed value is
    redundant, not hostile, and must not be treated as an attack."""
    server = _serve(tmp_path, sealed=SEALED, config_key=SEALED)
    try:
        from recto.bootloader.server import BootloaderHandler
        assert BootloaderHandler.config.capability_operator_pubkey == SEALED
    finally:
        _close(server)


# --------------------------------------------------------------------------
# THE GATE
# --------------------------------------------------------------------------

def test_config_that_DISAGREES_with_the_seal_refuses_to_start(tmp_path: Path):
    """THE TAKEOVER PATH. RED-BUILD: restore `if capability_operator_pubkey is
    None` as the only branch and this starts happily under the impostor key."""
    with pytest.raises(BootloaderError) as exc:
        _serve(tmp_path, sealed=SEALED, config_key=IMPOSTOR)
    msg = str(exc.value)
    assert "REFUSING TO START" in msg
    assert SEALED.hex()[:16] in msg and IMPOSTOR.hex()[:16] in msg, (
        "the refusal must name BOTH values -- an operator debugging this at "
        f"3am needs to see which is which: {msg}"
    )


def test_the_refusal_does_not_silently_prefer_either_side(tmp_path: Path):
    """A 'safe' fallback here would be the whole defect wearing a fix's clothes.

    Preferring the seal would look secure and would leave a launcher able to
    probe. Preferring config is the original hole. The ONLY correct behaviour
    is refusing to run at all, so nothing is left listening on either key.
    """
    with pytest.raises(BootloaderError):
        _serve(tmp_path, sealed=SEALED, config_key=IMPOSTOR)
    # Nothing bound, nothing serving, no trust root chosen. The absence of a
    # running server IS the assertion; a started server under either key fails
    # the test above by not raising.


def test_unsealed_plus_config_is_allowed_but_warns_loudly(tmp_path: Path, caplog):
    """First boot before `recto vault bootstrap` -- legitimate, never quiet.

    NOTE this test uses caplog and therefore proves the record is LOGGED, not
    that it is EMITTED. GATE 0c is what makes it reach a handler in production;
    see tests/test_bootloader_connections.py for the emission test. Stating the
    limit here so a green run is not over-read -- that gap cost twelve hours on
    2026-08-17.
    """
    with caplog.at_level(logging.WARNING, logger="recto.bootloader.operator"):
        server = _serve(tmp_path, sealed=None, config_key=SEALED)
    try:
        joined = " ".join(r.message for r in caplog.records)
        assert "NO SEALED VALUE" in joined, (
            f"an unsealed trust root started without saying so: {joined!r}"
        )
        assert "vault bootstrap" in joined, "the warning must name the remedy"
    finally:
        _close(server)
