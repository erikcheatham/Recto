"""An unreadable member must never report as an absent one.

    "NOTHING IS SEALED" and "WHAT IS SEALED CANNOT BE READ" ARE OPPOSITE FACTS.

The first says: you have not done the thing yet. The second says: you did it,
and something is wrong. An operator told the first when the second is true
concludes the vault is empty and starts over -- which is the single action that
destroys what was still recoverable.

Both commands an operator would reach for after an error are covered, because
the dangerous one is the SECOND: seeing "nothing is sealed", the natural next
move is `seal-passphrase`, and the old reseal guard would have read the slot as
free and overwritten the damaged member without a word.

THE POSITIVE CONTROL IS `test_a_genuinely_empty_vault_still_says_nothing_is_sealed`
-- without it, code that shouted "UNREADABLE" at everything would pass the rest.
"""

from __future__ import annotations

import io
import json
import pathlib
import types

import pytest

import recto.cli as cli
from recto.bootloader.state import StateStore

KIND = "passphrase"
PHRASE = "correct horse battery staple ridge lantern copper meadow"


def _members_file(d) -> pathlib.Path:
    return pathlib.Path(d) / "genesis_members.json"


def _damaged(d, body: dict) -> StateStore:
    _members_file(d).write_text(json.dumps(body), encoding="utf-8")
    return StateStore(state_dir=pathlib.Path(d))


@pytest.fixture
def run(tmp_path, monkeypatch):
    """(verify, seal) -> (rc, out, err), prompts driven without a TTY."""
    args = types.SimpleNamespace(state_dir=str(tmp_path), force=False)

    def verify(phrase=PHRASE):
        monkeypatch.setattr(cli, "_prompt_passphrase", lambda label: phrase)
        out, err = io.StringIO(), io.StringIO()
        return cli._cmd_vault_verify_passphrase(args, out=out, err=err), out.getvalue(), err.getvalue()

    def seal(phrase=PHRASE, force=False):
        q = [phrase, phrase]
        monkeypatch.setattr(cli, "_prompt_passphrase", lambda label: q.pop(0))
        monkeypatch.setattr("builtins.input", lambda *a, **k: "SEAL")
        args.force = force
        out, err = io.StringIO(), io.StringIO()
        return cli._cmd_vault_seal_passphrase(args, out=out, err=err), out.getvalue(), err.getvalue()

    return verify, seal


# ---------------------------------------------------------------------------
# THE POSITIVE CONTROL
# ---------------------------------------------------------------------------

def test_a_genuinely_empty_vault_still_says_nothing_is_sealed(run):
    verify, _ = run
    rc, _, err = verify()
    assert rc == 2
    assert "No passphrase member is sealed" in err
    assert "UNREADABLE" not in err


# ---------------------------------------------------------------------------
# THE DISTINCTION
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body,why", [
    ({"members": {KIND: {"pubkey": "00" * 32, "algorithm": "ecdsa-p256"}}},
     "length contradicts the recorded algorithm"),
    ({"members": {KIND: "nothexatall"}}, "pubkey is not valid hex"),
    ({"members": {KIND: 42}}, "entry is the wrong type"),
])
def test_a_damaged_member_reports_UNREADABLE_not_absent(tmp_path, monkeypatch, body, why):
    _damaged(tmp_path, body)
    args = types.SimpleNamespace(state_dir=str(tmp_path), force=False)
    monkeypatch.setattr(cli, "_prompt_passphrase", lambda label: PHRASE)
    out, err = io.StringIO(), io.StringIO()
    rc = cli._cmd_vault_verify_passphrase(args, out=out, err=err)
    err = err.getvalue()

    assert rc == 3, f"{why}: expected the unreadable exit code"
    assert "UNREADABLE" in err
    assert "NOT an empty vault" in err
    assert "No passphrase member is sealed" not in err, "reported as absent"


def test_an_unparseable_file_is_also_UNREADABLE_not_absent(tmp_path, monkeypatch):
    """The FILE being corrupt is not an empty vault either."""
    _members_file(tmp_path).write_text("{not json", encoding="utf-8")
    args = types.SimpleNamespace(state_dir=str(tmp_path), force=False)
    monkeypatch.setattr(cli, "_prompt_passphrase", lambda label: PHRASE)
    out, err = io.StringIO(), io.StringIO()
    assert cli._cmd_vault_verify_passphrase(args, out=out, err=err) == 3
    assert "unparseable" in err.getvalue()


# ---------------------------------------------------------------------------
# THE DANGEROUS ONE: THE NEXT COMMAND AN OPERATOR WOULD RUN
# ---------------------------------------------------------------------------

def test_sealing_over_a_DAMAGED_member_is_refused(tmp_path, monkeypatch):
    """**THE ONE THAT TURNS A RECOVERABLE PROBLEM INTO A PERMANENT ONE.**

    The old guard asked `get_genesis_member(...) is None`. A damaged member
    reads as None, so the slot looked free and the seal would have proceeded --
    overwriting the stored bytes with no warning, on the exact command an
    operator reaches for after being told nothing is sealed.
    """
    before = json.dumps({"members": {KIND: {"pubkey": "00" * 32, "algorithm": "ecdsa-p256"}}})
    _members_file(tmp_path).write_text(before, encoding="utf-8")

    args = types.SimpleNamespace(state_dir=str(tmp_path), force=False)
    q = [PHRASE, PHRASE]
    monkeypatch.setattr(cli, "_prompt_passphrase", lambda label: q.pop(0))
    monkeypatch.setattr("builtins.input", lambda *a, **k: "SEAL")
    out, err = io.StringIO(), io.StringIO()
    rc = cli._cmd_vault_seal_passphrase(args, out=out, err=err)
    err = err.getvalue()

    assert rc == 3
    assert "cannot be loaded" in err and "would overwrite it" in err
    assert _members_file(tmp_path).read_text(encoding="utf-8") == before, \
        "a refused seal still overwrote the damaged member"


def test_force_still_allows_deliberate_replacement(tmp_path, monkeypatch):
    """The refusal must be a guard, not a wall -- an operator who has decided
    the stored member is lost needs a way through."""
    _members_file(tmp_path).write_text(
        json.dumps({"members": {KIND: {"pubkey": "00" * 32, "algorithm": "ecdsa-p256"}}}),
        encoding="utf-8",
    )
    args = types.SimpleNamespace(state_dir=str(tmp_path), force=True)
    q = [PHRASE, PHRASE]
    monkeypatch.setattr(cli, "_prompt_passphrase", lambda label: q.pop(0))
    monkeypatch.setattr("builtins.input", lambda *a, **k: "SEAL")
    out, err = io.StringIO(), io.StringIO()
    assert cli._cmd_vault_seal_passphrase(args, out=out, err=err) == 0, err.getvalue()
    assert StateStore(state_dir=pathlib.Path(tmp_path)).get_genesis_member(KIND) is not None


# ---------------------------------------------------------------------------
# THE STORE-LEVEL CONTRACT
# ---------------------------------------------------------------------------

def test_one_damaged_member_does_not_hide_the_readable_ones(tmp_path):
    """A corrupt entry must not deny access to the rest of the set during a
    recovery -- it is recorded, not allowed to cascade."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    good = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    state = _damaged(tmp_path, {"members": {
        "passphrase": {"pubkey": good.hex(), "algorithm": "ed25519"},
        "recovery": {"pubkey": "00" * 32, "algorithm": "ecdsa-p256"},
    }})
    assert set(state.list_genesis_members_full()) == {"passphrase"}
    assert set(state.list_unreadable_genesis_members()) == {"recovery"}


def test_a_healthy_vault_reports_no_unreadable_members(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    state = StateStore(state_dir=pathlib.Path(tmp_path))
    state.put_genesis_member(
        KIND, Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "ed25519"
    )
    assert state.list_unreadable_genesis_members() == {}
