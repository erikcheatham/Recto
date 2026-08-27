"""GATE 5c-b -- the genesis entry path for the passphrase member.

WHAT THESE TESTS ARE ACTUALLY PROTECTING. Not "does the command work" but:

    THE OPERATOR MUST NOT BE ABLE TO SEAL A MEMBER HE CANNOT REPRODUCE.

Every failure mode here is silent by nature. A mistyped phrase derives a
perfectly valid key, seals without complaint, and reports success. The gap
between that moment and the moment it matters can be years.

THE POSITIVE CONTROL IS `test_seal_then_verify_round_trips`. Most tests below
assert a REFUSAL, and a pair of commands that refused everything would satisfy
them all.
"""

from __future__ import annotations

import builtins
import io
import pathlib
import types

import pytest

import recto.cli as cli
from recto.bootloader.state import StateStore

PHRASE = "correct horse battery staple ridge lantern copper meadow"
OTHER = "eight totally different words go right here now ok"
KIND = "passphrase"


@pytest.fixture
def sealer(tmp_path, monkeypatch):
    """Drive the prompts without a TTY. Returns (run_seal, run_verify, state)."""
    args = types.SimpleNamespace(state_dir=str(tmp_path), force=False)

    def run_seal(entries, confirm="SEAL", force=False):
        q = list(entries)
        monkeypatch.setattr(cli, "_prompt_passphrase", lambda label: q.pop(0))
        monkeypatch.setattr(builtins, "input", lambda *a, **k: confirm)
        args.force = force
        out, err = io.StringIO(), io.StringIO()
        rc = cli._cmd_vault_seal_passphrase(args, out=out, err=err)
        return rc, out.getvalue(), err.getvalue()

    def run_verify(entry):
        q = [entry]
        monkeypatch.setattr(cli, "_prompt_passphrase", lambda label: q.pop(0))
        out, err = io.StringIO(), io.StringIO()
        rc = cli._cmd_vault_verify_passphrase(args, out=out, err=err)
        return rc, out.getvalue(), err.getvalue()

    return run_seal, run_verify, StateStore(state_dir=pathlib.Path(tmp_path))


# --------------------------------------------------------------------------
# THE POSITIVE CONTROL
# --------------------------------------------------------------------------

def test_seal_then_verify_round_trips(sealer):
    seal, verify, state = sealer
    rc, out, _ = seal([PHRASE, PHRASE])
    assert rc == 0, out
    assert "SEALED" in out
    assert state.get_genesis_member(KIND) is not None

    rc, out, _ = verify(PHRASE)
    assert rc == 0 and "MATCHES" in out


# --------------------------------------------------------------------------
# THE PHRASE ITSELF NEVER LEAVES THE PROMPT
# --------------------------------------------------------------------------

def test_the_phrase_is_never_printed_or_persisted(sealer, tmp_path):
    """**THE ONE THAT WOULD BE UNRECOVERABLE IF IT REGRESSED.**

    A phrase echoed to stdout lands in a scroll buffer, a screen share, a
    terminal log. A phrase written to disk is simply the secret, stored. Only
    the PUBLIC key may be emitted or persisted.
    """
    seal, _, _ = sealer
    rc, out, err = seal([PHRASE, PHRASE])
    assert rc == 0
    assert PHRASE not in out and PHRASE not in err
    for word in PHRASE.split():
        assert word not in out, f"a phrase word reached stdout: {word}"

    for path in pathlib.Path(tmp_path).rglob("*"):
        if path.is_file():
            blob = path.read_bytes()
            assert PHRASE.encode() not in blob, f"phrase written to {path.name}"
            for word in PHRASE.split():
                assert word.encode() not in blob, f"{word!r} written to {path.name}"


def test_the_command_REJECTS_a_phrase_passed_as_an_argument():
    """argv is visible in `ps` to every user on the box and is recorded by most
    shells, so the phrase must have no way in except the no-echo prompt.

    **THIS TEST WAS ORIGINALLY A SKIP** -- it looked for a parser factory that
    did not exist and passed by not running, on the same day three other
    vacuous checks were found. It now builds the real parser and asserts the
    refusal. `vault bootstrap` takes its pubkey positionally, which is correct
    there (a pubkey is public) and would be catastrophic here.
    """
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["vault", "seal-passphrase", PHRASE])
    with pytest.raises(SystemExit):
        parser.parse_args(["vault", "verify-passphrase", PHRASE])
    # POSITIVE CONTROL: the same parser accepts the legitimate invocations,
    # so the SystemExits above are the positional being rejected and not the
    # subcommand simply being unreachable.
    assert parser.parse_args(["vault", "seal-passphrase"]).vault_command == "seal-passphrase"
    assert parser.parse_args(["vault", "verify-passphrase"]).vault_command == "verify-passphrase"


# --------------------------------------------------------------------------
# REFUSALS -- each one is a silent disaster prevented
# --------------------------------------------------------------------------

def test_mismatched_entries_seal_nothing(sealer):
    """A slip caught. Nothing must be written on the way to the refusal."""
    seal, _, state = sealer
    rc, _, err = seal([PHRASE, PHRASE.replace("meadow", "meadows")])
    assert rc == 2 and "differ" in err
    assert state.get_genesis_member(KIND) is None, "a refused seal still wrote"


def test_declining_the_confirmation_seals_nothing(sealer):
    seal, _, state = sealer
    rc, _, err = seal([PHRASE, PHRASE], confirm="yes")
    assert rc == 2 and "Not sealed" in err
    assert state.get_genesis_member(KIND) is None


def test_dice_rolls_are_refused_at_the_prompt(sealer):
    """The confusion the operator surfaced on 2026-08-19, at the exact place
    it would have been made."""
    seal, _, state = sealer
    rolls = "41533 24261 11256 63421 52134 31627 45512 16334"
    rc, _, err = seal([rolls, rolls])
    assert rc == 2 and "DICE ROLLS" in err
    assert state.get_genesis_member(KIND) is None


def test_resealing_is_refused_without_force(sealer):
    """Resealing orphans whatever trusted the old member. It must be a
    deliberate act, not a re-run of the same command."""
    seal, _, state = sealer
    assert seal([PHRASE, PHRASE])[0] == 0
    first = state.get_genesis_member(KIND)

    rc, _, err = seal([OTHER, OTHER])
    assert rc == 2 and "already sealed" in err
    assert state.get_genesis_member(KIND) == first, "a refused reseal overwrote"

    assert seal([OTHER, OTHER], force=True)[0] == 0
    assert state.get_genesis_member(KIND) != first


# --------------------------------------------------------------------------
# THE DRILL
# --------------------------------------------------------------------------

def test_verify_reports_failure_without_hinting(sealer):
    """No partial match, no which-word, no oracle.

    A helpful hint here would let anyone with host access narrow the phrase one
    word at a time. Failure reports only that it failed -- and points at the
    paper rather than the software, because that is where the fault will be.
    """
    seal, verify, _ = sealer
    assert seal([PHRASE, PHRASE])[0] == 0
    rc, out, err = verify(OTHER)
    assert rc == 1
    assert "DOES NOT MATCH" in err
    assert "Check the paper" in err
    for word in PHRASE.split():
        assert word not in err, "the failure message leaked a sealed word"


def test_verify_before_any_seal_says_so(sealer):
    _, verify, _ = sealer
    rc, _, err = verify(PHRASE)
    assert rc == 2 and "No passphrase member is sealed" in err


def test_verify_never_writes(sealer, tmp_path):
    """The drill must be safe to run at any time, including from a cold
    recovery where the operator is not sure what state anything is in."""
    seal, verify, _ = sealer
    assert seal([PHRASE, PHRASE])[0] == 0
    before = {p: p.read_bytes() for p in pathlib.Path(tmp_path).rglob("*") if p.is_file()}
    verify(PHRASE)
    verify(OTHER)
    after = {p: p.read_bytes() for p in pathlib.Path(tmp_path).rglob("*") if p.is_file()}
    assert before == after, "verify-passphrase mutated the vault"
