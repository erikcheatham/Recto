"""GATE 5b (OBSERVE) -- deriving a bootloader id from the operator key set.

WHAT THIS PASS DOES AND DELIBERATELY DOES NOT DO. It adds `derive_bootloader_id`
and logs, at startup, what the derivation WOULD produce beside what is actually
configured. It changes NO behaviour: the live `bootloader_id` is still whatever
config supplies (or a random UUID). Nothing verifies the derived value yet.

WHY THE DERIVATION MATTERS. `bootloader_id` is the JWT audience -- `verify_jwt(
..., audience=cfg.bootloader_id)`. Configured or random, it is A NAME THE PHONE
IS TOLD. A look-alike deployment at any hostname can claim any id and the phone
will sign against it. DERIVED, the id becomes A CLAIM THE PHONE CAN CHECK: the
phone recomputes it from the key set it can see, and a mismatch is arithmetic
rather than the operator noticing a URL looks off.

That is also why the hostname question dissolved (operator, 2026-08-18): the app
carries no compiled-in host at all, so the right target was never "which name" --
it is that the phone should not trust a name.

THE POSITIVE CONTROL IS `test_a_normal_operator_key_derives_a_wellformed_id`.
Most tests below assert a REFUSAL, an inequality, or an invariant, and a
`derive_bootloader_id` that raised on everything -- or returned a constant --
would satisfy several of them. Without a test that an ordinary key produces an
ordinary, correctly-shaped id, this file cannot tell "the derivation is sound"
from "the derivation is broken in a way that happens to look strict".
"""

from __future__ import annotations

import logging

import pytest

from recto.bootloader.server import (
    BOOTLOADER_ID_DERIVATION_V1,
    BOOTLOADER_ID_PREFIX,
    IDENTITY_MEMBER_KINDS,
    ChallengeStore,
    collect_identity_member_pubkeys,
    create_server,
    derive_bootloader_id,
)
from recto.bootloader.state import StateStore

OPERATOR = bytes(range(64))
MEMBER = bytes((b + 7) % 256 for b in OPERATOR)


# --------------------------------------------------------------------------
# THE POSITIVE CONTROL -- read this one first.
# --------------------------------------------------------------------------

def test_a_normal_operator_key_derives_a_wellformed_id():
    """The ordinary case. If this fails, every assertion below is meaningless."""
    got = derive_bootloader_id(OPERATOR)
    assert got.startswith(BOOTLOADER_ID_PREFIX), got
    hexpart = got[len(BOOTLOADER_ID_PREFIX):]
    assert len(hexpart) == 32, f"expected 128 bits of hex, got {len(hexpart)}"
    assert all(c in "0123456789abcdef" for c in hexpart), got
    # Deterministic: same input, same answer, every call.
    assert derive_bootloader_id(OPERATOR) == got


# --------------------------------------------------------------------------
# THE CROSS-LANGUAGE CONTRACT
# --------------------------------------------------------------------------

def test_the_cross_language_parity_pin():
    """THE PHONE MUST RECOMPUTE THIS, AND THE PHONE IS C#.

    This pin is the contract between the Python bootloader and any
    reimplementation. It follows the pattern the repo already uses for the pair
    deep link (recto/qr/pair.py CANONICAL_DEMO_PAIR_URL + its C# sister test).

    IF A C# IMPLEMENTATION DISAGREES WITH THIS VALUE, THE C# IS WRONG -- OR THE
    DERIVATION CHANGED AND ITS VERSION STRING WAS NOT BUMPED. Do not repair a
    parity failure by editing the pin; that converts a caught drift into a
    silent one.
    """
    assert derive_bootloader_id(OPERATOR) == "rb1-1f344bc9162a781dff78b772d05c17e4"
    assert derive_bootloader_id(OPERATOR, [MEMBER]) == (
        "rb1-340247a518af7a52e22f56f9f88bff5e"
    )


def test_the_version_string_is_part_of_the_hash():
    """Domain separation, ISOLATED TO THE ONE VARIABLE.

    FIRST DRAFT OF THIS TEST WAS VACUOUS AND THE RED-BUILD CAUGHT IT. It
    compared against a bare `sha256(OPERATOR)`, which differs from the real
    digest for TWO reasons -- no version string AND no length prefix -- so it
    stayed green even with the version string deleted. A test that passes for a
    reason other than the one it names is not evidence.

    This version reconstructs the digest with the length prefix INTACT and only
    the version string removed, so a mismatch can mean nothing else.
    """
    import hashlib
    h = hashlib.sha256()                       # no version string
    h.update(len(OPERATOR).to_bytes(4, "big"))  # length prefix KEPT
    h.update(OPERATOR)
    unversioned = BOOTLOADER_ID_PREFIX + h.hexdigest()[:32]
    assert derive_bootloader_id(OPERATOR) != unversioned, (
        "the version string is not being mixed in -- a v2 derivation could "
        "not be distinguished from a v1 one"
    )
    assert BOOTLOADER_ID_DERIVATION_V1 == "recto-bootloader-id-v1"


# --------------------------------------------------------------------------
# THE THREE PROPERTIES
# --------------------------------------------------------------------------

def test_derivation_is_order_independent():
    """The id depends on the SET, not on enumeration order.

    Enumeration order is not stable across state backends (file vs postgres).
    If order mattered, migrating the backend would silently change the
    bootloader's identity and invalidate every outstanding token.
    """
    a = derive_bootloader_id(OPERATOR, [b"alpha", b"beta"])
    b = derive_bootloader_id(OPERATOR, [b"beta", b"alpha"])
    assert a == b


def test_duplicate_members_do_not_change_the_id():
    """A set, not a list. Enrolling the same key twice is not a new identity."""
    assert derive_bootloader_id(OPERATOR, [MEMBER]) == \
           derive_bootloader_id(OPERATOR, [MEMBER, MEMBER])


def test_length_prefixing_prevents_concatenation_ambiguity():
    """{AB, C} and {A, BC} must NOT hash alike.

    Without a length prefix they concatenate to the same bytes. That is a
    genuine forgery primitive: two different key sets sharing one identity.
    """
    assert derive_bootloader_id(OPERATOR, [b"AB", b"C"]) != \
           derive_bootloader_id(OPERATOR, [b"A", b"BC"])


def test_a_different_operator_gives_a_different_id():
    assert derive_bootloader_id(OPERATOR) != derive_bootloader_id(MEMBER)


def test_adding_a_member_changes_the_id():
    """This is WHY the genesis set must be sealed rather than recomputed from
    live registrations -- see the observe-log comment in create_server. Every
    enrolment would otherwise rotate the JWT audience and invalidate every
    outstanding token."""
    assert derive_bootloader_id(OPERATOR) != derive_bootloader_id(OPERATOR, [MEMBER])


# --------------------------------------------------------------------------
# REFUSAL
# --------------------------------------------------------------------------

@pytest.mark.parametrize("empty", [None, b""])
def test_an_unsealed_bootloader_has_no_derived_identity(empty):
    """Returning a plausible-looking id for an unsealed bootloader would be
    worse than refusing: it would be an identity derived from nothing, which
    a phone could then 'verify' against nothing."""
    with pytest.raises(ValueError) as exc:
        derive_bootloader_id(empty)
    assert "no operator pubkey" in str(exc.value)


# --------------------------------------------------------------------------
# THE OBSERVE PASS CHANGES NOTHING -- this is the point of the whole gate
# --------------------------------------------------------------------------

def test_a_configured_id_is_IGNORED_when_the_vault_is_sealed(tmp_path, caplog):
    """THE FLIP (2026-08-19). A CONTRACT CHANGED HERE, DELIBERATELY.

    This test was previously named
    `test_observe_logs_the_comparison_without_changing_the_live_id`, and it
    asserted, verbatim:

        assert BootloaderHandler.config.bootloader_id == configured, (
            "GATE 5b is observe-only and must not replace the configured id"
        )

    **That was correct for the observe pass and is now forbidden.** It is
    rewritten rather than deleted so the record shows a contract CHANGED -- a
    vanished test looks like a test that never existed.

    WHY IGNORING BEATS REFUSING HERE, since GATE 5a refuses in a similar shape:
    5a had TWO candidates for one slot, so picking either left a launcher able
    to probe. **Here there is only one candidate.** The id is a function of the
    sealed key; a configured `bootloader_id` is not a competing value, it is a
    value with nowhere to go. Making the setting INERT is stronger than
    refusing to start on it -- and it lets the flip ship without a coordinated
    compose change.

    NOTE this uses caplog and so proves the line is LOGGED, not EMITTED. GATE 0c
    is what makes it reach a handler in production. Stating the limit so a green
    run is not over-read -- that exact gap cost twelve hours on 2026-08-17.
    """
    state = StateStore(state_dir=tmp_path)
    state.put_operator_pubkey(OPERATOR)
    configured = "a-name-somebody-chose"
    derived = derive_bootloader_id(OPERATOR)

    with caplog.at_level(logging.INFO, logger="recto.bootloader.identity"):
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=state,
            bootloader_id=configured, challenges=ChallengeStore(),
            ssl_context=None,
        )
    try:
        from recto.bootloader.server import BootloaderHandler
        assert BootloaderHandler.config.bootloader_id == derived, (
            "the sealed key set did not become the live identity"
        )
        assert BootloaderHandler.config.bootloader_id != configured, (
            "a configured name is still winning -- the flip did not take"
        )
        # getMessage() applies the args; r.message is the already-rendered form
        # and re-applying args to it raises. Use the accessor, not the field.
        joined = " ".join(r.getMessage() for r in caplog.records)
        assert "IGNORED" in joined, (
            f"an ignored config value must be reported, not silently dropped: "
            f"{joined!r}"
        )
        assert configured in joined and derived in joined, (
            "the warning must name BOTH -- someone debugging a phone that "
            "stopped verifying needs to see the old name and the new identity"
        )
        assert any(
            r.levelno >= logging.WARNING for r in caplog.records
        ), "a disagreeing config is inert, not harmless -- it must WARN"
    finally:
        try:
            server.server_close()
        except Exception:
            pass


def test_an_AGREEING_config_is_not_reported_as_a_problem(tmp_path, caplog):
    """Redundancy is not disagreement. A launcher restating the derived id is
    harmless and must not produce a warning -- otherwise the warning becomes
    noise and stops being read."""
    state = StateStore(state_dir=tmp_path)
    state.put_operator_pubkey(OPERATOR)
    derived = derive_bootloader_id(OPERATOR)

    with caplog.at_level(logging.INFO, logger="recto.bootloader.identity"):
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=state,
            bootloader_id=derived, challenges=ChallengeStore(),
            ssl_context=None,
        )
    try:
        from recto.bootloader.server import BootloaderHandler
        assert BootloaderHandler.config.bootloader_id == derived
        assert not any(r.levelno >= logging.WARNING for r in caplog.records), (
            "restating the derived id is redundant, not hostile"
        )
    finally:
        try:
            server.server_close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# THE SET HALF -- sealed identity members join the derivation
# --------------------------------------------------------------------------

RECOVERY_PUBKEY = bytes(range(32))
PASSPHRASE_PUBKEY = bytes(reversed(range(32)))


def test_the_identity_allowlist_splits_device_from_quorum(tmp_path):
    """recovery-phone is identity; passphrase is quorum-only.

    The bootloader's id answers "which bootloader is this" and derives from
    the DEVICE set. The passphrase answers "who may authorise" (tier 3) and
    deliberately does not rename the bootloader when sealed.
    """
    assert "recovery-phone" in IDENTITY_MEMBER_KINDS
    assert "passphrase" not in IDENTITY_MEMBER_KINDS
    state = StateStore(state_dir=tmp_path)
    state.put_genesis_member("passphrase", PASSPHRASE_PUBKEY)
    state.put_genesis_member("recovery-phone", RECOVERY_PUBKEY)
    identity, excluded = collect_identity_member_pubkeys(
        state.list_genesis_members_full()
    )
    assert identity == [RECOVERY_PUBKEY]
    assert excluded == ["passphrase"]


def test_enrolling_a_recovery_phone_changes_the_live_id(tmp_path):
    """The enrolment birth property: the 'new bootloader' is born when the
    set changes -- by arithmetic, not by anyone renaming anything."""
    state = StateStore(state_dir=tmp_path)
    state.put_operator_pubkey(OPERATOR)
    state.put_genesis_member("recovery-phone", RECOVERY_PUBKEY)
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state,
        challenges=ChallengeStore(), ssl_context=None,
    )
    try:
        from recto.bootloader.server import BootloaderHandler
        live = BootloaderHandler.config.bootloader_id
        assert live == derive_bootloader_id(OPERATOR, [RECOVERY_PUBKEY])
        assert live != derive_bootloader_id(OPERATOR), (
            "the sealed recovery phone did not enter the identity derivation"
        )
    finally:
        try:
            server.server_close()
        except Exception:
            pass


def test_a_sealed_passphrase_does_NOT_change_the_id(tmp_path):
    """No identity churn from quorum membership: the id with a sealed
    passphrase equals the operator-only id. This is what lets the phrase be
    sealed before genesis without renaming the bootloader at the next
    deploy."""
    state = StateStore(state_dir=tmp_path)
    state.put_operator_pubkey(OPERATOR)
    state.put_genesis_member("passphrase", PASSPHRASE_PUBKEY)
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state,
        challenges=ChallengeStore(), ssl_context=None,
    )
    try:
        from recto.bootloader.server import BootloaderHandler
        assert BootloaderHandler.config.bootloader_id == \
               derive_bootloader_id(OPERATOR)
    finally:
        try:
            server.server_close()
        except Exception:
            pass


def test_the_identity_inputs_snapshot_recomputes_to_the_live_id(tmp_path):
    """The registration payload's promise: id and inputs never disagree.

    Decode the snapshotted inputs exactly as a phone would and re-derive;
    the result must equal the live id. A snapshot that drifts from the id it
    claims to explain would teach phones to distrust the mechanism."""
    import base64

    def _unb64u(s: str) -> bytes:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)

    state = StateStore(state_dir=tmp_path)
    state.put_operator_pubkey(OPERATOR)
    state.put_genesis_member("recovery-phone", RECOVERY_PUBKEY)
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state,
        challenges=ChallengeStore(), ssl_context=None,
    )
    try:
        from recto.bootloader.server import BootloaderHandler
        inputs = BootloaderHandler.config.bootloader_identity_inputs
        assert inputs is not None
        assert inputs["derivation"] == BOOTLOADER_ID_DERIVATION_V1
        recomputed = derive_bootloader_id(
            _unb64u(inputs["operator_pubkey_b64u"]),
            [_unb64u(k) for k in inputs["member_pubkeys_b64u"]],
        )
        assert recomputed == BootloaderHandler.config.bootloader_id
    finally:
        try:
            server.server_close()
        except Exception:
            pass


def test_an_unsealed_bootloader_emits_no_identity_inputs(tmp_path):
    """No derived id, no claim: the inputs snapshot must be None so the
    registration field is omitted rather than describing an id that was
    never derived."""
    state = StateStore(state_dir=tmp_path)  # nothing sealed
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state,
        bootloader_id="unsealed", challenges=ChallengeStore(), ssl_context=None,
    )
    try:
        from recto.bootloader.server import BootloaderHandler
        assert BootloaderHandler.config.bootloader_identity_inputs is None
    finally:
        try:
            server.server_close()
        except Exception:
            pass


def test_observe_never_breaks_a_start_when_there_is_nothing_to_derive(tmp_path):
    """An unsealed bootloader must still START. The derivation refuses, the
    observation warns, and startup continues -- an observation pass that could
    take down a boot would be a worse defect than the one it is measuring."""
    state = StateStore(state_dir=tmp_path)  # no operator pubkey sealed
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state,
        bootloader_id="unsealed-still-starts", challenges=ChallengeStore(),
        ssl_context=None,
    )
    try:
        from recto.bootloader.server import BootloaderHandler
        assert BootloaderHandler.config.bootloader_id == "unsealed-still-starts"
    finally:
        try:
            server.server_close()
        except Exception:
            pass
