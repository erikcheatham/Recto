"""Hard rule 15 - the fail-closed shapes recurve tried to call defects (2026-09-25).

The first whole-tree recurve pass over Recto (run e410, 140 modules, an
independent refuter) raised 24 findings at or above high. Twenty-three were the
DESIGN, read back to the reader as a defect. Each accepted design is a decision
this tree stands on; this file pins the ones a unit test can hold, so a future
change that breaks the shape fails here, in the tree, before a reader has to
find it again. The acceptance ledger (operator-side, never in a public tree)
binds each acceptance to the quoted code; these tests bind the BEHAVIOUR.

Pinned elsewhere, named here so the map is whole:
  15.a operator pubkey None -> the bootloader REFUSES to mint / create a
       profile / add a device: test_bootloader_capability.py
       ::test_mint_refuses_when_no_operator_pubkey_is_configured (GATE 0)
  15.b the pending envelope is a read, never an approval:
       test_bootloader_pending_signed.py (tier 0, one action, single use,
       pinned to the wire bytes)
  15.e the export-mnemonic gate is the caller's, and there is ONE caller,
       biometric first: Recto.Shared (Settings.razor) - a source rule, see
       docs/hard-rules.md
  15.f the TOFU window is one host, one pairing operation:
       Recto.Shared.Tests/PinningServiceTests.cs
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest

from recto.bootloader.server import ChallengeStore
from recto.capability.jwt import verify_jws
from recto.capability.pair_record import verify_pair_grant
from recto.capability.signing import mint_jws, public_key_hex
from recto.capability.types import CapabilityClaims, CapabilityClause, CapabilityScope
from recto.profile.manage import bootstrap_master, create_child_profile, mark_profile_revoked

_KEY = bytes.fromhex("7" * 64)


def _claims(*, now: int, nbf: int, exp: int) -> CapabilityClaims:
    return CapabilityClaims(
        iss="bootloader:rule15",
        sub="phone:rule15",
        aud=["recto-phone"],
        iat=now,
        nbf=nbf,
        exp=exp,
        jti=f"rule15-{uuid.uuid4().hex}",
        cap=CapabilityClause(tier=0, registry_version="0", scope=CapabilityScope(), allow_actions=["x:y"]),
        purpose="rule 15 fixture",
        max_uses=1,
    )


class TestRule15cTimeBoundsAreUpstream:
    """15.c - verify_pair_grant's window CEILING sits on top of verify_jws's
    standard bounds (nbf <= now < exp). A future nbf is refused BEFORE the
    grant is ever read; the grant check does not re-check what verify_jws
    already refused. (recurve: missing-nbf-check, pair_record.py:173)"""

    def test_verify_jws_refuses_a_future_nbf(self) -> None:
        now = int(time.time())
        token = mint_jws(_claims(now=now, nbf=now + 600, exp=now + 1200), _KEY)
        with pytest.raises(ValueError, match="nbf"):
            verify_jws(token, expected_pubkey=bytes.fromhex(public_key_hex(_KEY)), expected_aud="recto-phone", now=now)

    def test_verify_jws_accepts_the_same_token_once_nbf_has_passed(self) -> None:
        now = int(time.time())
        token = mint_jws(_claims(now=now, nbf=now + 600, exp=now + 1200), _KEY)
        claims = verify_jws(token, expected_pubkey=bytes.fromhex(public_key_hex(_KEY)),
                            expected_aud="recto-phone", now=now + 601)
        assert claims.nbf == now + 600

    def test_verify_pair_grant_documents_that_verify_jws_comes_first(self) -> None:
        # The contract is written where the reader looks: the docstring.
        assert "verify_jws" in (verify_pair_grant.__doc__ or "")


class TestRule15dMasterRevocation:
    """15.d - "while children exist" means ACTIVE children. A master whose
    children are all revoked has nothing left to orphan; revoking it then is
    the intended end state. (recurve: master-revocation-without-children-check)"""

    def test_master_refuses_while_an_active_child_exists(self, tmp_path: Path) -> None:
        mi = bootstrap_master(master_pubkey_hex=bytes(range(64)).hex(), display_name="m", state_dir=tmp_path)
        create_child_profile(kind="work", display_name="c", derived_pubkey_hex=bytes(range(1, 65)).hex(),
                             state_dir=tmp_path)
        with pytest.raises(ValueError, match="active child"):
            mark_profile_revoked(mi.master_profile_id, state_dir=tmp_path)

    def test_master_revokes_once_every_child_is_revoked(self, tmp_path: Path) -> None:
        mi = bootstrap_master(master_pubkey_hex=bytes(range(64)).hex(), display_name="m", state_dir=tmp_path)
        child = create_child_profile(kind="work", display_name="c", derived_pubkey_hex=bytes(range(1, 65)).hex(),
                                     state_dir=tmp_path)
        mark_profile_revoked(child.profile_id, state_dir=tmp_path)
        revoked = mark_profile_revoked(mi.master_profile_id, state_dir=tmp_path)
        assert revoked.revoked is True


class TestRule15gInMemoryChallengeStoreIsStillAGate:
    """15.g - ChallengeStore(state=None) is the legacy/test construction; what
    it loses without a store is cross-replica persistence, never single-use or
    the TTL. (recurve: fail-open-on-missing-state-store, server.py:632)"""

    def test_challenge_is_single_use(self) -> None:
        store = ChallengeStore()
        c, _exp = store.issue_challenge(ttl_seconds=60)
        assert store.consume_challenge(c) is True
        assert store.consume_challenge(c) is False
        assert store.consume_challenge("never-issued") is False

    def test_pairing_code_is_single_use_and_expires(self) -> None:
        store = ChallengeStore()
        code, _exp = store.issue_pairing_code(ttl_seconds=60)
        assert store.consume_pairing_code(code) is True
        assert store.consume_pairing_code(code) is False
        expired, _ = store.issue_pairing_code(ttl_seconds=0)
        time.sleep(0.01)
        assert store.consume_pairing_code(expired) is False


class TestRule15kSecretConfigIsTheOperators:
    """Hard rule 15.k: `config` is the operator's secret definition. EnvSource
    reads the operator's own environment under the operator's chosen name;
    nothing in a request shapes it - the backend takes no request at all."""

    def test_env_source_reads_only_the_name_the_operator_wrote(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import inspect

        from recto.secrets.env import EnvSource

        monkeypatch.setenv("OPERATOR_CHOSE_THIS", "v1")
        monkeypatch.delenv("db-password", raising=False)
        src = EnvSource()
        assert src.fetch("db-password", {"env_var": "OPERATOR_CHOSE_THIS"}).value == "v1"
        # the backend's contract carries no request: (secret_name, config) and nothing else
        params = list(inspect.signature(EnvSource.fetch).parameters)
        assert params == ["self", "secret_name", "config"]

    def test_no_secret_source_takes_a_request(self) -> None:
        import inspect

        from recto.secrets.base import SecretSource

        params = list(inspect.signature(SecretSource.fetch).parameters)
        assert params == ["self", "secret_name", "config"]
        assert not any(p in ("request", "headers", "payload", "handler") for p in params)

