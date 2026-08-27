"""Tests for Phase 5 Wave C part 4: persistent operator pubkey trust root.

Two layers:

1. ``StateStore.put_operator_pubkey`` / ``get_operator_pubkey`` /
   ``is_vault_bootstrapped`` round-trip + persistence across a
   fresh StateStore on the same state_dir.

2. ``create_server`` fallback: when ``capability_operator_pubkey``
   kwarg is None and ``vault_root.json`` exists in the state dir,
   the bootloader's config picks up the persisted value
   automatically.

The CLI-side tests for ``recto vault bootstrap`` /
``recto vault status`` live in ``tests/test_cli_vault.py`` so this
module can stay state-store-focused.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from recto.bootloader.server import (
    BootloaderError,
    BootloaderHandler,
    ChallengeStore,
    create_server,
)
from recto.bootloader.state import StateStore


# ---------------------------------------------------------------------------
# StateStore: put / get / is_vault_bootstrapped round-trip
# ---------------------------------------------------------------------------


class TestOperatorPubkeyStateStore:
    @pytest.fixture
    def store(self, tmp_path: Path) -> StateStore:
        return StateStore(state_dir=tmp_path)

    @staticmethod
    def _fixture_pubkey() -> bytes:
        # 64-byte deterministic fixture (X || Y form). Not a real
        # secp256k1 point; the StateStore doesn't validate curve
        # membership -- that's the verifier's concern.
        return bytes(range(64))

    def test_get_returns_none_before_bootstrap(self, store: StateStore) -> None:
        assert store.get_operator_pubkey() is None
        assert store.is_vault_bootstrapped() is False

    def test_put_then_get_round_trips(self, store: StateStore) -> None:
        pk = self._fixture_pubkey()
        store.put_operator_pubkey(pk)
        assert store.is_vault_bootstrapped() is True
        got = store.get_operator_pubkey()
        assert got == pk

    def test_put_overwrites(self, store: StateStore) -> None:
        store.put_operator_pubkey(self._fixture_pubkey())
        new_pk = bytes(range(63, -1, -1))  # different 64-byte value
        store.put_operator_pubkey(new_pk)
        assert store.get_operator_pubkey() == new_pk

    def test_put_rejects_wrong_length(self, store: StateStore) -> None:
        with pytest.raises(ValueError, match="64 bytes"):
            store.put_operator_pubkey(b"\x00" * 32)
        with pytest.raises(ValueError, match="64 bytes"):
            store.put_operator_pubkey(b"\x00" * 65)
        with pytest.raises(ValueError, match="64 bytes"):
            store.put_operator_pubkey(b"")

    def test_persistence_survives_fresh_store(self, tmp_path: Path) -> None:
        s1 = StateStore(state_dir=tmp_path)
        pk = self._fixture_pubkey()
        s1.put_operator_pubkey(pk)
        # Fresh store on same dir should re-read from vault_root.json.
        s2 = StateStore(state_dir=tmp_path)
        assert s2.is_vault_bootstrapped() is True
        assert s2.get_operator_pubkey() == pk

    def test_corrupt_vault_root_returns_none(self, tmp_path: Path) -> None:
        """If vault_root.json is present but malformed, get returns
        None (rather than crashing)."""
        s = StateStore(state_dir=tmp_path)
        # Write a vault_root.json without the expected structure.
        (tmp_path / "vault_root.json").write_text(
            json.dumps({"unrelated": "garbage"}), encoding="utf-8",
        )
        assert s.is_vault_bootstrapped() is True  # file exists
        assert s.get_operator_pubkey() is None  # but unreadable

    def test_invalid_hex_returns_none(self, tmp_path: Path) -> None:
        s = StateStore(state_dir=tmp_path)
        (tmp_path / "vault_root.json").write_text(
            json.dumps({"operator_pubkey_hex": "not-hex-at-all"}),
            encoding="utf-8",
        )
        assert s.get_operator_pubkey() is None


# ---------------------------------------------------------------------------
# create_server fallback to persisted pubkey
# ---------------------------------------------------------------------------


class TestCreateServerFallback:
    @staticmethod
    def _fixture_pubkey() -> bytes:
        return bytes(range(64))

    def test_explicit_kwarg_that_DISAGREES_is_refused(
        self, tmp_path: Path
    ) -> None:
        """GATE 5a, 2026-08-18. THE CONTRACT INVERTED, and the old one is worth
        reading before the new one.

        This test was named `test_explicit_kwarg_wins_over_persisted` and its
        body carried the comment:

            # Persist one pubkey...
            # ...but pass a different one as the kwarg. Explicit wins.

        It asserted that a launcher argument may REPLACE a sealed trust root,
        and it passed for as long as it existed. That is the operator-takeover
        path stated as a specification: `capability_operator_pubkey` is
        constructor config re-read on every start, so whoever controlled the
        deploy controlled the operator -- unsigned, unchained, untraced.

        RULED (operator, 2026-08-17): *"On disagreement between config and
        sealed state the bootloader REFUSES TO START. Disagreement is fatal,
        never an update."*

        REWRITTEN RATHER THAN DELETED. Removing it would erase the fact that a
        contract changed; a reader six months from now should be able to see
        that this behaviour was once intended and is now forbidden. The two
        sibling tests below are UNAFFECTED -- sealed-with-no-kwarg and
        neither-present both still hold, which is what makes this a narrowing
        of the contract rather than a rewrite of it.
        """
        s = StateStore(state_dir=tmp_path)
        s.put_operator_pubkey(self._fixture_pubkey())
        explicit = bytes(range(64, 128))  # 64 bytes, values 64..127
        with pytest.raises(BootloaderError) as exc:
            create_server(
                bind_host="127.0.0.1", bind_port=0, state=s,
                bootloader_id="t", challenges=ChallengeStore(),
                ssl_context=None,
                capability_operator_pubkey=explicit,
            )
        assert "REFUSING TO START" in str(exc.value)

    def test_persisted_used_when_kwarg_none(self, tmp_path: Path) -> None:
        s = StateStore(state_dir=tmp_path)
        s.put_operator_pubkey(self._fixture_pubkey())
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=s,
            bootloader_id="t", challenges=ChallengeStore(),
            ssl_context=None,
            # capability_operator_pubkey not passed
        )
        try:
            assert BootloaderHandler.config.capability_operator_pubkey == self._fixture_pubkey()
        finally:
            server.server_close()

    def test_none_when_neither_kwarg_nor_persisted(
        self, tmp_path: Path
    ) -> None:
        s = StateStore(state_dir=tmp_path)
        # No bootstrap, no kwarg.
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=s,
            bootloader_id="t", challenges=ChallengeStore(),
            ssl_context=None,
        )
        try:
            assert BootloaderHandler.config.capability_operator_pubkey is None
        finally:
            server.server_close()
