"""Tests for `recto vault bootstrap` and `recto vault status` CLI
subcommands (Phase 5 Wave C part 4).

Each test invokes ``recto.cli.main`` with the relevant argv and a
captured stdout/stderr, then asserts on exit code + on the
filesystem state under a temp state-dir.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from recto.cli import main


def _fixture_pubkey_hex() -> str:
    """64-byte deterministic fixture (X || Y), hex-encoded.
    Not a real secp256k1 point -- the CLI doesn't validate curve
    membership.
    """
    return bytes(range(64)).hex()


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------


class TestVaultBootstrap:
    def test_happy_path_writes_vault_root(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["vault", "bootstrap", _fixture_pubkey_hex(),
             "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        # vault_root.json present + contains the expected pubkey.
        path = tmp_path / "vault_root.json"
        assert path.exists()
        body = json.loads(path.read_text(encoding="utf-8"))
        assert body["operator_pubkey_hex"] == _fixture_pubkey_hex()
        assert "stored_at_unix" in body
        # Stdout reports the path + pubkey for the operator.
        out_text = out.getvalue()
        assert "bootstrapped" in out_text
        assert _fixture_pubkey_hex() in out_text

    def test_accepts_0x_prefix(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["vault", "bootstrap", "0x" + _fixture_pubkey_hex(),
             "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 0
        body = json.loads((tmp_path / "vault_root.json").read_text())
        assert body["operator_pubkey_hex"] == _fixture_pubkey_hex()

    def test_accepts_file_path_argument(self, tmp_path: Path) -> None:
        # Write the hex to a file; pass the file path.
        hex_file = tmp_path / "operator_pubkey.txt"
        hex_file.write_text(_fixture_pubkey_hex(), encoding="utf-8")
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["vault", "bootstrap", str(hex_file),
             "--state-dir", str(state_dir)],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        body = json.loads((state_dir / "vault_root.json").read_text())
        assert body["operator_pubkey_hex"] == _fixture_pubkey_hex()

    def test_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        # First bootstrap.
        rc = main(
            ["vault", "bootstrap", _fixture_pubkey_hex(),
             "--state-dir", str(tmp_path)],
            stdout=io.StringIO(), stderr=io.StringIO(),
        )
        assert rc == 0
        # Second bootstrap with a DIFFERENT pubkey, no --force.
        new_hex = bytes(range(64, 128)).hex()
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["vault", "bootstrap", new_hex, "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "already bootstrapped" in err.getvalue()
        # Original pubkey unchanged.
        body = json.loads((tmp_path / "vault_root.json").read_text())
        assert body["operator_pubkey_hex"] == _fixture_pubkey_hex()

    def test_force_overwrites(self, tmp_path: Path) -> None:
        # First bootstrap.
        main(
            ["vault", "bootstrap", _fixture_pubkey_hex(),
             "--state-dir", str(tmp_path)],
            stdout=io.StringIO(), stderr=io.StringIO(),
        )
        # Force-overwrite with a different pubkey.
        new_hex = bytes(range(64, 128)).hex()
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["vault", "bootstrap", new_hex,
             "--state-dir", str(tmp_path), "--force"],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        body = json.loads((tmp_path / "vault_root.json").read_text())
        assert body["operator_pubkey_hex"] == new_hex

    def test_rejects_wrong_length_hex(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["vault", "bootstrap", "ab" * 32,  # 32-byte (64 chars), not 64-byte
             "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 2
        assert "128 hex chars" in err.getvalue()

    def test_rejects_invalid_hex(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["vault", "bootstrap", "z" * 128,  # right length, not hex
             "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 2
        assert "invalid hex" in err.getvalue()


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestVaultStatus:
    def test_reports_unbootstrapped(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["vault", "status", "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 0
        out_text = out.getvalue()
        assert "NOT bootstrapped" in out_text
        assert "recto vault bootstrap" in out_text

    def test_reports_bootstrapped_with_pubkey(self, tmp_path: Path) -> None:
        # Bootstrap first.
        main(
            ["vault", "bootstrap", _fixture_pubkey_hex(),
             "--state-dir", str(tmp_path)],
            stdout=io.StringIO(), stderr=io.StringIO(),
        )
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["vault", "status", "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 0
        out_text = out.getvalue()
        assert "bootstrapped" in out_text
        assert _fixture_pubkey_hex() in out_text

    def test_reports_corrupt_file(self, tmp_path: Path) -> None:
        # Manually create a malformed vault_root.json.
        (tmp_path / "vault_root.json").write_text(
            json.dumps({"unrelated": "garbage"}),
            encoding="utf-8",
        )
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["vault", "status", "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "unreadable" in err.getvalue()
