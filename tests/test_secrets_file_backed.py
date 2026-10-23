"""Tests for the file-backed SecretSource (container-viable connection store)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from recto.secrets.base import (
    DirectSecret,
    SecretNotFoundError,
    SecretSourceError,
)
from recto.secrets.file_backed import FileBackedSecretSource


class TestName:
    def test_name_is_file_backed(self, tmp_path: Path) -> None:
        assert FileBackedSecretSource("MyService", tmp_path).name == "file-backed"


class TestWriteFetchRoundTrip:
    def test_write_then_fetch_returns_value(self, tmp_path: Path) -> None:
        src = FileBackedSecretSource("MyService", tmp_path)
        src.write("conn.podcast_index", "super-secret-value")
        result = src.fetch("conn.podcast_index", {})
        assert isinstance(result, DirectSecret)
        assert result.value == "super-secret-value"

    def test_write_persists_to_disk_under_service_dir(self, tmp_path: Path) -> None:
        FileBackedSecretSource("MyService", tmp_path).write("conn.x", "v")
        path = tmp_path / "MyService" / "conn.x.json"
        assert path.is_file()
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["value"] == "v"
        assert "updated_at_unix" in payload

    def test_write_stores_comment(self, tmp_path: Path) -> None:
        FileBackedSecretSource("MyService", tmp_path).write("conn.x", "v", "a note")
        payload = json.loads((tmp_path / "MyService" / "conn.x.json").read_text())
        assert payload["comment"] == "a note"

    def test_overwrite_replaces_value(self, tmp_path: Path) -> None:
        src = FileBackedSecretSource("MyService", tmp_path)
        src.write("conn.x", "first")
        src.write("conn.x", "second")
        assert src.fetch("conn.x", {}).value == "second"

    def test_two_services_are_isolated(self, tmp_path: Path) -> None:
        a = FileBackedSecretSource("MyService", tmp_path)
        b = FileBackedSecretSource("OtherService", tmp_path)
        a.write("conn.x", "alpha")
        b.write("conn.x", "bravo")
        assert a.fetch("conn.x", {}).value == "alpha"
        assert b.fetch("conn.x", {}).value == "bravo"

    def test_non_string_value_rejected(self, tmp_path: Path) -> None:
        src = FileBackedSecretSource("MyService", tmp_path)
        with pytest.raises(SecretSourceError):
            src.write("conn.x", 123)  # type: ignore[arg-type]


class TestFetchMissing:
    def test_missing_raises_when_required(self, tmp_path: Path) -> None:
        src = FileBackedSecretSource("MyService", tmp_path)
        with pytest.raises(SecretNotFoundError):
            src.fetch("conn.nope", {})

    def test_missing_default_is_required(self, tmp_path: Path) -> None:
        # fetch with empty config still treats missing as fatal
        src = FileBackedSecretSource("MyService", tmp_path)
        with pytest.raises(SecretNotFoundError):
            src.fetch("conn.nope", {})

    def test_missing_returns_empty_when_not_required(self, tmp_path: Path) -> None:
        src = FileBackedSecretSource("MyService", tmp_path)
        result = src.fetch("conn.nope", {"required": False})
        assert isinstance(result, DirectSecret)
        assert result.value == ""

    def test_corrupt_blob_raises_source_error(self, tmp_path: Path) -> None:
        d = tmp_path / "MyService"
        d.mkdir(parents=True)
        (d / "conn.bad.json").write_text("{ not json", encoding="utf-8")
        with pytest.raises(SecretSourceError):
            FileBackedSecretSource("MyService", tmp_path).fetch("conn.bad", {})

    def test_blob_missing_value_key_raises(self, tmp_path: Path) -> None:
        d = tmp_path / "MyService"
        d.mkdir(parents=True)
        (d / "conn.bad.json").write_text('{"comment":"x"}', encoding="utf-8")
        with pytest.raises(SecretSourceError):
            FileBackedSecretSource("MyService", tmp_path).fetch("conn.bad", {})


class TestDelete:
    def test_delete_removes_file(self, tmp_path: Path) -> None:
        src = FileBackedSecretSource("MyService", tmp_path)
        src.write("conn.x", "v")
        src.delete("conn.x")
        assert not (tmp_path / "MyService" / "conn.x.json").exists()
        with pytest.raises(SecretNotFoundError):
            src.fetch("conn.x", {})

    def test_delete_missing_is_idempotent(self, tmp_path: Path) -> None:
        # no raise on deleting a secret that was never written
        FileBackedSecretSource("MyService", tmp_path).delete("conn.never")


class TestPathTraversalDefense:
    @pytest.mark.parametrize("bad", ["..", "../escape", "a/b", "a\\b", "."])
    def test_traversal_secret_name_rejected(self, tmp_path: Path, bad: str) -> None:
        src = FileBackedSecretSource("MyService", tmp_path)
        with pytest.raises(SecretSourceError):
            src.write(bad, "v")
        with pytest.raises(SecretSourceError):
            src.fetch(bad, {})

    @pytest.mark.parametrize("bad", ["..", "a/b", "a\\b", ""])
    def test_traversal_service_name_rejected(self, tmp_path: Path, bad: str) -> None:
        with pytest.raises(SecretSourceError):
            FileBackedSecretSource(bad, tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX file-mode assertions")
class TestPosixPermissions:
    def test_secret_file_is_owner_only(self, tmp_path: Path) -> None:
        FileBackedSecretSource("MyService", tmp_path).write("conn.x", "v")
        mode = stat.S_IMODE((tmp_path / "MyService" / "conn.x.json").stat().st_mode)
        assert mode == 0o600

    def test_service_dir_is_owner_only(self, tmp_path: Path) -> None:
        FileBackedSecretSource("MyService", tmp_path).write("conn.x", "v")
        mode = stat.S_IMODE((tmp_path / "MyService").stat().st_mode)
        assert mode == 0o700


class TestRepr:
    def test_directsecret_repr_is_redacted(self, tmp_path: Path) -> None:
        src = FileBackedSecretSource("MyService", tmp_path)
        src.write("conn.x", "leak-me-not")
        result = src.fetch("conn.x", {})
        assert "leak-me-not" not in repr(result)
        assert "redacted" in repr(result).lower()
