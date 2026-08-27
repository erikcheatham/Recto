"""Tests for recto.cli.

The CLI is a thin dispatcher; tests inject stubs for every external
dependency (credman, NSSM, launcher, prompt) so we exercise the
argparse + dispatch + error-handling logic without touching real
systems.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from recto import cli
from recto.config import ServiceConfig
from recto.nssm import (
    NssmConfig,
    NssmError,
    NssmNotInstalledError,
    NssmServiceNotFoundError,
    NssmStatus,
)
from recto.secrets import (
    CredManSource,
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
    SecretSourceError,
)


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class FakeCredManSource(CredManSource):
    """In-memory CredManSource for CLI tests.

    Mirrors the FakeCredManSource pattern from
    tests/test_secrets_credman.py: uses platform_check=False to bypass
    the Windows-only guard, then overrides the four `_*_blob` methods
    to back them with a shared dict.
    """

    def __init__(self, service: str, store: dict[str, str]) -> None:
        super().__init__(service, platform_check=False)
        self._store = store

    def _read_blob(self, target: str) -> str:
        if target not in self._store:
            raise SecretNotFoundError(target)
        return self._store[target]

    def _write_blob(self, target: str, value: str, comment: str = "") -> None:
        self._store[target] = value

    def _delete_blob(self, target: str) -> None:
        if target not in self._store:
            raise SecretNotFoundError(target)
        del self._store[target]

    def _list_targets(self, filter_pattern: str) -> list[str]:
        # Simple wildcard support: prefix-match before the trailing '*'.
        if filter_pattern.endswith("*"):
            prefix = filter_pattern[:-1]
            return [t for t in self._store if t.startswith(prefix)]
        return [t for t in self._store if t == filter_pattern]


class FakeNssmClient:
    """NssmClient stand-in for migrate / status tests.

    Holds a mutable NssmConfig snapshot and tracks set/reset calls so
    the test can assert on what migrate-from-nssm wrote back.
    """

    def __init__(
        self,
        *,
        config: NssmConfig | None = None,
        status_value: str = NssmStatus.SERVICE_STOPPED,
        not_installed: bool = False,
        not_found: bool = False,
    ) -> None:
        self.config = config
        self.status_value = status_value
        self.not_installed = not_installed
        self.not_found = not_found
        self.set_calls: list[tuple[str, str, str]] = []
        self.reset_calls: list[tuple[str, str]] = []

    def status(self, service: str) -> str:
        if self.not_installed:
            raise NssmNotInstalledError("nssm.exe missing")
        return self.status_value

    def get_all(self, service: str) -> NssmConfig:
        if self.not_installed:
            raise NssmNotInstalledError("nssm.exe missing")
        if self.not_found or self.config is None:
            raise NssmServiceNotFoundError(f"{service!r} not found")
        return self.config

    def set(self, service: str, field: str, value: str) -> None:
        self.set_calls.append((service, field, value))

    def reset(self, service: str, field: str) -> None:
        self.reset_calls.append((service, field))

    def get(self, service: str, field_name: str, *subparams: str) -> str:
        """Mirror the production NssmClient.get() interface so callers
        like _detect_user_objectname_mismatch() (which reads ObjectName
        per-service to detect SYSTEM-vs-user CredMan mismatches) can
        exercise their code path through tests. Compound parameters
        like AppExit / AppEvents take subparams; the simple flat
        parameters used in tests don't.

        Reads from the NssmConfig snapshot the fake was constructed
        with; falls back to "" for any field the snapshot doesn't
        explicitly carry, mirroring NssmClient's behavior of returning
        empty string for unset parameters."""
        if self.not_installed:
            raise NssmNotInstalledError("nssm.exe missing")
        if self.not_found or self.config is None:
            raise NssmServiceNotFoundError(f"{service!r} not found")
        # Map common flat fields off the NssmConfig dataclass. The fake
        # only needs to cover what tests actually read; production
        # NssmClient handles the full surface via subprocess.
        flat_field_map = {
            "Application":         self.config.app_path,
            "AppPath":             self.config.app_path,  # legacy name for the same field
            "AppParameters":       self.config.app_parameters,
            "AppDirectory":        self.config.app_directory,
            "DisplayName":         getattr(self.config, "display_name", "") or "",
            "Description":         getattr(self.config, "description", "") or "",
            "ObjectName":          getattr(self.config, "object_name", "") or "",
            "Start":               getattr(self.config, "start_type", "") or "",
            "AppEnvironmentExtra": "\r\n".join(self.config.app_environment_extra),
        }
        return flat_field_map.get(field_name, "")


def _capture() -> tuple[io.StringIO, io.StringIO]:
    """Return (stdout_buf, stderr_buf)."""
    return io.StringIO(), io.StringIO()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_launch_subcommand_parses(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["launch", "service.yaml"])
        assert args.command == "launch"
        assert args.yaml_path == "service.yaml"
        assert args.once is False

    def test_launch_once_flag(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["launch", "service.yaml", "--once"])
        assert args.once is True

    def test_credman_set_with_value_flag(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            ["credman", "set", "myservice", "MY_KEY", "--value", "the-value"]
        )
        assert args.command == "credman"
        assert args.credman_command == "set"
        assert args.service == "myservice"
        assert args.name == "MY_KEY"
        assert args.value == "the-value"

    def test_credman_list(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["credman", "list", "myservice"])
        assert args.credman_command == "list"
        assert args.service == "myservice"

    def test_credman_delete(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["credman", "delete", "myservice", "MY_KEY"])
        assert args.credman_command == "delete"
        assert args.service == "myservice"
        assert args.name == "MY_KEY"

    def test_status(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["status", "myservice"])
        assert args.command == "status"
        assert args.service == "myservice"

    def test_migrate_with_yaml_out_and_dry_run(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            [
                "migrate-from-nssm",
                "myservice",
                "--yaml-out",
                "out.yaml",
                "--dry-run",
            ]
        )
        assert args.command == "migrate-from-nssm"
        assert args.service == "myservice"
        assert args.yaml_out == "out.yaml"
        assert args.dry_run is True

    def test_no_subcommand_errors(self) -> None:
        parser = cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])


# ---------------------------------------------------------------------------
# launch subcommand
# ---------------------------------------------------------------------------


def _make_yaml(tmp_path: Path) -> Path:
    yaml_path = tmp_path / "service.yaml"
    yaml_path.write_text(
        "apiVersion: recto/v1\n"
        "kind: Service\n"
        "metadata:\n"
        "  name: myservice\n"
        "spec:\n"
        "  exec: python.exe\n",
        encoding="utf-8",
    )
    return yaml_path


class TestLaunchCommand:
    def test_launch_dispatches_to_run_by_default(self, tmp_path: Path) -> None:
        yaml_path = _make_yaml(tmp_path)
        captured: dict[str, Any] = {}

        def fake_launch(config: ServiceConfig, **_kw: Any) -> int:
            captured["config"] = config
            return 0

        out, err = _capture()
        rc = cli.main(
            ["launch", str(yaml_path)],
            launch_fn=fake_launch,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert captured["config"].metadata.name == "myservice"

    def test_launch_returns_child_returncode(self, tmp_path: Path) -> None:
        yaml_path = _make_yaml(tmp_path)
        out, err = _capture()
        rc = cli.main(
            ["launch", str(yaml_path)],
            launch_fn=lambda _cfg, **_kw: 42,
            stdout=out,
            stderr=err,
        )
        assert rc == 42

    def test_launch_missing_file_returns_1(self, tmp_path: Path) -> None:
        out, err = _capture()
        rc = cli.main(
            ["launch", str(tmp_path / "does-not-exist.yaml")],
            launch_fn=lambda _cfg, **_kw: 0,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "not found" in err.getvalue()

    def test_launch_invalid_yaml_returns_1(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "apiVersion: WRONG\nkind: WRONG\nmetadata: {}\nspec: {}",
            encoding="utf-8",
        )
        out, err = _capture()
        rc = cli.main(
            ["launch", str(bad)],
            launch_fn=lambda _cfg, **_kw: 0,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "invalid config" in err.getvalue()


# ---------------------------------------------------------------------------
# credman subcommands
# ---------------------------------------------------------------------------


class TestCredmanSet:
    def test_set_with_value_flag_writes_to_credman(self) -> None:
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "set", "myservice", "MY_KEY", "--value", "the-value"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert store["recto:myservice:MY_KEY"] == "the-value"
        assert "installed" in out.getvalue()

    def test_set_prompts_for_value_when_not_provided(self) -> None:
        store: dict[str, str] = {}
        prompts_seen: list[str] = []

        def fake_prompt(p: str) -> str:
            prompts_seen.append(p)
            return "from-prompt"

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "set", "myservice", "MY_KEY"],
            credman_factory=factory,
            prompt=fake_prompt,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert store["recto:myservice:MY_KEY"] == "from-prompt"
        assert len(prompts_seen) == 1
        assert "MY_KEY" in prompts_seen[0]
        # The prompt SHOULD mention 'hidden' so the operator knows nothing's echoed.
        assert "hidden" in prompts_seen[0].lower()

    def test_set_empty_prompt_value_refuses(self) -> None:
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "set", "myservice", "MY_KEY"],
            credman_factory=factory,
            prompt=lambda _p: "",  # user just hit enter
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "empty" in err.getvalue().lower()
        assert "recto:myservice:MY_KEY" not in store

    def test_set_explicit_empty_value_via_flag_is_allowed(self) -> None:
        # Operator explicitly passing --value "" is "I really mean empty".
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "set", "myservice", "MY_KEY", "--value", ""],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert store["recto:myservice:MY_KEY"] == ""


class TestCredmanList:
    def test_list_empty(self) -> None:
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "list", "myservice"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert out.getvalue() == ""

    def test_list_returns_only_matching_service(self) -> None:
        # Multiple services in the store; list should only print the
        # ones scoped to the requested service name.
        store = {
            "recto:myservice:KEY_A": "a",
            "recto:myservice:KEY_B": "b",
            "recto:other:KEY_C": "c",
        }

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "list", "myservice"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        lines = out.getvalue().strip().splitlines()
        assert lines == ["KEY_A", "KEY_B"]


class TestCredmanDelete:
    def test_delete_removes_existing_entry(self) -> None:
        store = {"recto:myservice:KEY": "val"}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "delete", "myservice", "KEY"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert "recto:myservice:KEY" not in store
        assert "deleted" in out.getvalue()

    def test_delete_missing_returns_1(self) -> None:
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "delete", "myservice", "KEY"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "does not exist" in err.getvalue()


# ---------------------------------------------------------------------------
# secrets list subcommand (Papercut #2)
# ---------------------------------------------------------------------------


class _StubListableSource:
    """Tiny SecretSource-ish stand-in for the secrets-list backend
    iteration test. Doesn't subclass SecretSource because we don't
    care about the abstract-method contract for this test -- we only
    care that the registry layer can call list_names() on it."""

    def __init__(self, names: list[str]) -> None:
        self._names = list(names)

    @property
    def name(self) -> str:
        return "stub"

    def fetch(self, secret_name: str, config: dict[str, Any]):
        raise NotImplementedError

    def list_names(self) -> list[str]:
        return list(self._names)


class _StubNonListableSource:
    """SecretSource without list_names -- e.g. EnvSource. The
    secrets-list iteration should silently skip these."""

    @property
    def name(self) -> str:
        return "stub-no-list"

    def fetch(self, secret_name: str, config: dict[str, Any]):
        raise NotImplementedError


class TestSecretsListCommand:
    """Papercut #2: `recto secrets list <service>` walks every
    registered SecretSource backend and prefixes each entry with
    `[<backend>]`. Pre-fix `recto credman list` only saw the
    per-user credman store, so dpapi-machine secrets were invisible."""

    def _swap_registry(self, mapping: dict[str, Any]) -> dict[str, Any]:
        """Replace the global registry with `mapping` and return the
        original so the test can restore it in finally."""
        from recto.secrets import _SOURCE_FACTORIES

        original = dict(_SOURCE_FACTORIES)
        _SOURCE_FACTORIES.clear()
        _SOURCE_FACTORIES.update(mapping)
        return original

    def _restore_registry(self, original: dict[str, Any]) -> None:
        from recto.secrets import _SOURCE_FACTORIES

        _SOURCE_FACTORIES.clear()
        _SOURCE_FACTORIES.update(original)

    def test_lists_across_credman_and_dpapi_machine(self) -> None:
        """Both backends report names; output prefixes each line with
        the backend selector."""
        original = self._swap_registry(
            {
                "credman": lambda _svc: _StubListableSource(
                    ["MY_API_KEY", "WEBHOOK_TOKEN"]
                ),
                "dpapi-machine": lambda _svc: _StubListableSource(
                    ["MY_PUSH_TOKEN"]
                ),
            }
        )
        try:
            out, err = _capture()
            rc = cli.main(
                ["secrets", "list", "myservice"],
                stdout=out,
                stderr=err,
            )
            assert rc == 0
            lines = sorted(out.getvalue().strip().splitlines())
            assert lines == [
                "[credman] MY_API_KEY",
                "[credman] WEBHOOK_TOKEN",
                "[dpapi-machine] MY_PUSH_TOKEN",
            ]
            assert err.getvalue() == ""
        finally:
            self._restore_registry(original)

    def test_silently_skips_backends_without_list_names(self) -> None:
        """EnvSource doesn't implement list_names (the env var space
        has no enumeration primitive). Mixing it in should not raise
        and should not appear in output."""
        original = self._swap_registry(
            {
                "credman": lambda _svc: _StubListableSource(["KEY_A"]),
                "env": lambda _svc: _StubNonListableSource(),
            }
        )
        try:
            out, err = _capture()
            rc = cli.main(
                ["secrets", "list", "myservice"],
                stdout=out,
                stderr=err,
            )
            assert rc == 0
            assert out.getvalue().strip() == "[credman] KEY_A"
            # No error or warning for the non-listable backend.
            assert "env" not in err.getvalue()
        finally:
            self._restore_registry(original)

    def test_empty_inventory_returns_zero(self) -> None:
        """No backends report any names: exit 0, empty output. An
        empty inventory is valid state (a freshly migrated service
        before any secrets have been installed)."""
        original = self._swap_registry(
            {
                "credman": lambda _svc: _StubListableSource([]),
                "dpapi-machine": lambda _svc: _StubListableSource([]),
            }
        )
        try:
            out, err = _capture()
            rc = cli.main(
                ["secrets", "list", "myservice"],
                stdout=out,
                stderr=err,
            )
            assert rc == 0
            assert out.getvalue() == ""
            assert err.getvalue() == ""
        finally:
            self._restore_registry(original)

    def test_secrets_subcommand_in_parser(self) -> None:
        """Parser-level: `secrets list <service>` parses cleanly."""
        parser = cli.build_parser()
        args = parser.parse_args(["secrets", "list", "myservice"])
        assert args.command == "secrets"
        assert args.secrets_command == "list"
        assert args.service == "myservice"

    def test_credman_list_still_works(self) -> None:
        """Backward-compat: `recto credman list` is NOT removed.
        Operators with existing scripts using it keep working."""
        store = {"recto:myservice:KEY_X": "v"}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "list", "myservice"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert out.getvalue().strip() == "KEY_X"


# ---------------------------------------------------------------------------
# secrets set subcommand (backend-agnostic; default backend dpapi-machine)
# ---------------------------------------------------------------------------


class _StubWritableSource:
    """SecretSource-ish stand-in supporting write() + delete() + list_names()
    backed by a shared dict. Used to exercise `recto secrets set` and
    `recto secrets delete` without needing the real DPAPI/CredMan backends.

    The test installs this under whatever selector name the test cares
    about (`dpapi-machine` / `credman` / `stub`) via the registry-swap
    pattern from TestSecretsListCommand. The service-name parameter is
    captured so the test can assert it gets threaded through.
    """

    def __init__(self, store: dict[tuple[str, str], str], service: str) -> None:
        self._store = store
        self._service = service

    @property
    def name(self) -> str:
        return "stub-writable"

    def fetch(self, secret_name: str, config: dict[str, Any]):
        raise NotImplementedError

    def write(self, secret_name: str, value: str, comment: str = "") -> None:
        self._store[(self._service, secret_name)] = value

    def delete(self, secret_name: str) -> None:
        if (self._service, secret_name) not in self._store:
            raise SecretNotFoundError(secret_name)
        del self._store[(self._service, secret_name)]

    def list_names(self) -> list[str]:
        return sorted(
            n for (svc, n) in self._store.keys() if svc == self._service
        )


class _StubReadOnlySource:
    """SecretSource without write/delete -- e.g. a future read-only
    external-vault backend. `recto secrets set --source ...` should
    refuse to call it with a clear error rather than crashing on the
    missing attribute."""

    @property
    def name(self) -> str:
        return "stub-readonly"

    def fetch(self, secret_name: str, config: dict[str, Any]):
        raise NotImplementedError


def _swap_registry(mapping: dict[str, Any]) -> dict[str, Any]:
    """Reuse of TestSecretsListCommand's helper at module scope so the
    set/delete test classes can also swap. Returns the original snapshot
    for restoration."""
    from recto.secrets import _SOURCE_FACTORIES

    original = dict(_SOURCE_FACTORIES)
    _SOURCE_FACTORIES.clear()
    _SOURCE_FACTORIES.update(mapping)
    return original


def _restore_registry(original: dict[str, Any]) -> None:
    from recto.secrets import _SOURCE_FACTORIES

    _SOURCE_FACTORIES.clear()
    _SOURCE_FACTORIES.update(original)


class TestSecretsSetCommand:
    """`recto secrets set <service> <name>` writes to whichever backend
    `--source` selects (default: dpapi-machine). Mirror of
    `recto credman set`'s safety guards (empty-prompt refusal, --value ''
    explicit-empty allowance, etc.) but via the registry seam rather than
    a credman_factory parameter."""

    def test_set_default_source_is_dpapi_machine(self) -> None:
        store: dict[tuple[str, str], str] = {}
        original = _swap_registry(
            {
                "dpapi-machine": lambda svc: _StubWritableSource(store, svc),
                "credman": lambda svc: _StubWritableSource(
                    {("OTHER_SVC", "X"): "y"}, svc
                ),
            }
        )
        try:
            out, err = _capture()
            rc = cli.main(
                ["secrets", "set", "myservice", "MY_KEY", "--value", "the-value"],
                stdout=out,
                stderr=err,
            )
            assert rc == 0
            # Default backend is dpapi-machine, so the value lands there.
            assert store[("myservice", "MY_KEY")] == "the-value"
            assert "[dpapi-machine] installed" in out.getvalue()
        finally:
            _restore_registry(original)

    def test_set_with_explicit_source_credman(self) -> None:
        store: dict[tuple[str, str], str] = {}
        original = _swap_registry(
            {
                "credman": lambda svc: _StubWritableSource(store, svc),
            }
        )
        try:
            out, err = _capture()
            rc = cli.main(
                [
                    "secrets",
                    "set",
                    "myservice",
                    "MY_KEY",
                    "--source",
                    "credman",
                    "--value",
                    "v",
                ],
                stdout=out,
                stderr=err,
            )
            assert rc == 0
            assert store[("myservice", "MY_KEY")] == "v"
            assert "[credman] installed" in out.getvalue()
        finally:
            _restore_registry(original)

    def test_set_prompts_when_value_omitted(self) -> None:
        store: dict[tuple[str, str], str] = {}
        prompts_seen: list[str] = []

        def fake_prompt(p: str) -> str:
            prompts_seen.append(p)
            return "from-prompt"

        original = _swap_registry(
            {"dpapi-machine": lambda svc: _StubWritableSource(store, svc)}
        )
        try:
            out, err = _capture()
            rc = cli.main(
                ["secrets", "set", "myservice", "MY_KEY"],
                prompt=fake_prompt,
                stdout=out,
                stderr=err,
            )
            assert rc == 0
            assert store[("myservice", "MY_KEY")] == "from-prompt"
            assert len(prompts_seen) == 1
            assert "MY_KEY" in prompts_seen[0]
            assert "hidden" in prompts_seen[0].lower()
        finally:
            _restore_registry(original)

    def test_set_empty_prompt_refuses(self) -> None:
        store: dict[tuple[str, str], str] = {}
        original = _swap_registry(
            {"dpapi-machine": lambda svc: _StubWritableSource(store, svc)}
        )
        try:
            out, err = _capture()
            rc = cli.main(
                ["secrets", "set", "myservice", "MY_KEY"],
                prompt=lambda _p: "",  # operator just hit enter
                stdout=out,
                stderr=err,
            )
            assert rc == 1
            assert "empty" in err.getvalue().lower()
            assert ("myservice", "MY_KEY") not in store
        finally:
            _restore_registry(original)

    def test_set_explicit_empty_value_via_flag_is_allowed(self) -> None:
        store: dict[tuple[str, str], str] = {}
        original = _swap_registry(
            {"dpapi-machine": lambda svc: _StubWritableSource(store, svc)}
        )
        try:
            out, err = _capture()
            rc = cli.main(
                ["secrets", "set", "myservice", "MY_KEY", "--value", ""],
                stdout=out,
                stderr=err,
            )
            assert rc == 0
            assert store[("myservice", "MY_KEY")] == ""
        finally:
            _restore_registry(original)

    def test_set_unknown_source_returns_1(self) -> None:
        original = _swap_registry({})
        try:
            out, err = _capture()
            rc = cli.main(
                [
                    "secrets",
                    "set",
                    "myservice",
                    "MY_KEY",
                    "--source",
                    "no-such-backend",
                    "--value",
                    "v",
                ],
                stdout=out,
                stderr=err,
            )
            assert rc == 1
            assert "no-such-backend" in err.getvalue()
        finally:
            _restore_registry(original)

    def test_set_readonly_backend_returns_1(self) -> None:
        original = _swap_registry(
            {"readonly-vault": lambda _svc: _StubReadOnlySource()}
        )
        try:
            out, err = _capture()
            rc = cli.main(
                [
                    "secrets",
                    "set",
                    "myservice",
                    "MY_KEY",
                    "--source",
                    "readonly-vault",
                    "--value",
                    "v",
                ],
                stdout=out,
                stderr=err,
            )
            assert rc == 1
            assert "readonly-vault" in err.getvalue()
            assert "write" in err.getvalue().lower()
        finally:
            _restore_registry(original)

    def test_set_in_parser(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            [
                "secrets",
                "set",
                "myservice",
                "MY_KEY",
                "--source",
                "credman",
                "--value",
                "v",
            ]
        )
        assert args.command == "secrets"
        assert args.secrets_command == "set"
        assert args.service == "myservice"
        assert args.name == "MY_KEY"
        assert args.source == "credman"
        assert args.value == "v"

    def test_set_default_source_in_parser(self) -> None:
        """Parser-level: --source defaults to dpapi-machine."""
        parser = cli.build_parser()
        args = parser.parse_args(
            ["secrets", "set", "myservice", "MY_KEY", "--value", "v"]
        )
        assert args.source == "dpapi-machine"


class TestSecretsDeleteCommand:
    """`recto secrets delete <service> <name>` removes from whichever
    backend `--source` selects (default: dpapi-machine)."""

    def test_delete_removes_existing_entry(self) -> None:
        store: dict[tuple[str, str], str] = {("myservice", "KEY"): "v"}
        original = _swap_registry(
            {"dpapi-machine": lambda svc: _StubWritableSource(store, svc)}
        )
        try:
            out, err = _capture()
            rc = cli.main(
                ["secrets", "delete", "myservice", "KEY"],
                stdout=out,
                stderr=err,
            )
            assert rc == 0
            assert ("myservice", "KEY") not in store
            assert "[dpapi-machine] deleted" in out.getvalue()
        finally:
            _restore_registry(original)

    def test_delete_missing_returns_1(self) -> None:
        store: dict[tuple[str, str], str] = {}
        original = _swap_registry(
            {"dpapi-machine": lambda svc: _StubWritableSource(store, svc)}
        )
        try:
            out, err = _capture()
            rc = cli.main(
                ["secrets", "delete", "myservice", "KEY"],
                stdout=out,
                stderr=err,
            )
            assert rc == 1
            assert "does not exist" in err.getvalue()
        finally:
            _restore_registry(original)

    def test_delete_explicit_credman_source(self) -> None:
        store: dict[tuple[str, str], str] = {("myservice", "KEY"): "v"}
        original = _swap_registry(
            {"credman": lambda svc: _StubWritableSource(store, svc)}
        )
        try:
            out, err = _capture()
            rc = cli.main(
                [
                    "secrets",
                    "delete",
                    "myservice",
                    "KEY",
                    "--source",
                    "credman",
                ],
                stdout=out,
                stderr=err,
            )
            assert rc == 0
            assert ("myservice", "KEY") not in store
        finally:
            _restore_registry(original)

    def test_delete_in_parser(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            ["secrets", "delete", "myservice", "KEY", "--source", "credman"]
        )
        assert args.command == "secrets"
        assert args.secrets_command == "delete"
        assert args.service == "myservice"
        assert args.name == "KEY"
        assert args.source == "credman"


# ---------------------------------------------------------------------------
# status subcommand
# ---------------------------------------------------------------------------


class TestStatusCommand:
    def test_status_running_returns_0(self) -> None:
        nssm = FakeNssmClient(status_value=NssmStatus.SERVICE_RUNNING)
        out, err = _capture()
        rc = cli.main(
            ["status", "myservice"],
            nssm_factory=lambda: nssm,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert "SERVICE_RUNNING" in out.getvalue()

    def test_status_stopped_returns_1(self) -> None:
        nssm = FakeNssmClient(status_value=NssmStatus.SERVICE_STOPPED)
        out, err = _capture()
        rc = cli.main(
            ["status", "myservice"],
            nssm_factory=lambda: nssm,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "SERVICE_STOPPED" in out.getvalue()

    def test_status_nssm_missing_returns_1(self) -> None:
        nssm = FakeNssmClient(not_installed=True)
        out, err = _capture()
        rc = cli.main(
            ["status", "myservice"],
            nssm_factory=lambda: nssm,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "nssm" in err.getvalue().lower()


# ---------------------------------------------------------------------------
# migrate-from-nssm subcommand
# ---------------------------------------------------------------------------


def _example_nssm_config(service: str = "svc") -> NssmConfig:
    return NssmConfig(
        service=service,
        app_path="C:\\python.exe",
        app_parameters="C:\\app\\main.py --foo",
        app_directory="C:\\app",
        app_environment_extra=("API_KEY=secret123", "DB_URL=postgres://x"),
        display_name="My Service",
    )


class TestMigrateFromNssm:
    def test_dry_run_makes_no_changes(self, tmp_path: Path) -> None:
        nssm = FakeNssmClient(config=_example_nssm_config())
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            [
                "migrate-from-nssm",
                "svc",
                "--yaml-out",
                str(tmp_path / "svc.yaml"),
                "--dry-run",
            ],
            nssm_factory=lambda: nssm,
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        # No mutations on either side.
        assert store == {}
        assert nssm.set_calls == []
        assert nssm.reset_calls == []
        # YAML file not written.
        assert not (tmp_path / "svc.yaml").exists()
        # Plan output mentions the secrets and the new app path.
        body = out.getvalue()
        assert "API_KEY" in body
        assert "DB_URL" in body
        # Secret values must NOT appear in the plan output.
        assert "secret123" not in body
        assert "<redacted>" in body

    def test_apply_installs_secrets_writes_yaml_retargets_nssm(
        self, tmp_path: Path
    ) -> None:
        nssm = FakeNssmClient(config=_example_nssm_config())
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        yaml_out = tmp_path / "svc.yaml"
        out, err = _capture()
        rc = cli.main(
            [
                "migrate-from-nssm",
                "svc",
                "--yaml-out",
                str(yaml_out),
            ],
            nssm_factory=lambda: nssm,
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        # Secrets installed.
        assert store["recto:svc:API_KEY"] == "secret123"
        assert store["recto:svc:DB_URL"] == "postgres://x"
        # YAML written and parses back into a valid ServiceConfig.
        from recto.config import load_config

        cfg = load_config(yaml_out)
        assert cfg.metadata.name == "svc"
        assert cfg.spec.exec == "C:\\python.exe"
        assert {s.name for s in cfg.spec.secrets} == {"API_KEY", "DB_URL"}
        for s in cfg.spec.secrets:
            assert s.source == "credman"
            assert s.target_env == s.name
        # NSSM retargeted.
        set_calls_dict = {(svc, fld): val for svc, fld, val in nssm.set_calls}
        assert set_calls_dict[("svc", "Application")] == "python.exe"
        assert "recto launch" in set_calls_dict[("svc", "AppParameters")]
        assert ("svc", "AppEnvironmentExtra") in nssm.reset_calls

    def test_service_not_found_returns_1(self, tmp_path: Path) -> None:
        nssm = FakeNssmClient(not_found=True)
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            [
                "migrate-from-nssm",
                "ghost",
                "--yaml-out",
                str(tmp_path / "ghost.yaml"),
            ],
            nssm_factory=lambda: nssm,
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "not found" in err.getvalue()
        assert store == {}


# ---------------------------------------------------------------------------
# Top-level error paths
# ---------------------------------------------------------------------------


class TestMainErrorPaths:
    def test_no_argv_uses_sys_argv_and_errors_on_no_command(self) -> None:
        # cli.main(None) reads sys.argv. argparse exits 2 on no
        # subcommand. We capture the SystemExit-equivalent return.
        out, err = _capture()
        rc = cli.main([], stdout=out, stderr=err)
        # argparse renders its error to stderr (the global stderr,
        # not our captured one - we don't intercept argparse's own
        # writes), and returns code 2.
        assert rc == 2

    def test_keyboard_interrupt_is_handled(self) -> None:
        def raises(_cfg: ServiceConfig, **_kw: Any) -> int:
            raise KeyboardInterrupt

        # Need a valid yaml to get past load_config.
        out, err = _capture()
        rc = cli.main(
            ["launch", "/nonexistent.yaml"],
            launch_fn=raises,
            stdout=out,
            stderr=err,
        )
        # missing file path lands at 1 before we ever hit launch_fn.
        assert rc == 1


# ---------------------------------------------------------------------------
# apply subcommand
# ---------------------------------------------------------------------------


def _make_apply_yaml(tmp_path: Path, *, name: str = "myservice") -> Path:
    yaml_path = tmp_path / "service.yaml"
    yaml_path.write_text(
        f"apiVersion: recto/v1\n"
        f"kind: Service\n"
        f"metadata:\n"
        f"  name: {name}\n"
        f"  description: An example service\n"
        f"spec:\n"
        f"  exec: python.exe\n"
        f'  working_dir: "C:\\\\path\\\\{name}"\n',
        encoding="utf-8",
    )
    return yaml_path


class TestApplyCommandParsing:
    def test_apply_with_dry_run(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["apply", "service.yaml", "--dry-run"])
        assert args.command == "apply"
        assert args.yaml_path == "service.yaml"
        assert args.dry_run is True
        assert args.yes is False
        # Papercut #1: --python-exe defaults to None so _cmd_apply can
        # detect "operator did not pass an override" and preserve NSSM's
        # current Application value verbatim. Pre-Papercut-#1 default
        # was the literal "python.exe" string.
        assert args.python_exe is None

    def test_apply_with_yes_short_flag(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["apply", "service.yaml", "-y"])
        assert args.yes is True

    def test_apply_with_python_exe_override(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            ["apply", "x.yaml", "--python-exe", "C:\\Python312\\python.exe"]
        )
        assert args.python_exe == "C:\\Python312\\python.exe"


class TestApplyDispatch:
    def test_dry_run_prints_plan_and_exits_without_mutating(
        self, tmp_path: Path
    ) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        # Empty NSSM config: every field needs a change.
        nssm_stub = FakeNssmClient(
            config=NssmConfig(service="myservice")
        )
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path), "--dry-run"],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert "recto apply: myservice" in out.getvalue()
        assert "--dry-run; no changes made" in out.getvalue()
        # Critical: no NSSM mutations.
        assert nssm_stub.set_calls == []
        assert nssm_stub.reset_calls == []

    def test_yes_flag_skips_prompt_and_applies(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(config=NssmConfig(service="myservice"))
        out, err = _capture()
        # confirm should NOT be called when --yes is set; pass a confirm
        # that would fail the test if it were.
        def boom_confirm(_p: str) -> str:
            raise AssertionError("confirm should not be called with --yes")

        rc = cli.main(
            ["apply", str(yaml_path), "--yes"],
            nssm_factory=lambda: nssm_stub,
            confirm=boom_confirm,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert len(nssm_stub.set_calls) == 5  # all five scalar fields
        # No AppEnvironmentExtra reset (current state had it empty).
        assert nssm_stub.reset_calls == []
        assert "applied 5 change(s)" in out.getvalue()

    def test_interactive_y_applies(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(config=NssmConfig(service="myservice"))
        prompts_seen: list[str] = []

        def confirm_yes(prompt: str) -> str:
            prompts_seen.append(prompt)
            return "y"

        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path)],
            nssm_factory=lambda: nssm_stub,
            confirm=confirm_yes,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert len(prompts_seen) == 1
        assert "Apply" in prompts_seen[0]
        assert len(nssm_stub.set_calls) == 5

    def test_interactive_n_aborts(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(config=NssmConfig(service="myservice"))

        def confirm_no(_p: str) -> str:
            return "n"

        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path)],
            nssm_factory=lambda: nssm_stub,
            confirm=confirm_no,
            stdout=out,
            stderr=err,
        )
        # Aborting is a successful no-op (exit 0), not an error.
        assert rc == 0
        assert "aborted" in out.getvalue()
        assert nssm_stub.set_calls == []

    def test_interactive_eof_aborts(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(config=NssmConfig(service="myservice"))

        def confirm_eof(_p: str) -> str:
            raise EOFError()

        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path)],
            nssm_factory=lambda: nssm_stub,
            confirm=confirm_eof,
            stdout=out,
            stderr=err,
        )
        # EOF on stdin (e.g. Ctrl-D, or `recto apply ... < /dev/null`) is
        # treated as "no" -- safer default than re-raising.
        assert rc == 0
        assert nssm_stub.set_calls == []

    def test_python_exe_default_preserves_existing_application(
        self, tmp_path: Path
    ) -> None:
        """Papercut #1: when --python-exe is NOT passed, recto apply
        keeps NSSM's existing Application value rather than proposing
        a change to bare 'python.exe'. The pre-fix behavior silently
        overwrote a fully-qualified C:\\Python314\\python.exe with the
        bare name, breaking service-account contexts whose PATH
        didn't resolve to the right Python."""
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        # NSSM already has a fully-qualified python.exe set (e.g. from
        # a prior migrate-from-nssm run with --python-exe).
        nssm_stub = FakeNssmClient(
            config=NssmConfig(
                service="myservice",
                app_path="C:\\Python314\\python.exe",
                app_parameters=f"-m recto launch {yaml_path.resolve()}",
                app_directory="C:\\path\\myservice",
                display_name="An example service",
                description="An example service",
            )
        )
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path), "--yes"],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        # No-op for Application -- the operator didn't ask for a change.
        application_sets = [
            v for svc, fld, v in nssm_stub.set_calls if fld == "Application"
        ]
        assert application_sets == []
        # And the rendered plan shouldn't mark Application as changed.
        assert "Application" not in [
            line.split(":")[0].strip().lstrip("~")
            for line in out.getvalue().split("\n")
            if line.startswith("  ~")
        ]

    def test_python_exe_explicit_override_still_lands(
        self, tmp_path: Path
    ) -> None:
        """Papercut #1 doesn't break the explicit-override path. When
        operators pass --python-exe, it lands as a proposed change
        regardless of NSSM's current value."""
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(
            config=NssmConfig(
                service="myservice",
                app_path="C:\\OldPython\\python.exe",
                app_parameters=f"-m recto launch {yaml_path.resolve()}",
                app_directory="C:\\path\\myservice",
                display_name="An example service",
                description="An example service",
            )
        )
        out, err = _capture()
        rc = cli.main(
            [
                "apply", str(yaml_path), "--yes",
                "--python-exe", "C:\\NewPython\\python.exe",
            ],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        application_sets = [
            v for svc, fld, v in nssm_stub.set_calls if fld == "Application"
        ]
        assert application_sets == ["C:\\NewPython\\python.exe"]

    def test_python_exe_default_falls_back_to_python_exe_when_nssm_empty(
        self, tmp_path: Path
    ) -> None:
        """Papercut #1 backward-compat: if NSSM's Application is empty
        (a freshly `nssm install`ed service that's never been Recto-
        wrapped), the implicit fallback is 'python.exe' so the apply
        can still wire a usable Application."""
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(config=NssmConfig(service="myservice"))
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path), "--yes"],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        application_sets = [
            v for svc, fld, v in nssm_stub.set_calls if fld == "Application"
        ]
        assert application_sets == ["python.exe"]

    def test_no_changes_needed_returns_zero_without_apply(
        self, tmp_path: Path
    ) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        # Build NSSM state to match what cfg implies.
        nssm_stub = FakeNssmClient(
            config=NssmConfig(
                service="myservice",
                app_path="python.exe",
                app_parameters=f"-m recto launch {yaml_path.resolve()}",
                app_directory="C:\\path\\myservice",
                display_name="An example service",
                description="An example service",
            )
        )
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path), "--yes"],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert "no changes needed" in out.getvalue()
        assert nssm_stub.set_calls == []
        assert nssm_stub.reset_calls == []

    def test_invalid_yaml_returns_one(self, tmp_path: Path) -> None:
        # Syntactically valid YAML but invalid Recto schema (wrong
        # apiVersion). Tests the ConfigValidationError code path.
        # (yaml.YAMLError parse failures are a separate handler gap
        # affecting both `apply` and `launch`; tracked for follow-up.)
        bad_path = tmp_path / "bad.yaml"
        bad_path.write_text(
            "apiVersion: recto/v999\n"
            "kind: Service\n"
            "metadata:\n  name: x\n"
            "spec:\n  exec: x\n",
            encoding="utf-8",
        )
        nssm_stub = FakeNssmClient(config=NssmConfig(service="x"))
        out, err = _capture()
        rc = cli.main(
            ["apply", str(bad_path)],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "invalid config" in err.getvalue()

    def test_missing_yaml_file_returns_one(self, tmp_path: Path) -> None:
        nssm_stub = FakeNssmClient(config=NssmConfig(service="x"))
        out, err = _capture()
        rc = cli.main(
            ["apply", str(tmp_path / "no-such-file.yaml")],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "file not found" in err.getvalue()

    def test_nssm_service_not_found_returns_one(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(not_found=True)
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path)],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "not found" in err.getvalue()
        # The error should mention the migration path as a hint.
        assert "migrate-from-nssm" in err.getvalue()

    def test_nssm_not_installed_returns_one(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(not_installed=True)
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path)],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "nssm" in err.getvalue().lower()

    def test_environment_extra_clear_summarized(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(
            config=NssmConfig(
                service="myservice",
                app_path="python.exe",
                app_parameters=f"-m recto launch {yaml_path.resolve()}",
                app_directory="C:\\path\\myservice",
                display_name="An example service",
                description="An example service",
                # Stale plaintext secret -- the apply should clear it.
                app_environment_extra=("LEFTOVER=value",),
            )
        )
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path), "--yes"],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert nssm_stub.set_calls == []  # all scalar fields matched
        assert nssm_stub.reset_calls == [("myservice", "AppEnvironmentExtra")]
        assert "cleared AppEnvironmentExtra" in out.getvalue()
        # Critical: the leftover secret value MUST NOT appear in stdout.
        assert "LEFTOVER" not in out.getvalue()
        assert "value" not in out.getvalue().split("(s)")[-1]


# ---------------------------------------------------------------------------
# v0.2.2: --keep-as-env flag for migrate-from-nssm
# ---------------------------------------------------------------------------


class TestPartitionEnvEntries:
    """Pure data-layer tests for partition_env_entries."""

    def test_no_keep_as_env_routes_everything_to_secrets(self) -> None:
        from recto._migrate import partition_env_entries
        entries = [("MY_API_KEY", "secret-value"), ("PYTHONUNBUFFERED", "1")]
        secrets, plain = partition_env_entries(entries, keep_as_env=None)
        assert secrets == entries
        assert plain == []

    def test_explicit_keep_as_env_routes_to_plain(self) -> None:
        from recto._migrate import partition_env_entries
        entries = [
            ("MY_API_KEY", "secret-value"),
            ("PYTHONUNBUFFERED", "1"),
            ("LOG_LEVEL", "info"),
        ]
        secrets, plain = partition_env_entries(
            entries, keep_as_env=["PYTHONUNBUFFERED", "LOG_LEVEL"]
        )
        assert secrets == [("MY_API_KEY", "secret-value")]
        assert plain == [("PYTHONUNBUFFERED", "1"), ("LOG_LEVEL", "info")]

    def test_preserves_input_order(self) -> None:
        from recto._migrate import partition_env_entries
        entries = [("Z", "1"), ("A", "2"), ("M", "3")]
        secrets, _ = partition_env_entries(entries, keep_as_env=None)
        assert [k for k, _ in secrets] == ["Z", "A", "M"]

    def test_unknown_key_in_keep_list_is_silently_ignored(self) -> None:
        from recto._migrate import partition_env_entries
        entries = [("FOO", "v")]
        secrets, plain = partition_env_entries(
            entries, keep_as_env=["NOT_PRESENT"]
        )
        # FOO wasn't in keep list -> goes to secrets. NOT_PRESENT
        # wasn't in entries -> doesn't appear in plain.
        assert secrets == [("FOO", "v")]
        assert plain == []


class TestMigrateKeepAsEnvCli:
    """CLI integration: --keep-as-env flag end-to-end."""

    def test_migrate_with_keep_as_env_routes_to_yaml_env_block(
        self, tmp_path: Path
    ) -> None:
        # NSSM config has both a real secret and a non-secret env var.
        nssm = FakeNssmClient(
            config=NssmConfig(
                service="myservice",
                app_path="C:\\old\\python.exe",
                app_parameters="app.py",
                app_directory="C:\\path\\to\\myservice",
                app_environment_extra=(
                    "MY_API_KEY=secret-value",
                    "PYTHONUNBUFFERED=1",
                ),
            )
        )
        cred_store: dict[str, str] = {}
        yaml_out = tmp_path / "out.yaml"
        out, err = _capture()
        rc = cli.main(
            [
                "migrate-from-nssm",
                "myservice",
                "--yaml-out",
                str(yaml_out),
                "--keep-as-env",
                "PYTHONUNBUFFERED",
            ],
            nssm_factory=lambda: nssm,
            credman_factory=lambda svc: FakeCredManSource(svc, cred_store),
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        # MY_API_KEY went to CredMan; PYTHONUNBUFFERED did NOT.
        assert "recto:myservice:MY_API_KEY" in cred_store
        assert "recto:myservice:PYTHONUNBUFFERED" not in cred_store
        # The generated YAML has PYTHONUNBUFFERED in its env: block.
        text = yaml_out.read_text(encoding="utf-8")
        assert "  env:" in text
        assert "    PYTHONUNBUFFERED: \"1\"" in text
        # And MY_API_KEY in its secrets: block.
        assert "  secrets:" in text
        assert "    - name: MY_API_KEY" in text
        # The plan output (printed to stdout) lists plain env separately.
        assert "plain_env_to_yaml" in out.getvalue()
        assert "PYTHONUNBUFFERED" in out.getvalue()

    def test_migrate_no_keep_as_env_keeps_v0_1_behavior(
        self, tmp_path: Path
    ) -> None:
        # Without --keep-as-env, every entry still routes to CredMan.
        nssm = FakeNssmClient(
            config=NssmConfig(
                service="myservice",
                app_path="C:\\old\\python.exe",
                app_parameters="app.py",
                app_directory="C:\\path",
                app_environment_extra=(
                    "PYTHONUNBUFFERED=1",
                    "LOG_LEVEL=info",
                ),
            )
        )
        cred_store: dict[str, str] = {}
        yaml_out = tmp_path / "out.yaml"
        out, err = _capture()
        rc = cli.main(
            [
                "migrate-from-nssm",
                "myservice",
                "--yaml-out",
                str(yaml_out),
            ],
            nssm_factory=lambda: nssm,
            credman_factory=lambda svc: FakeCredManSource(svc, cred_store),
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        # Both went to CredMan -- backward compat preserved.
        assert "recto:myservice:PYTHONUNBUFFERED" in cred_store
        assert "recto:myservice:LOG_LEVEL" in cred_store
        text = yaml_out.read_text(encoding="utf-8")
        # No env: block in the YAML (every entry is a secret).
        assert "  env:" not in text

    def test_migrate_keep_as_env_comma_separated(
        self, tmp_path: Path
    ) -> None:
        nssm = FakeNssmClient(
            config=NssmConfig(
                service="myservice",
                app_path="x",
                app_parameters="a",
                app_directory="d",
                app_environment_extra=(
                    "A=1",
                    "B=2",
                    "C=3",
                    "D=4",
                ),
            )
        )
        cred_store: dict[str, str] = {}
        yaml_out = tmp_path / "out.yaml"
        out, err = _capture()
        rc = cli.main(
            [
                "migrate-from-nssm",
                "myservice",
                "--yaml-out",
                str(yaml_out),
                "--keep-as-env",
                "A,C",   # multi-value via comma
            ],
            nssm_factory=lambda: nssm,
            credman_factory=lambda svc: FakeCredManSource(svc, cred_store),
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        # A and C in YAML; B and D in CredMan.
        text = yaml_out.read_text(encoding="utf-8")
        assert "    A: \"1\"" in text
        assert "    C: \"3\"" in text
        assert "recto:myservice:B" in cred_store
        assert "recto:myservice:D" in cred_store
        # And A, C should NOT appear in CredMan.
        assert "recto:myservice:A" not in cred_store
        assert "recto:myservice:C" not in cred_store

    def test_migrate_warns_on_keep_as_env_entry_not_in_source(
        self, tmp_path: Path
    ) -> None:
        """Papercut #4: --keep-as-env entries that aren't in the source
        AppEnvironmentExtra should emit a warning, not silently skip.
        Otherwise operators chasing 'expected N entries, got N-1' have no
        clue which name was the offender."""
        nssm = FakeNssmClient(
            config=NssmConfig(
                service="myservice",
                app_path="x",
                app_parameters="a",
                app_directory="d",
                app_environment_extra=(
                    "REAL_KEY=1",
                    "ANOTHER_REAL=2",
                ),
            )
        )
        cred_store: dict[str, str] = {}
        yaml_out = tmp_path / "out.yaml"
        out, err = _capture()
        rc = cli.main(
            [
                "migrate-from-nssm",
                "myservice",
                "--yaml-out",
                str(yaml_out),
                "--keep-as-env",
                "REAL_KEY,GHOST_KEY,ANOTHER_GHOST",
            ],
            nssm_factory=lambda: nssm,
            credman_factory=lambda svc: FakeCredManSource(svc, cred_store),
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        # Migration succeeds; REAL_KEY routes to plain env, ANOTHER_REAL
        # routes to CredMan as a secret (it wasn't on the keep-list).
        text = yaml_out.read_text(encoding="utf-8")
        assert "    REAL_KEY: \"1\"" in text
        assert "recto:myservice:ANOTHER_REAL" in cred_store
        # The two missing names each emit a separate warning to stderr.
        err_text = err.getvalue()
        assert "GHOST_KEY" in err_text
        assert "ANOTHER_GHOST" in err_text
        assert err_text.count("--keep-as-env entry") == 2
        assert "not found in source AppEnvironmentExtra" in err_text
        # REAL_KEY should NOT appear in any warning (it was found).
        assert "'REAL_KEY'" not in err_text


class TestMigrateDisplayNameEmission:
    """Papercut #3: migrate-from-nssm should emit NSSM DisplayName ->
    YAML display_name and NSSM Description -> YAML description as
    distinct fields, not collapsing both into a single description."""

    def test_migrator_emits_display_name_for_nssm_displayname(
        self, tmp_path: Path
    ) -> None:
        """Source NSSM has DisplayName set but no Description. New
        YAML should have display_name set and no description (vs
        pre-Papercut-#3 which emitted description=display_name)."""
        nssm = FakeNssmClient(
            config=NssmConfig(
                service="svc",
                app_path="C:\\python.exe",
                app_parameters="app.py",
                app_directory="C:\\app",
                display_name="MyService Short",
                # description intentionally empty
                app_environment_extra=(),
            )
        )
        cred_store: dict[str, str] = {}
        yaml_out = tmp_path / "svc.yaml"
        out, err = _capture()
        rc = cli.main(
            ["migrate-from-nssm", "svc", "--yaml-out", str(yaml_out)],
            nssm_factory=lambda: nssm,
            credman_factory=lambda svc: FakeCredManSource(svc, cred_store),
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        text = yaml_out.read_text(encoding="utf-8")
        # New behavior: display_name emitted, description NOT emitted.
        assert "display_name: \"MyService Short\"" in text
        assert "description:" not in text
        # Round-trip: load_config sees display_name, description stays "".
        from recto.config import load_config

        cfg = load_config(yaml_out)
        assert cfg.metadata.display_name == "MyService Short"
        assert cfg.metadata.description == ""

    def test_migrator_emits_both_when_nssm_has_both(
        self, tmp_path: Path
    ) -> None:
        """When the source NSSM has both DisplayName and Description set
        (operator explicitly configured them as distinct values), the
        migrator preserves the distinction in the YAML."""
        nssm = FakeNssmClient(
            config=NssmConfig(
                service="svc",
                app_path="C:\\python.exe",
                app_parameters="app.py",
                app_directory="C:\\app",
                display_name="MyService",
                description="A longer narrative for the operator audit pane.",
                app_environment_extra=(),
            )
        )
        cred_store: dict[str, str] = {}
        yaml_out = tmp_path / "svc.yaml"
        out, err = _capture()
        rc = cli.main(
            ["migrate-from-nssm", "svc", "--yaml-out", str(yaml_out)],
            nssm_factory=lambda: nssm,
            credman_factory=lambda svc: FakeCredManSource(svc, cred_store),
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        text = yaml_out.read_text(encoding="utf-8")
        assert "display_name: \"MyService\"" in text
        assert (
            'description: "A longer narrative for the operator audit pane."'
            in text
        )
        # Round-trip check.
        from recto.config import load_config

        cfg = load_config(yaml_out)
        assert cfg.metadata.display_name == "MyService"
        assert cfg.metadata.description == (
            "A longer narrative for the operator audit pane."
        )

    def test_migrator_omits_both_when_nssm_has_neither(
        self, tmp_path: Path
    ) -> None:
        """No DisplayName, no Description -> YAML has neither field.
        Backward-compat with the simplest possible NSSM service."""
        nssm = FakeNssmClient(
            config=NssmConfig(
                service="svc",
                app_path="C:\\python.exe",
                app_parameters="app.py",
                app_directory="C:\\app",
                app_environment_extra=(),
                # display_name and description both default to ""
            )
        )
        cred_store: dict[str, str] = {}
        yaml_out = tmp_path / "svc.yaml"
        out, err = _capture()
        rc = cli.main(
            ["migrate-from-nssm", "svc", "--yaml-out", str(yaml_out)],
            nssm_factory=lambda: nssm,
            credman_factory=lambda svc: FakeCredManSource(svc, cred_store),
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        text = yaml_out.read_text(encoding="utf-8")
        assert "display_name:" not in text
        assert "description:" not in text


# ---------------------------------------------------------------------------
# v0.2.2 Gap 4: recto events CLI subcommand
# ---------------------------------------------------------------------------


def _make_apply_yaml_with_admin(tmp_path: Path, *, enabled: bool = True, bind: str = "127.0.0.1:5050") -> Path:
    """service.yaml that enables (or disables) admin_ui for the events command."""
    yaml_path = tmp_path / "svc.yaml"
    if enabled:
        admin = f"  admin_ui:\n    enabled: true\n    bind: {bind}\n"
    else:
        admin = "  admin_ui:\n    enabled: false\n"
    yaml_path.write_text(
        "apiVersion: recto/v1\n"
        "kind: Service\n"
        "metadata:\n  name: myservice\n"
        "spec:\n  exec: python.exe\n"
        + admin,
        encoding="utf-8",
    )
    return yaml_path


class TestEventsCommandParsing:
    def test_events_basic(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["events", "svc.yaml"])
        assert args.command == "events"
        assert args.yaml_path == "svc.yaml"
        assert args.kind is None
        assert args.limit == 200
        assert args.restart_history is False

    def test_events_with_kind_and_limit(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            ["events", "svc.yaml", "--kind", "child.exit", "--limit", "50"]
        )
        assert args.kind == "child.exit"
        assert args.limit == 50

    def test_events_restart_history_flag(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["events", "svc.yaml", "--restart-history"])
        assert args.restart_history is True


class TestEventsCommandDispatch:
    def test_events_admin_ui_disabled_returns_one(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml_with_admin(tmp_path, enabled=False)
        out, err = _capture()
        rc = cli.main(["events", str(yaml_path)], stdout=out, stderr=err)
        assert rc == 1
        assert "admin_ui.enabled is false" in err.getvalue()

    def test_events_invalid_yaml_returns_one(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("apiVersion: recto/v999\nkind: Service\nmetadata:\n  name: x\nspec:\n  exec: x\n")
        out, err = _capture()
        rc = cli.main(["events", str(bad)], stdout=out, stderr=err)
        assert rc == 1
        assert "invalid config" in err.getvalue()

    def test_events_missing_yaml_returns_one(self, tmp_path: Path) -> None:
        out, err = _capture()
        rc = cli.main(
            ["events", str(tmp_path / "nope.yaml")], stdout=out, stderr=err
        )
        assert rc == 1
        assert "file not found" in err.getvalue()

    def test_events_fetch_url_called_with_correct_url(
        self, tmp_path: Path
    ) -> None:
        yaml_path = _make_apply_yaml_with_admin(
            tmp_path, enabled=True, bind="127.0.0.1:5050"
        )
        recorded: list[tuple[str, float]] = []

        def fake_fetch(url: str, timeout: float) -> bytes:
            recorded.append((url, timeout))
            return b'{"events": [], "count": 0}'

        # Inject fetch_url via a patched _cmd_events (the production
        # path uses the default _default_fetch_url; tests want the
        # injection seam).
        out, err = _capture()
        # Bypass argparse for direct kwarg injection. Simulate the args
        # that `recto events <yaml>` would yield.
        args = cli.build_parser().parse_args(["events", str(yaml_path)])
        rc = cli._cmd_events(
            args, out=out, err=err, fetch_url=fake_fetch
        )
        assert rc == 0
        assert len(recorded) == 1
        url, _timeout = recorded[0]
        assert url == "http://127.0.0.1:5050/api/events?limit=200"

    def test_events_kind_filter_appends_query_string(
        self, tmp_path: Path
    ) -> None:
        yaml_path = _make_apply_yaml_with_admin(tmp_path)
        recorded: list[str] = []

        def fake_fetch(url: str, _timeout: float) -> bytes:
            recorded.append(url)
            return b'{"events": []}'

        out, err = _capture()
        args = cli.build_parser().parse_args(
            ["events", str(yaml_path), "--kind", "child.spawn,child.exit"]
        )
        cli._cmd_events(args, out=out, err=err, fetch_url=fake_fetch)
        assert recorded[0].endswith("&kind=child.spawn&kind=child.exit")

    def test_events_restart_history_hits_correct_endpoint(
        self, tmp_path: Path
    ) -> None:
        yaml_path = _make_apply_yaml_with_admin(tmp_path)
        recorded: list[str] = []

        def fake_fetch(url: str, _timeout: float) -> bytes:
            recorded.append(url)
            return b'{"events": []}'

        out, err = _capture()
        args = cli.build_parser().parse_args(
            ["events", str(yaml_path), "--restart-history"]
        )
        cli._cmd_events(args, out=out, err=err, fetch_url=fake_fetch)
        assert "/api/restart-history" in recorded[0]
        assert "/api/events?" not in recorded[0]

    def test_events_unreachable_server_returns_one(
        self, tmp_path: Path
    ) -> None:
        yaml_path = _make_apply_yaml_with_admin(tmp_path)

        def boom_fetch(_url: str, _t: float) -> bytes:
            raise ConnectionRefusedError("connection refused")

        out, err = _capture()
        args = cli.build_parser().parse_args(["events", str(yaml_path)])
        rc = cli._cmd_events(args, out=out, err=err, fetch_url=boom_fetch)
        assert rc == 1
        assert "failed to reach" in err.getvalue()
        assert "ConnectionRefusedError" in err.getvalue()
        # Hint user toward NSSM AppStdout log fallback.
        assert "AppStdout" in err.getvalue()

    def test_events_prints_response_body_to_stdout(
        self, tmp_path: Path
    ) -> None:
        yaml_path = _make_apply_yaml_with_admin(tmp_path)

        def fake_fetch(_url: str, _t: float) -> bytes:
            return b'{"events": [{"kind": "child.spawn"}], "count": 1}'

        out, err = _capture()
        args = cli.build_parser().parse_args(["events", str(yaml_path)])
        rc = cli._cmd_events(args, out=out, err=err, fetch_url=fake_fetch)
        assert rc == 0
        body = out.getvalue()
        assert "child.spawn" in body
        assert "count" in body
