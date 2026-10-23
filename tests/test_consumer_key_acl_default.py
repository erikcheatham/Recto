"""The public entrypoint's per-key allowlist ENFORCES by default: RECTO_CONNECTIONS_KEY_ACL_ENFORCE unset, "1" or
"true" enforce; "0" or "false" is the explicit audit opt-out; any other value refuses the start with exit 2, naming the
variable and the accepted values - as the library's own default (TestKeyAclDefaultPosture) has it."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "examples") not in sys.path:
    sys.path.insert(0, str(REPO / "examples"))

VAR = "RECTO_CONNECTIONS_KEY_ACL_ENFORCE"


def _env_key_acl_enforce() -> bool:
    from run_bootloader_consumer import _env_key_acl_enforce as helper
    return helper()


def test_unset_enforces(monkeypatch) -> None:
    monkeypatch.delenv(VAR, raising=False)
    assert _env_key_acl_enforce() is True


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "True", " 1 ", "", "   "])
def test_one_true_and_set_but_empty_enforce(monkeypatch, raw) -> None:
    monkeypatch.setenv(VAR, raw)
    assert _env_key_acl_enforce() is True


@pytest.mark.parametrize("raw", ["0", "false", "FALSE"])
def test_zero_and_false_are_the_audit_opt_out(monkeypatch, raw) -> None:
    monkeypatch.setenv(VAR, raw)
    assert _env_key_acl_enforce() is False


@pytest.mark.parametrize("raw", ["yes", "2", "on", "no", "off"])
def test_any_other_value_refuses_the_start(monkeypatch, capsys, raw) -> None:
    monkeypatch.setenv(VAR, raw)
    with pytest.raises(SystemExit) as exited:
        _env_key_acl_enforce()
    assert exited.value.code == 2
    err = capsys.readouterr().err
    assert VAR in err and "1/true" in err and "0/false" in err, err


def test_the_launcher_hands_create_server_an_enforcing_gate_when_unset(monkeypatch, tmp_path) -> None:
    import tests.test_capability_consumer_actions as tcca

    rc, kwargs = tcca._launcher_kwargs(monkeypatch, tmp_path, [{"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A"}])
    assert rc is None and kwargs is not None
    assert kwargs["connections_key_acl_enforce"] is True


@pytest.mark.parametrize("raw", ["0", "false"])
def test_the_launcher_hands_create_server_the_audit_opt_out(monkeypatch, tmp_path, raw) -> None:
    import tests.test_capability_consumer_actions as tcca

    real_delenv = monkeypatch.delenv

    def keep_the_flag(name, *a, **k):  # the harness clears every RECTO_ variable; this one is the test's input
        if name != VAR:
            real_delenv(name, *a, **k)

    monkeypatch.setenv(VAR, raw)
    monkeypatch.setattr(monkeypatch, "delenv", keep_the_flag)
    rc, kwargs = tcca._launcher_kwargs(monkeypatch, tmp_path, [{"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A"}])
    assert rc is None and kwargs is not None
    assert kwargs["connections_key_acl_enforce"] is False
