"""THE CONFIG SEAM for the signed-poll ceremony (hard rule 14.2; 2026-09-21).

THE DEFECT. ``signed_poll_mode`` was a ``create_server()`` kwarg with no env var, no CLI
flag and no YAML; the container's launcher never passed it. The ceremony the substrate
names -- advisory -> evidence window -> flip -> single redeploy -- had no handle for its
last step: a deployed bootloader could not be put in ``required`` at all.

THE SEAM. ``RECTO_SIGNED_POLL_MODE`` in ``examples/run_bootloader_consumer.py``, resolved
by ``_resolve_signed_poll_mode``. Unset = advisory (the substrate's own default). An illegal
spelling is REFUSED at startup, never coerced: a mode that silently fell back to advisory
would read, to an operator watching the evidence window, as "the flip took".

THE POSITIVE CONTROL is the legal-values test -- a resolver that refused everything would
pass the refusal test alone.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

_EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
if str(_EXAMPLES) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES))

from run_bootloader_consumer import _resolve_signed_poll_mode  # noqa: E402

from recto.bootloader.server import SIGNED_POLL_MODES  # noqa: E402


def test_unset_is_advisory_the_substrate_default():
    assert _resolve_signed_poll_mode({}) == "advisory"
    assert _resolve_signed_poll_mode({"RECTO_SIGNED_POLL_MODE": ""}) == "advisory"
    assert _resolve_signed_poll_mode({"RECTO_SIGNED_POLL_MODE": "   "}) == "advisory"


@pytest.mark.parametrize("mode", SIGNED_POLL_MODES)
def test_every_legal_mode_resolves_to_itself(mode):
    """The positive control. Also proves the seam reaches 'required' -- the step the
    ceremony could not take before this seam existed."""
    assert _resolve_signed_poll_mode({"RECTO_SIGNED_POLL_MODE": mode}) == mode
    assert _resolve_signed_poll_mode({"RECTO_SIGNED_POLL_MODE": f"  {mode.upper()} "}) == mode


@pytest.mark.parametrize("bad", ["enforced", "on", "true", "1", "require", "advisory,required"])
def test_an_illegal_spelling_is_refused_not_coerced(bad):
    """RED-BUILD: make the resolver fall back to 'advisory' on an unknown value and this
    passes a typo through as the default -- the operator sees the flip 'take' while
    every phone keeps polling bare."""
    with pytest.raises(ValueError, match="RECTO_SIGNED_POLL_MODE"):
        _resolve_signed_poll_mode({"RECTO_SIGNED_POLL_MODE": bad})


def test_the_launcher_passes_the_mode_to_create_server():
    """Source-level falsifier: the seam is only a seam if the kwarg reaches the server."""
    src = (_EXAMPLES / "run_bootloader_consumer.py").read_text(encoding="utf-8")
    assert "signed_poll_mode=signed_poll_mode," in src, (
        "create_server() is called without signed_poll_mode -- the env var is read by nothing"
    )
