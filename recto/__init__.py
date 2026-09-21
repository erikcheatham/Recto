"""Recto — modern Windows-service wrapper.

Public API surface:
    recto.config.load_config        — parse + validate a service.yaml
    recto.config.ServiceConfig      — top-level dataclass
    recto.secrets.SecretSource      — ABC for pluggable secret backends
    recto.secrets.SecretMaterial    — sealed type returned by SecretSource.fetch
    recto.secrets.DirectSecret      — variant: secret materialized as a string
    recto.secrets.SigningCapability — variant: secret never leaves enclave
    recto.secrets.EnvSource         — passthrough backend reading os.environ
    recto.secrets.CredManSource     — Windows Credential Manager backend
    recto.secrets.register_source   — third-party backend registration
    recto.launcher.launch           — read config, fetch secrets, spawn child

Higher-level entry points (CLI, healthz probe loop, restart policy, comms
webhook dispatch) are wired in alongside the launcher in v0.1.
"""

# ONE VALUE, ONE PLACE (2026-08-17). This was a hardcoded "0.1.0.dev0" while
# pyproject.toml declared version = "1.0.0" -- two version numbers for one
# package, disagreeing, and `recto --version` read the wrong one. Nobody
# updated this line when the package went to 1.0.0, because nothing made them:
# a copy of a fact drifts silently, and the only symptom was a CLI cheerfully
# reporting a version that had not existed for months.
#
# pyproject.toml is now the sole declaration; this reads it at import.
# The fallback is NOT "0.1.0.dev0" again -- it says plainly that the package is
# not installed (a source checkout without `pip install -e .`), because a
# plausible-looking wrong number is worse than an obviously absent one.
from importlib.metadata import PackageNotFoundError, version as _pkg_version

# THE DISTRIBUTION IS NAMED "recto-core", NOT "recto". Getting this wrong is
# not hypothetical -- the first draft of this file queried "recto" and resolved
# to 0.1.0.dev0 from a STALE recto.egg-info left behind when the package was
# renamed. Locally that looked like a working fix. In the container, which
# pip-installs fresh and therefore has no ghost, it would have fallen through
# to the not-installed branch and reported a version the software never had.
# Right on the developer's machine, wrong in production: the same shape as the
# caplog gap that hid GATE 0c.
try:
    __version__ = _pkg_version("recto-core")
except PackageNotFoundError:  # a source tree without `pip install -e .`
    __version__ = "0.0.0+not-installed"
__all__ = ["__version__"]
