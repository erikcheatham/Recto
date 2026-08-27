"""
recto.capability — Phase 5 capability-JWT primitives.

Implements the operator-issued, scoped, time-bounded JWT capability
system that hardens Recto's Hard Rule #9 ("phone enclave is a generic
capability provider; agents inherit from humans") from a trust-based
posture into cryptographically-enforced authorization.

Phase 5 Wave A scope (this package, started 2026-05-05):
- JWT claim shape (CapabilityClaims dataclass)
- Capability action manifest (versioned JSON, single source of truth)
- Mint / verify primitives (next-session — this package currently
  holds types + manifest only)

See `recto/capability/SPEC.md` for the human-readable spec and the
"Phase 5 capability-JWT schema design (drafted 2026-05-05)" section
in the project memory for the canonical design.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path


def manifest_v1_path() -> Path:
    """Resolve the path to the bundled `manifest_v1.json` file.

    Uses `importlib.resources` so the lookup works whether the package
    is installed from a wheel (file under site-packages) or from a
    development checkout (file under the source tree). The returned
    path is a real filesystem path — callers can pass it to
    `load_manifest()` directly, or pass it to subprocess CLIs that
    take a path argument.

    Used by:
      - The release workflow's wheel-shipping verification step (per
        `RELEASING.md` step 6) — confirms `package-data` correctly
        included the JSON in the built wheel.
      - The bootloader's first-boot manifest seeder, when no operator-
        authored manifest has been deployed yet.
      - Operators wanting to view the canonical template before
        forking their own production manifest.

    Returns:
        pathlib.Path pointing at `recto/capability/manifest_v1.json`.

    Raises:
        FileNotFoundError: the bundled JSON is missing — typically
        means a packaging bug (`[tool.setuptools.package-data]` in
        pyproject.toml didn't ship the file). Re-build the wheel or
        check the install.
    """
    # importlib.resources.files() returns a Traversable; the .joinpath
    # + .as_posix dance handles both wheel-bundled and dev-checkout
    # cases. Convert to Path via str() so callers get a familiar API.
    ref = resources.files(__name__).joinpath("manifest_v1.json")
    # On a real filesystem (dev checkout OR an unpacked wheel),
    # ref will resolve to a concrete path. For zipfile-installed
    # wheels (rare for Python pkgs), this would need as_file() —
    # but Recto's wheel ships as a regular directory install, so
    # str() is safe and gives callers a Path-compatible string.
    path = Path(str(ref))
    if not path.is_file():
        raise FileNotFoundError(
            f"recto.capability bundled manifest not found at {path}. "
            f"Likely cause: pyproject.toml [tool.setuptools.package-data] "
            f"did not include the JSON. Re-build the wheel."
        )
    return path


__all__ = [
    "manifest_v1_path",
    # Filled in further as mint/verify lands.
]
