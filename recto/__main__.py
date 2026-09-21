"""`python -m recto` entry point.

Forwards to recto.cli:main(). The console-script entry registered
in pyproject.toml (`recto = "recto.cli:main"`) hits the same target,
so `recto launch ...` and `python -m recto launch ...` are identical.
"""

from __future__ import annotations

import sys

from recto.cli import main


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
