"""Phase 2.0.C C.4 helper -- bootstrap master_identity.json from operator pubkey.

The `recto vault bootstrap` CLI writes vault_root.json (used by the capability
verifier). This script writes the sister file master_identity.json (used by
the profile system) so subsequent `recto profile create personal:child`
calls have a master to derive from.

Same 128-hex operator pubkey value goes into both. No CLI wrapper exists
for the master-bootstrap path yet -- this script fills that gap.

Usage:
    python scripts\\c4_bootstrap_master.py <128-hex-operator-pubkey>
    python scripts\\c4_bootstrap_master.py <128-hex-operator-pubkey> --state-dir <path>
    python scripts\\c4_bootstrap_master.py <128-hex-operator-pubkey> --display-name "Erik (primary)"

Default state-dir matches the example bootloader's default
(~/.recto/bootloader on Windows, $HOME/.recto/bootloader otherwise).
"""

from __future__ import annotations

import argparse
import pathlib
import sys

# Make Recto importable from a checkout (no install required)
_repo_root = pathlib.Path(__file__).resolve().parents[1]
if (_repo_root / "recto").is_dir() and str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from recto.profile.manage import bootstrap_master, MasterAlreadyBootstrappedError


def main() -> int:
    ap = argparse.ArgumentParser(description="Bootstrap master_identity.json from operator pubkey")
    ap.add_argument("pubkey_hex", help="128-hex secp256k1 operator pubkey (same value used for recto vault bootstrap)")
    ap.add_argument("--state-dir", default=str(pathlib.Path.home() / ".recto" / "bootloader"),
                    help="bootloader state dir (default ~/.recto/bootloader)")
    ap.add_argument("--display-name", default="Personal (master)",
                    help="human label for the master profile row")
    ap.add_argument("--label", default=None,
                    help="optional MasterIdentity label (defaults to display-name)")
    ap.add_argument("--force", action="store_true",
                    help="overwrite an existing master_identity.json (catastrophic; for rotation)")
    args = ap.parse_args()

    state_dir = pathlib.Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)

    try:
        mi = bootstrap_master(
            args.pubkey_hex,
            display_name=args.display_name,
            label=args.label,
            state_dir=state_dir,
            force=args.force,
        )
    except MasterAlreadyBootstrappedError as exc:
        print(f"\nMaster already bootstrapped at {state_dir / 'master_identity.json'}.",
              file=sys.stderr)
        print(f"Pass --force to overwrite (rotation only -- destroys profile history).",
              file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 2

    print(f"\nMaster bootstrapped at {state_dir / 'master_identity.json'}")
    print(f"  master_profile_id: {mi.master_profile_id}")
    print(f"  master_pubkey:     {mi.master_pubkey_hex}")
    print(f"  display_name:      {mi.master_profile_display_name if hasattr(mi, 'master_profile_display_name') else args.display_name}")
    print(f"\nNext step:")
    print(f"  recto profile list --state-dir {state_dir}")
    print(f"  recto profile create personal:child --name \"Pseudonym 1\" \\")
    print(f"    --phone-id <iphone-phone-id> --agent-id myservice-agent --agent-token <token>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
