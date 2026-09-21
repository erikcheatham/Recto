"""Phase 2.0.C C.4 hardware-ceremony helper -- recover operator pubkey from JWSes.

SEC1 section 4.1.6 public-key recovery. Each JWS signature has 2 candidate
recovery_id values; intersecting candidate sets across 2-3 distinct JWSes
uniquely resolves the actual signer pubkey.

Wraps recto.ethereum.recover_public_key (already pure-stdlib + secp256k1).

Usage:
    python scripts\\c4_recover_operator_pubkey.py "<jws-1>" "<jws-2>"
    python scripts\\c4_recover_operator_pubkey.py "<jws-1>" "<jws-2>" "<jws-3>"

Output:
    The single 128-hex secp256k1 pubkey present in all candidate sets,
    suitable for `recto vault bootstrap <hex>`.
"""

from __future__ import annotations

import base64
import hashlib
import sys

# Make Recto importable from a checkout (no install required)
import pathlib
_repo_root = pathlib.Path(__file__).resolve().parents[1]
if (_repo_root / "recto").is_dir() and str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from recto.ethereum import recover_public_key


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def candidates_for_jws(jws: str) -> set[str]:
    """Return both rec_id=0 and rec_id=1 candidate pubkeys (hex) for one JWS."""
    parts = jws.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"JWS must have 3 dot-separated parts; got {len(parts)}")
    header_b64u, payload_b64u, sig_b64u = parts

    signing_input = f"{header_b64u}.{payload_b64u}".encode("ascii")
    digest = hashlib.sha256(signing_input).digest()

    sig = b64u_decode(sig_b64u)
    if len(sig) != 64:
        raise ValueError(f"JWS signature must be 64 bytes (r||s); got {len(sig)}")
    r = sig[:32]
    s = sig[32:]

    out: set[str] = set()
    for rec_id in (0, 1):
        try:
            pub = recover_public_key(digest, r + s + bytes([rec_id]))
        except Exception:
            continue
        # pub is 64 bytes X||Y (no SEC1 0x04 prefix)
        if len(pub) == 65 and pub[0] == 0x04:
            pub = pub[1:]
        if len(pub) != 64:
            continue
        out.add(pub.hex())
    return out


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: c4_recover_operator_pubkey.py <jws-1> <jws-2> [<jws-3>]",
            file=sys.stderr,
        )
        return 2

    jws_list = sys.argv[1:]
    print(f"Recovering operator pubkey from {len(jws_list)} JWS(es)...\n")

    candidate_sets: list[set[str]] = []
    for i, jws in enumerate(jws_list, 1):
        try:
            cs = candidates_for_jws(jws)
        except Exception as exc:
            print(f"JWS #{i}: parse/recovery failed: {exc}", file=sys.stderr)
            return 1
        print(f"JWS #{i}: {len(cs)} candidate(s)")
        for c in sorted(cs):
            print(f"  {c}")
        candidate_sets.append(cs)
        print()

    if not candidate_sets:
        print("No candidates extracted", file=sys.stderr)
        return 1

    intersection = candidate_sets[0]
    for cs in candidate_sets[1:]:
        intersection = intersection & cs

    print(f"Intersection: {len(intersection)} pubkey(s)")
    if len(intersection) == 1:
        pubkey = next(iter(intersection))
        print(f"\nOperator pubkey (128 hex): {pubkey}")
        print(f"\nNext step:")
        print(f"  recto vault bootstrap {pubkey}")
        return 0
    elif len(intersection) == 0:
        print("\nERROR: zero candidates in intersection.")
        print("All JWSes must come from the SAME signer. Verify they all", file=sys.stderr)
        print("originated from the iPhone (not from a stray fake-phone).", file=sys.stderr)
        return 1
    else:
        print("\nMultiple candidates -- need another JWS to disambiguate:")
        for c in sorted(intersection):
            print(f"  {c}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
