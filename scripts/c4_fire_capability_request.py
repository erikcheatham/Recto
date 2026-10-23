"""Phase 2.0.C C.4 hardware-ceremony helper -- fire one capability_request.

Posts a tiny Tier-0 capability_request to the local bootloader, polls until
the iPhone operator approves via Face ID, then prints the assembled JWS.

Run this 2-3 times after pairing the iPhone to collect distinct JWSes;
intersect their candidate pubkey sets via c4_recover_operator_pubkey.py to
uniquely resolve the operator's secp256k1 pubkey (SEC1 section 4.1.6).

Env vars required:
    RECTO_BOOTLOADER_URL    default http://localhost:8765
    RECTO_AGENT_ID          default myservice-agent
    RECTO_AGENT_TOKEN       (or MYSERVICE_AGENT_TOKEN as fallback)

Usage:
    python scripts\\c4_fire_capability_request.py
    python scripts\\c4_fire_capability_request.py --phone-id <uuid>

If --phone-id is omitted, picks the first ecdsa-p256 phone (the iPhone).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid


def post_json(url: str, body: dict, headers: dict) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} on POST {url}: {body_text}") from e


def get_json(url: str, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, method="GET")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} on GET {url}: {body_text}") from e


def main() -> int:
    ap = argparse.ArgumentParser(description="Fire one capability_request smoke")
    ap.add_argument("--phone-id", help="explicit iPhone phone_id; default: auto-pick first ecdsa-p256 phone")
    ap.add_argument("--purpose", default="C.4 smoke: operator pubkey recovery",
                    help="purpose string shown on the phone approval card")
    ap.add_argument("--poll-timeout", type=int, default=120,
                    help="seconds to wait for approval before timing out")
    args = ap.parse_args()

    bootloader = os.environ.get("RECTO_BOOTLOADER_URL", "http://localhost:8765").rstrip("/")
    agent_id = os.environ.get("RECTO_AGENT_ID", "myservice-agent")
    agent_token = (
        os.environ.get("RECTO_AGENT_TOKEN")
        or os.environ.get("MYSERVICE_AGENT_TOKEN")
    )
    if not agent_token:
        print("ERROR: set RECTO_AGENT_TOKEN or MYSERVICE_AGENT_TOKEN env var", file=sys.stderr)
        return 2

    auth_headers = {
        "X-Recto-Agent-Id": agent_id,
        "X-Recto-Agent-Token": agent_token,
    }

    # Resolve target phone_id
    phone_id = args.phone_id
    if not phone_id:
        # No HTTP list-all endpoint exposed; read phones.json from state dir.
        # Default state dir is C:\Users\<user>\.recto\bootloader\ on Windows.
        import pathlib
        state_dir = pathlib.Path(
            os.environ.get("RECTO_STATE_DIR",
                           str(pathlib.Path.home() / ".recto" / "bootloader"))
        )
        phones_path = state_dir / "phones.json"
        if not phones_path.is_file():
            print(f"ERROR: cannot find phones.json at {phones_path}. "
                  f"Pass --phone-id explicitly, or set RECTO_STATE_DIR.",
                  file=sys.stderr)
            return 1
        try:
            phones_doc = json.loads(phones_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"ERROR: cannot parse {phones_path}: {exc}", file=sys.stderr)
            return 1
        # phones.json structure: {"phones": [{...}, ...]} OR a dict keyed by phone_id
        phones_list: list[dict] = []
        if isinstance(phones_doc, dict):
            if "phones" in phones_doc and isinstance(phones_doc["phones"], list):
                phones_list = phones_doc["phones"]
            else:
                # dict keyed by phone_id
                for k, v in phones_doc.items():
                    if isinstance(v, dict):
                        v.setdefault("phone_id", k)
                        phones_list.append(v)
        elif isinstance(phones_doc, list):
            phones_list = phones_doc

        iphone = None
        for p in phones_list:
            algs = p.get("supported_algorithms") or [p.get("algorithm", "")]
            if "ecdsa-p256" in algs:
                iphone = p
                break
        if not iphone:
            algs_seen = [p.get("supported_algorithms") or [p.get("algorithm", "")] for p in phones_list]
            print(f"ERROR: no ecdsa-p256 phone in {phones_path}.\n"
                  f"  Total phones registered: {len(phones_list)}\n"
                  f"  Algorithms seen: {algs_seen}\n"
                  f"  Pass --phone-id explicitly if you know the iPhone's id.",
                  file=sys.stderr)
            return 1
        phone_id = iphone["phone_id"]
        label = iphone.get("device_label", "(unlabeled)")
        print(f"Auto-picked iPhone: phone_id={phone_id} label={label}")
    else:
        print(f"Targeting phone_id={phone_id} (from --phone-id)")

    # Build minimal Tier-0 CapabilityClaims
    now = int(time.time())
    jti = f"c4-smoke-{uuid.uuid4().hex[:12]}"
    claims = {
        "iss": "phone:operator:enclave",
        "sub": "agent:c4-smoke@devbox",
        "aud": ["c4-smoke"],
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": jti,
        "cap": {
            "tier": 0,
            "registry_version": "v1",
            "groups": [],
            "scope": {},
            "allow_actions": ["smoke:hello"],
            "deny_actions": [],
            "limits": {},
        },
        "purpose": args.purpose,
    }

    body = {
        "phone_id": phone_id,
        "claims": claims,
        "operation_description": args.purpose,
    }

    print(f"\nPOST {bootloader}/v0.4/capability/request")
    print(f"  jti={jti}")
    print(f"  Awaiting Face ID approval on iPhone...")
    resp = post_json(f"{bootloader}/v0.4/capability/request", body, headers=auth_headers)
    request_id = resp.get("request_id")
    result_path = resp.get("result_url")
    if not request_id or not result_path:
        print(f"ERROR: unexpected POST response: {json.dumps(resp, indent=2)}", file=sys.stderr)
        return 1
    result_url = result_path if result_path.startswith("http") else f"{bootloader}{result_path}"
    print(f"  request_id={request_id}")
    print(f"  polling {result_url}")

    # Poll until complete or timeout
    deadline = time.time() + args.poll_timeout
    poll_count = 0
    while time.time() < deadline:
        time.sleep(2)
        poll_count += 1
        try:
            result = get_json(result_url, headers=auth_headers)
        except RuntimeError as exc:
            print(f"  poll {poll_count}: {exc}")
            continue
        phase = result.get("phase")
        status = result.get("status")
        jws = result.get("capability_jws") or result.get("jws")

        # The bootloader's capability/result endpoint returns the assembled
        # JWS as soon as the phone approves. The exact terminal shape varies:
        # some paths set phase="complete" + status="approved", others set
        # only status="approved" with phase unset. Accept any of:
        #   (a) explicit jws field present (the load-bearing signal)
        #   (b) status in {approved, denied, signature_error, timeout, expired}
        # Result-store entries are single-use (take semantic) -- capture on
        # FIRST sight or we lose the JWS forever.
        terminal_statuses = {"approved", "denied", "signature_error", "timeout", "expired"}
        is_terminal = (
            phase == "complete"
            or jws
            or (status in terminal_statuses)
        )
        if is_terminal:
            if status == "approved" and jws:
                elapsed = result.get("elapsed_seconds", "?")
                print(f"\nAPPROVED in {elapsed}s")
                print(f"\nJWS (paste this into c4_recover_operator_pubkey.py):")
                print(jws)
                return 0
            elif status == "approved" and not jws:
                print(f"\nWARNING: status=approved but no JWS in response: {json.dumps(result, indent=2)}",
                      file=sys.stderr)
                return 1
            else:
                print(f"\nFAILED: status={status} reason={result.get('reason', '')}",
                      file=sys.stderr)
                return 1
        if poll_count % 5 == 0:
            print(f"  poll {poll_count}: phase={phase} status={status}")

    print(f"\nTIMEOUT after {args.poll_timeout}s -- iPhone never approved", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
