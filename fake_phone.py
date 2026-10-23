"""Software fake phone for Recto Phase 5 smoke testing.

NOT FOR PRODUCTION. This bypasses iOS Secure Enclave entirely:
generates an Ed25519 keypair in software, pairs with a Recto
bootloader using a pre-shared pairing code, then polls
/v0.4/pending and auto-approves every incoming request.

Use case: end-to-end smoke of consumer-side integrations (e.g.
MyService's IRectoCapabilityClient + DevTools "Recto" tab) without
needing a physical paired phone. Proves the wire shape works
across consumer -> bootloader -> "phone" -> bootloader -> consumer
in pure software.

Run AFTER starting the bootloader. The bootloader's startup banner
prints the pairing code; pass it as the only argument:

    python fake_phone.py 936099

The script blocks polling forever; Ctrl-C to stop. Every approval
prints a short summary line so you can see when MyService hits the
bootloader and the round-trip completes.

Capability JWS signing: for capability_request kinds, the Phase 5
protocol expects a secp256k1 signature over SHA-256(signing_input)
that the BOOTLOADER assembles into the final JWS. We generate a
fresh secp256k1 keypair in software too (separate from the Ed25519
envelope key); this means the assembled JWS verifies correctly
internally but the cross-check against bootloader's
capability_operator_pubkey will only pass if the bootloader was
launched with our generated pubkey configured. For the smoke-test
path where MyService just wants to receive the JWS and decode it,
this works without the cross-check.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def post_json(url: str, body: dict, headers: dict | None = None) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} on POST {url}: {body}") from e


def get_json(url: str, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, method="GET")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} on GET {url}: {body}") from e


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pairing_code", help="6-digit code from bootloader banner")
    parser.add_argument("--bootloader", default="http://localhost:8765",
                        help="bootloader base URL (default localhost:8765)")
    parser.add_argument("--device-label", default="fake-phone-dev",
                        help="label this fake phone reports during register")
    args = parser.parse_args()

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
        )
        from cryptography.hazmat.primitives import hashes, serialization
    except ImportError:
        print("ERROR: pip install cryptography>=42", file=sys.stderr)
        sys.exit(2)

    base = args.bootloader.rstrip("/")

    # Step 1: get registration challenge using the pairing code.
    # Note: this endpoint is GET on the bootloader, not POST.
    print(f"[fake-phone] requesting challenge from {base}", flush=True)
    chal_resp = get_json(
        f"{base}/v0.4/registration_challenge?code={args.pairing_code}",
    )
    challenge = chal_resp["challenge_b64u"]
    print(f"[fake-phone] got challenge (expires unix {chal_resp.get('expires_at_unix')})", flush=True)

    # Step 2: generate Ed25519 keypair, sign challenge, register.
    ed_priv = Ed25519PrivateKey.generate()
    ed_pub_bytes = ed_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sig_bytes = ed_priv.sign(challenge.encode("ascii"))
    register_body = {
        "v0_4_protocol": 1,
        "device_label": args.device_label,
        "supported_algorithms": ["ed25519"],
        "public_key_b64u": b64u_encode(ed_pub_bytes),
        "registration_proof": {
            "challenge": challenge,
            "signature_b64u": b64u_encode(sig_bytes),
        },
    }
    reg_resp = post_json(f"{base}/v0.4/register", body=register_body)
    phone_id = reg_resp["phone_id"]
    print(f"[fake-phone] PAIRED as phone_id={phone_id}", flush=True)

    # Generate secp256k1 keypair for capability JWS signing.
    cap_priv = ec.generate_private_key(ec.SECP256K1())
    cap_pub_numbers = cap_priv.public_key().public_numbers()
    cap_pub_x = cap_pub_numbers.x.to_bytes(32, "big")
    cap_pub_y = cap_pub_numbers.y.to_bytes(32, "big")
    cap_pub_uncompressed_64 = cap_pub_x + cap_pub_y
    print(f"[fake-phone] cap operator pubkey (hex, 64 bytes uncompressed): "
          f"{cap_pub_uncompressed_64.hex()}", flush=True)
    print(f"[fake-phone] (if bootloader was launched without "
          f"capability_operator_pubkey, no cross-check; JWS will assemble OK)",
          flush=True)

    # Step 3: poll /v0.4/pending and auto-approve everything.
    print(f"[fake-phone] polling {base}/v0.4/pending?phone_id={phone_id} every 1s. Ctrl-C to stop.", flush=True)
    seen_request_ids: set[str] = set()
    while True:
        try:
            pending = get_json(f"{base}/v0.4/pending?phone_id={phone_id}")
        except Exception as e:
            print(f"[fake-phone] poll error: {e}", flush=True)
            time.sleep(2)
            continue

        # Bootloader's GET /v0.4/pending returns {"requests": [...]} per
        # server.py:_handle_pending. Earlier draft of fake_phone read
        # "pending" which silently iterated an empty list and never
        # approved -- caught 2026-05-09 during MyService DevTools smoke.
        for req in pending.get("requests", []):
            request_id = req.get("request_id")
            kind = req.get("kind")
            if request_id is None or request_id in seen_request_ids:
                continue
            seen_request_ids.add(request_id)
            print(f"[fake-phone] approving request_id={request_id} kind={kind}", flush=True)

            # Build the Ed25519 envelope: sign the DECODED payload_hash_b64u
            # (32 raw SHA-256 hash bytes), NOT the request_id. The bootloader's
            # _handle_respond decodes payload_hash_b64u from the stashed
            # PendingRequest and verifies the signature against THOSE bytes.
            # See server.py:601-607. Earlier draft of fake_phone signed
            # request_id.encode("ascii") which produced a valid Ed25519 sig
            # over the wrong bytes -- bootloader rejected with
            # "approved-response signature invalid". Caught 2026-05-09
            # during MyService DevTools smoke (the iPhone hits same bug).
            payload_hash_b64u = req["context"]["payload_hash_b64u"]
            envelope_payload = b64u_decode(payload_hash_b64u)
            envelope_sig = ed_priv.sign(envelope_payload)

            # Bootloader's _handle_respond expects:
            #   decision == "approved" (NOT "approve" -- past tense)
            #   signature_b64u TOP-LEVEL (NOT nested under approved_response)
            #   cap_signature_b64u TOP-LEVEL when kind=capability_request
            # See server.py:556 _handle_respond. Earlier draft of fake_phone
            # used the nested "approved_response" envelope and "approve"
            # decision -- both wrong; bootloader returned 400
            # "unknown decision 'approve'". Caught 2026-05-09 during the
            # MyService DevTools smoke (same error iPhone hit -- not a
            # P-256 issue, just decision-string + envelope-shape mismatch).
            respond_body: dict = {
                "decision": "approved",
                "signature_b64u": b64u_encode(envelope_sig),
            }

            # If capability_request, also produce the cap_signature_b64u
            # over SHA-256(cap_header_b64.cap_payload_b64).
            if kind == "capability_request":
                cap_header_b64 = req["context"]["cap_header_b64"]
                cap_payload_b64 = req["context"]["cap_payload_b64"]
                signing_input = f"{cap_header_b64}.{cap_payload_b64}".encode("ascii")
                digest = hashlib.sha256(signing_input).digest()
                from cryptography.hazmat.primitives.asymmetric.utils import (
                    Prehashed,
                )
                # Prehashed = "input is already SHA-256 digest, sign it
                # directly" -- otherwise cryptography would re-hash.
                der_sig = cap_priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
                r, s = decode_dss_signature(der_sig)
                raw_rs = r.to_bytes(32, "big") + s.to_bytes(32, "big")
                respond_body["cap_signature_b64u"] = b64u_encode(raw_rs)
                print(f"[fake-phone]   cap signature attached ({len(raw_rs)} bytes raw r||s)",
                      flush=True)

            try:
                resp = post_json(f"{base}/v0.4/respond/{request_id}", body=respond_body)
                print(f"[fake-phone]   bootloader resp: {resp}", flush=True)
            except Exception as e:
                print(f"[fake-phone]   respond error: {e}", flush=True)

        time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[fake-phone] stopped", flush=True)
