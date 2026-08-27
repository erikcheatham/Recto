"""Example operator-side launcher for a Recto Phase 5 bootloader.

This is a reference for how to bring up a real Recto bootloader paired
with an operator's phone, with one or more external agents registered.
The example below wires MyService as the agent, but the same shape works
for any consumer that holds an agent identity in your bootloader's
``capability_agent_tokens`` map.

Usage:

    # 1. Pre-share an agent token between your bootloader and the consumer.
    #    Mint with `python -c "import secrets; print(secrets.token_hex(32))"`.
    #    Set in your shell:
    #
    #      Linux/macOS:  export MYSERVICE_AGENT_TOKEN=<64-hex>
    #      Windows PS:   $env:MYSERVICE_AGENT_TOKEN = "<64-hex>"
    #
    #    Write the SAME value to the consumer's secret store. For
    #    MyService-on-localhost that's user-secrets; for MyService-on-
    #    staging it's the dpapi-machine vault as
    #    RECTO_CAPABILITY_AGENT_TOKEN.

    # 2. (Optional) bootstrap the operator's secp256k1 pubkey so the
    #    consumer-side secret-read verifier can check signatures:
    #
    #      recto vault bootstrap <operator-pubkey-hex>

    # 3. Run this script:
    #
    #      python examples/run_bootloader_example.py

    # 4. Pair your phone against http://<this-machine-LAN-ip>:8765 via
    #    the Recto MAUI app's pairing flow.

    # 5. From the consumer (e.g. MyService's DevTools "Recto" tab),
    #    click Fetch manifest -> Run round-trip -> approve on phone.

The script binds 0.0.0.0 so the phone (LAN) AND the consumer (any
LAN-reachable host or, if behind Docker, via host.docker.internal)
can both reach it. Lock to 127.0.0.1 if you want loopback-only access.
"""

from __future__ import annotations

import os
import pathlib
import sys

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import AppContext, StateStore


# Where the bootloader keeps its persistent state (paired phones,
# revocations, vault_root.json, etc.). Default puts it under your home
# dir so `recto vault bootstrap` writes to the same place.
STATE_DIR = pathlib.Path(os.path.expanduser("~/.recto/bootloader"))

BIND_HOST = "0.0.0.0"
BIND_PORT = 8765


def main() -> None:
    agent_token = os.environ.get("MYSERVICE_AGENT_TOKEN", "").strip()
    if not agent_token:
        print(
            "ERROR: MYSERVICE_AGENT_TOKEN env var is unset.\n"
            "Mint one with `python -c \"import secrets; print(secrets.token_hex(32))\"`,\n"
            "set it in your shell, write the SAME value to the consumer's\n"
            "secret store, then re-run this script.",
            file=sys.stderr,
        )
        sys.exit(2)

    if len(agent_token) != 64:
        print(
            f"ERROR: MYSERVICE_AGENT_TOKEN must be 64 hex chars, got {len(agent_token)}.",
            file=sys.stderr,
        )
        sys.exit(2)

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state = StateStore(state_dir=STATE_DIR)

    # Construct the ChallengeStore explicitly so we can mint a pairing
    # code below from the SAME instance the bootloader will consume from
    # at registration time. If create_server() is called with
    # challenges=None it auto-creates one internally -- but then the
    # launcher has no way to mint a code on it, and pairing is impossible
    # without first hitting some out-of-band code-issue endpoint (which
    # the bare bootloader doesn't ship). Owning the ChallengeStore here
    # is the canonical fix.
    challenges = ChallengeStore()

    # Locate the bundled v1 action manifest -- ships with the Recto
    # package at recto/capability/manifest_v1.json. The bootloader's
    # GET /v0.4/capability/manifest serves this verbatim with ETag
    # caching; without it the endpoint returns 404 "no_manifest_configured"
    # which makes consumer-side connectivity smoke tests fail with
    # 502 instead of 200 (the MyService DevTools "Fetch manifest"
    # button fires this).
    manifest_path = pathlib.Path(__file__).resolve().parent.parent \
        / "recto" / "capability" / "manifest_v1.json"

    server = create_server(
        bind_host=BIND_HOST,
        bind_port=BIND_PORT,
        state=state,
        challenges=challenges,
        bootloader_id="recto-example",
        capability_agent_tokens={
            "myservice-agent": agent_token,
        },
        capability_manifest_path=str(manifest_path) if manifest_path.exists() else None,
        principal_apps={
            "myservice-agent": AppContext(
                app_id="myservice",
                app_name="MyService",
                app_description="Media review platform",
                app_url="https://example.com",
                # Phone fetches this image at approval time and renders it in
                # the request-header banner. The staging URL works publicly
                # over the internet now that the WAF "Allow public brand
                # assets on staging" Skip rule (shipped 2026-05-11) carves
                # /_content/MyService.Shared/brand/* out of the IP-whitelist
                # gate — phones on cellular / theater / cafe fetch directly.
                # Alternatives for other deployment shapes:
                #   * Dev (the dev workstation bootloader, reachable by name
                #     on your own network): http://dev-workstation:7199/_content/MyService.Shared/brand/myservice-logo-1024.png
                #   * Prod (when example.com goes live): https://example.com/_content/MyService.Shared/brand/myservice-logo-1024.png
                # The phone caches the fetched bytes per the AppContext.
                app_icon_url="https://staging.example.com/_content/MyService.Shared/brand/myservice-logo-1024.png",
            ),
        },
    )

    # Mint a 6-digit pairing code valid for 1 hour. The operator types
    # this into the Recto MAUI app's Pair screen alongside the bootloader
    # URL. The default ttl_seconds is 300 (5 min) which is too tight
    # for the typical "find phone, unlock, open app, type" sequence on
    # a fresh-pair flow -- bump to 3600 for breathing room.
    pairing_code, pairing_exp = challenges.issue_pairing_code(ttl_seconds=3600)

    pubkey = state.get_operator_pubkey()
    pubkey_status = (
        f"operator pubkey loaded ({pubkey.hex()[:16]}...)"
        if pubkey is not None
        else "no operator pubkey -- run `recto vault bootstrap <hex>` for full verifier path"
    )

    print()
    print(f"Recto bootloader listening on http://{BIND_HOST}:{BIND_PORT}/")
    print(f"State dir: {STATE_DIR}")
    print(f"{pubkey_status}")
    print(f"Agents:    myservice-agent (token = {agent_token[:8]}...)")
    print()
    print("=" * 60)
    print(f"PAIRING CODE:  {pairing_code}")
    print(f"               (valid 60 min; expires unix {pairing_exp})")
    print("=" * 60)
    print()
    print("From your phone, open the Recto MAUI app -> Pair screen, enter:")
    print(f"   bootloader URL = http://<this-machine-LAN-ip>:{BIND_PORT}")
    print(f"   pairing code   = {pairing_code}")
    print()
    print("From MyService DevTools, hit the Recto tab and click Round-trip.")
    print("Ctrl-C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
