r"""Recto bootloader launcher -- env-var-parameterized for any consumer.

A thin orchestrator that reads its consumer-specific configuration
from environment variables, then calls
``recto.bootloader.server.create_server(...)``. The same script ships
unmodified to every consumer (MyService, MyTradingApp, MyTokenContract,
or any new Phase-5+ integrator) -- per-consumer values come in via env
vars instead of being hardcoded into a per-consumer fork.

This addresses the v1.0 sanitization finding (banked 2026-05-11) that
the prior shape forced every consumer to maintain a private fork of
this script just to inject their own VAULT_SERVICE, BOOTLOADER_ID,
agent_id, AppContext, etc. Forks meant future Recto-side fixes
(new endpoints, new safety checks) didn't auto-propagate -- a real
problem for substrate maintenance. Now the script is consumer-
agnostic and consumers configure via env.

Env var contract
================

Required:
    RECTO_BOOTLOADER_ID    Server identity. Appears on the operator's
                           phone after pairing as the "bootloader id"
                           field. Convention: "recto-<consumer>-
                           <env>", e.g., "recto-myservice-staging".

Optional (with defaults):
    RECTO_BIND_HOST        Listen interface. Default: "0.0.0.0".
                           Set to "127.0.0.1" for loopback-only.
    RECTO_BIND_PORT        Listen port. Default: "8765".
    RECTO_STATE_DIR        Where state.json + phones.json + sessions.json
                           live across restarts. Default:
                           "C:\\ProgramData\\Recto\\{bootloader_id}\\".
    RECTO_PUBLIC_URL       URL the operator's phone uses to reach this
                           bootloader (typically a Cloudflare Tunnel
                           hostname). Default: derives from bind host
                           + port. Surfaced in the startup banner +
                           pairing instructions.

Agent registration (optional but recommended -- without it, the
capability endpoints return 404):
    RECTO_AGENT_ID         The operator-trusted agent's identifier.
                           Convention: "<consumer>-<purpose>", e.g.,
                           "myservice-agent". Only inbound capability
                           requests carrying this exact agent_id +
                           the matching token authenticate.
    RECTO_AGENT_TOKEN      The agent's bearer token (64 hex chars).
                           When set, used directly. When unset, the
                           script falls back to fetching the token
                           from the dpapi-machine vault (see below).
                           Supervised-launcher case: Recto's launcher
                           injects this from a vault-decrypt at
                           child-spawn.
    RECTO_VAULT_SERVICE    dpapi-machine vault service name to read
                           the agent token from when RECTO_AGENT_TOKEN
                           is unset. Foreground bring-up convention.
    RECTO_VAULT_SECRET     dpapi-machine vault secret name within the
                           service. Default: "RECTO_CAPABILITY_AGENT_TOKEN"
                           (the canonical Recto convention).

AppContext (optional -- without it, the phone shows "Unknown app"
warning instead of the consumer's branded approval card):
    RECTO_APP_ID           Stable consumer-app identifier (e.g.,
                           "myservice"). Both RECTO_APP_ID and
                           RECTO_APP_NAME must be set to register an
                           AppContext; either alone is ignored.
    RECTO_APP_NAME         Display name shown on the phone (e.g.,
                           "MyService").
    RECTO_APP_DESCRIPTION  One-line tagline shown under the name.
                           Default: empty string.
    RECTO_APP_URL          Consumer's homepage / web tier URL.
                           Default: empty string.
    RECTO_APP_ICON_URL     Public URL for the consumer's icon shown
                           at the top of every approval card. Default:
                           empty string. The phone fetches this URL
                           anonymously, so it must be publicly
                           reachable (Cloudflare Access carve-out
                           required if the URL is behind an OTP gate).

Pairing-code mint (existing convention):
    RECTO_BOOTLOADER_QUIET  Set to "1" to suppress the startup-printed
                            pairing code (foreground convenience). When
                            running supervised, set this to "1" so each
                            restart doesn't issue a throwaway code.
                            Operators mint codes on demand via
                            POST /v0.4/pairing/code regardless.

Folder-drop event bus (RECTO_EVENTS_DIR, banked 2026-05-19 night):
    When set + writable, the launcher constructs a FileEventEmitter
    that emits capability + sign lifecycle events as JSONL records
    to <events_dir>/<YYYY-MM-DD>.jsonl. Peer-AIs on the host
    filesystem (Cowork instances, openclaw skills, audit watchers)
    tail-watch the daily files without polling the bootloader's HTTP
    surface. Substrate-level architectural primitive for AI-to-AI
    peer communication; complementary to HTTP capability_request
    (sync) — folder-drop is for async notifications. Unset = events
    not emitted (zero overhead; the bootloader's pre-events-folder
    behavior). Typical Docker bind-mount layout:

        # host-side compose volume mount:
        volumes:
          - ./recto-events:/var/lib/recto/events

        # container-side env var:
        environment:
          - RECTO_EVENTS_DIR=/var/lib/recto/events

    See recto/bootloader/events.py for the FileEventEmitter primitive
    and the canonical event-payload schema documentation.

Phase H end-user device pairing relay (RECTO_DEVICES_PAIR_CONSUMERS_FILE):
    For bootloaders that broker end-user device pairing on behalf of
    consumer apps (Phase H, 2026-05-19), set this env var to the path
    of a JSON manifest declaring which consumer URLs the bootloader
    should relay to. Without this env var (or with an empty consumers
    array), the POST /v0.4/devices/pair endpoint returns 404 (zero
    attack surface for bootloaders that don't broker pairing).

        $env:RECTO_DEVICES_PAIR_CONSUMERS_FILE = "C:\Recto\devices-pair-consumers.json"

    See examples/devices-pair-consumers.json.example for the canonical
    shape. Token resolution per consumer:
      1. consumer.token_env (if set, read os.environ[that name])
      2. consumer.vault_service + consumer.vault_secret (dpapi-machine fetch)
    First non-empty wins. Default vault_secret is
    "OPENCLAW_WEBHOOK_SECRET" -- v0 posture reuses the consumer's
    existing Openclaw webhook secret as the devices-pair webhook
    token (split into a dedicated secret later, likely alongside the
    Hermes-cutover key rename per the 2026-05-19 architectural call).

Connections substrate (RECTO_CONNECTIONS_FILE):
    For bootloaders that broker provider API-key management on behalf
    of consumer apps (Recto Connections, 2026-06-13), set these env
    vars. Without RECTO_CONNECTIONS_FILE, ALL /v0.4/connections/*
    endpoints return 404 (zero attack surface).

    DOCKERIZED topology (the canonical dockerized deployment -- the
    bootloader is a LINUX container, so paths are container paths and
    DPAPI is unavailable):

        RECTO_CONNECTIONS_FILE          = /var/lib/recto/bootloader/connections.json
        RECTO_CONNECTIONS_AGENT_SERVICES= {"my-agent":"MyService"}
        RECTO_CAPABILITY_OPERATOR_TOKEN = <injected by host launcher from the
                                           OPERATOR_WRITE_TOKEN vault entry>
        RECTO_CONNECTIONS_SECRET_DIR    = /var/lib/recto/bootloader/connections-secrets

    Use container paths INSIDE the bootloader-data named volume (survives
    rebuilds, host-private) -- a Windows path like C:\ProgramData\... is
    invisible to the Linux container.

    RECTO_CONNECTIONS_FILE points at the secret-free connections metadata
    sidecar (auto-created empty on first write; secret VALUES never land
    here). RECTO_CONNECTIONS_PATH is accepted as a legacy alias.

    RECTO_CONNECTIONS_AGENT_SERVICES maps each consumer agent_id to the
    ONE service it may READ -- JSON object {"agent":"Service"} OR compact
    CSV agent:Service,agent2:Service2. Reads (list metadata + fetch a
    secret value) are agent-token-gated AND service-scoped via this map;
    writes (upsert/rotate/enable/delete) are operator-gated.

    The operator write token (X-Recto-Operator-Token, the gate for writes
    AND /v0.4/capability/revoke) resolves first from
    $env:RECTO_CAPABILITY_OPERATOR_TOKEN (canonical, sister of
    RECTO_CAPABILITY_AGENT_TOKEN; the host launcher injects it before the
    container spawns), then $env:RECTO_OPERATOR_WRITE_TOKEN (legacy alias),
    then a dpapi-machine fetch (Windows-host foreground only -- no-ops in
    a container). Unresolved => writes stay 404 (reads still work). The
    token never transits stdout / history.

    Per-connection SECRET VALUES (conn.<key>) are read/written at runtime
    through the /v0.4/connections HTTP surface. DPAPI is Windows-bound and
    CANNOT decrypt inside a Linux container, so set RECTO_CONNECTIONS_SECRET_DIR
    to a file-backed store inside the named volume -- otherwise the first
    real secret write/read 500s. UNSET keeps the DpapiMachineSource default
    (foreground Windows-host path).

Multi-agent mode (RECTO_AGENTS_FILE):
    For deployments where ONE bootloader serves MULTIPLE consumer
    agents (e.g., two apps both registered against the same
    paired phone), the per-agent env vars above (RECTO_AGENT_ID /
    RECTO_VAULT_SERVICE / RECTO_APP_*) don't compose well -- they're
    single-tenant by shape. Set RECTO_AGENTS_FILE to the path of a
    JSON manifest instead:

        $env:RECTO_AGENTS_FILE = "C:\Recto\agents.json"

    See examples/agents.json.example for the canonical shape. When
    RECTO_AGENTS_FILE is set, the per-agent env vars are IGNORED
    (manifest is the single source of truth) and the bootloader
    registers every agent in the file. Same paired phone sees N
    distinct AppContext approval cards depending on which agent
    fired the request -- each card renders its own app icon, name,
    description.

    Token resolution per agent (in priority order):
      1. agent.token_env (if set, read os.environ[that name])
      2. agent.vault_service + agent.vault_secret (dpapi-machine fetch)
    First non-empty wins. Length-check (64 hex) applies to every agent.

Production state backend (RECTO_STATE_BACKEND, banked 2026-07-12):
    The state store defaults to the file-backed StateStore inside
    RECTO_STATE_DIR (single-instance posture, Hard Rule #4). For
    load-balanced / multi-instance deployments (e.g. Azure Container
    Apps with N replicas) select the PostgreSQL backend:

        RECTO_STATE_BACKEND       "file" (default) | "postgres"
        RECTO_POSTGRES_DSN        direct DSN (dev/test convenience;
                                  prefer the secret path in production)
        RECTO_POSTGRES_DSN_SECRET secret NAME resolved via the
                                  production secret source when
                                  RECTO_POSTGRES_DSN is unset.
                                  Default: "postgres-dsn"
        RECTO_POSTGRES_SCHEMA     schema name. Default: "recto_bootloader"

    Requires `pip install recto[postgres]` (the Docker image's
    RECTO_EXTRAS build arg must include `postgres`). The schema
    auto-creates on first boot (idempotent DDL); pool init is
    fail-fast so a bad DSN kills the process at startup, not 30s
    into the first request.

Production secret source (RECTO_SECRET_SOURCE):
    Where the launcher resolves production secret VALUES (the
    Postgres DSN, push-sender credentials) OUTSIDE the Windows
    dpapi-machine vault -- Linux containers cannot decrypt DPAPI.

        RECTO_SECRET_SOURCE       "" (none, default) | "azure-keyvault"
        RECTO_SECRET_SERVICE      service scope for the SecretSource's
                                  {service}--{name} normalization.
                                  Default: "recto"
        RECTO_AZURE_KEYVAULT_URL  vault URL, e.g.
                                  https://my-vault.vault.azure.net/
                                  (read by AzureKeyVaultSource; auth is
                                  DefaultAzureCredential -- Managed
                                  Identity inside Azure, az login
                                  locally)

    Requires `pip install recto[azure]` for azure-keyvault. Example:
    RECTO_SECRET_SERVICE=recto + RECTO_POSTGRES_DSN_SECRET=postgres-dsn
    resolves the Key Vault secret named `recto--postgres-dsn`.

Silent-push wake senders (RECTO_PUSH_*, all optional):
    When configured, queued requests fire an APNs / FCM silent wake
    at the operator's registered phones (recto.bootloader.push).
    Missing or failing push config degrades to a stderr WARN --
    polling remains the permanent fallback, never a hard dependency.

        RECTO_PUSH_APNS_TEAM_ID    Apple Developer team id
        RECTO_PUSH_APNS_KEY_ID     APNs auth-key id
        RECTO_PUSH_APNS_BUNDLE_ID  phone app bundle id (apns-topic)
        RECTO_PUSH_APNS_SANDBOX    "1" selects the sandbox gateway
        RECTO_PUSH_APNS_P8_SECRET  secret NAME (via the secret source)
                                   holding the .p8 key PEM, or:
        RECTO_PUSH_APNS_P8_FILE    filesystem path to the .p8 PEM
        RECTO_PUSH_FCM_PROJECT_ID  Firebase project id
        RECTO_PUSH_FCM_SA_SECRET   secret NAME holding the service-
                                   account JSON, or:
        RECTO_PUSH_FCM_SA_FILE     filesystem path to the JSON

    Requires `pip install recto[push]`.

Multi-URL failover (RECTO_PUBLIC_URLS, optional):
    Comma-separated public URLs, PRIMARY FIRST. When set, pairing
    registration responses carry the additive `bootloader_urls`
    field so phones persist the failover list (wave-C protocol
    extension). Unset keeps single-URL responses byte-identical to
    v1. RECTO_PUBLIC_URL (singular) remains the banner/pairing URL.

Usage
=====

Initial pairing ceremony (foreground; reads token from vault):

    $env:RECTO_BOOTLOADER_ID  = "recto-myservice-staging"
    $env:RECTO_AGENT_ID       = "myservice-agent"
    $env:RECTO_VAULT_SERVICE  = "MyService"
    $env:RECTO_APP_ID         = "myservice"
    $env:RECTO_APP_NAME       = "MyService"
    $env:RECTO_APP_DESCRIPTION = "Media review platform"
    $env:RECTO_APP_URL        = "https://example.com"
    $env:RECTO_APP_ICON_URL   = "https://example.com/icon.png"
    $env:RECTO_PUBLIC_URL     = "https://bootloader.example.com"
    .\.venv\Scripts\python.exe examples\run_bootloader_consumer.py

Supervised run (quiet, no banner; Recto launcher injects
RECTO_AGENT_TOKEN from dpapi-machine vault):

    $env:RECTO_BOOTLOADER_QUIET = "1"
    .\.venv\Scripts\python.exe examples\run_bootloader_consumer.py

When wrapping this via a sibling ``service.yaml``, all the env vars
above land as plain ``spec.env`` entries; ``RECTO_AGENT_TOKEN`` comes
from the launcher's vault-decrypt at child-spawn.

Multi-agent supervised run: declare each per-agent token env var name
in service.yaml's ``spec.secrets`` block (one per agent), point them
at distinct dpapi-machine vault entries, and set RECTO_AGENTS_FILE to
the manifest path. Recto's launcher decrypts every secret at
child-spawn and the manifest's ``token_env`` field on each agent
picks up the matching env var.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import sys

from recto.bootloader.events import construct_from_env as construct_events_emitter
from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import AppContext, StateStore
from recto.secrets.dpapi_machine import DpapiMachineSource


# ---------------------------------------------------------------------------
# Env helpers
# ---------------------------------------------------------------------------


def _env(name: str, *, default: str | None = None, required: bool = False) -> str | None:
    """Read an env var (stripped). Returns default if unset/empty.
    Exits with code 2 if required and unset.
    """
    raw = os.environ.get(name, "")
    val = raw.strip() if isinstance(raw, str) else ""
    if val:
        return val
    if required:
        print(
            f"ERROR: required env var {name} is unset or empty.",
            file=sys.stderr,
        )
        print(
            "See examples/run_bootloader_consumer.py docstring for the "
            "full env var contract.",
            file=sys.stderr,
        )
        sys.exit(2)
    return default


def _env_int(name: str, *, default: int) -> int:
    """Read an env var as an int. Returns default if unset; exits with
    code 2 on parse error."""
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        print(
            f"ERROR: env var {name}={raw!r} is not a valid integer.",
            file=sys.stderr,
        )
        sys.exit(2)


# ---------------------------------------------------------------------------
# Agent token resolution
# ---------------------------------------------------------------------------


def _resolve_token_for_agent(agent: dict) -> str:
    """Resolve the token for one agent dict (manifest-shape).

    Priority:
      1. ``agent["token_env"]`` -- read os.environ at that name. The
         supervised-launcher case: Recto's launcher decrypts the vault
         entry and injects under whatever env var name the operator
         declared in the manifest.
      2. ``agent["vault_service"]`` + ``agent["vault_secret"]`` --
         direct dpapi-machine fetch. The foreground bring-up case --
         operator runs this script without per-agent token env vars
         set; the script decrypts in-process from the configured
         vault service.

    Returns "" when neither source resolves; caller surfaces the
    error with agent_id context. The token never transits PowerShell
    history, command-line args, or stdout in either path.
    """
    token_env = (agent.get("token_env") or "").strip()
    if token_env:
        env_token = os.environ.get(token_env, "").strip()
        if env_token:
            return env_token

    vault_service = (agent.get("vault_service") or "").strip()
    if not vault_service:
        return ""

    vault_secret = (
        (agent.get("vault_secret") or "").strip()
        or "RECTO_CAPABILITY_AGENT_TOKEN"
    )

    try:
        source = DpapiMachineSource(vault_service)
        material = source.fetch(vault_secret, {})
    except Exception as ex:
        print(
            f"WARN: vault fetch for {vault_service}/{vault_secret} failed: "
            f"{type(ex).__name__}: {ex}",
            file=sys.stderr,
        )
        return ""
    return (material.value or "").strip()


# ---------------------------------------------------------------------------
# Connections substrate (Recto Connections, 2026-06-13)
# ---------------------------------------------------------------------------


def _parse_connections_agent_services(
    raw: str, var_name: str = "RECTO_CONNECTIONS_AGENT_SERVICES"
) -> dict[str, str]:
    """Parse an agent_id -> namespace map env var (`var_name` names the
    variable in error output; the user-vault substrate reuses this parser
    for RECTO_USER_VAULT_AGENT_PLATFORMS).

    Two accepted formats (JSON wins if the value starts with '{'):
      1. JSON object: {"my-agent": "MyService"}
      2. Compact CSV:  my-agent:MyService,other-agent:OtherService

    Empty / unset => {} (no agent may read connections even when
    connections_path is set; matches the create_server default).
    Exits with code 2 on malformed input.
    """
    raw = (raw or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as ex:
            print(
                f"ERROR: {var_name} is not valid JSON: {ex}",
                file=sys.stderr,
            )
            sys.exit(2)
        if not isinstance(obj, dict):
            print(
                f"ERROR: {var_name} JSON must be an object "
                "(agent_id -> service).",
                file=sys.stderr,
            )
            sys.exit(2)
        return {
            str(k).strip(): str(v).strip()
            for k, v in obj.items()
            if str(k).strip() and str(v).strip()
        }
    out: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            print(
                f"ERROR: {var_name} entry {pair!r} is not "
                "'agent_id:service'.",
                file=sys.stderr,
            )
            sys.exit(2)
        agent_id, service = pair.split(":", 1)
        agent_id, service = agent_id.strip(), service.strip()
        if agent_id and service:
            out[agent_id] = service
    return out


def _parse_connections_agent_keys(
    raw: str, var_name: str = "RECTO_CONNECTIONS_AGENT_KEYS"
) -> dict[str, list[str]]:
    """Parse an agent_id -> key-pattern-LIST map env var.

    Sister of `_parse_connections_agent_services`, but the value is a list
    of allowlist patterns rather than a single namespace.

    Two accepted formats (JSON wins if the value starts with '{'):
      1. JSON object: {"my-agent": ["anthropic", "media-*"]}
      2. Compact CSV:  my-agent:anthropic|media-*,other-agent:*

    A JSON value may also be a bare string ("my-agent": "anthropic") as a
    one-pattern convenience. Empty / unset => {} (no agent allowlisted;
    default-deny once enforcement is on).
    Exits with code 2 on malformed input.
    """
    raw = (raw or "").strip()
    if not raw:
        return {}
    out: dict[str, list[str]] = {}
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as ex:
            print(f"ERROR: {var_name} is not valid JSON: {ex}", file=sys.stderr)
            sys.exit(2)
        if not isinstance(obj, dict):
            print(
                f"ERROR: {var_name} JSON must be an object "
                "(agent_id -> [key patterns]).",
                file=sys.stderr,
            )
            sys.exit(2)
        for agent_id, value in obj.items():
            agent_id = str(agent_id).strip()
            if not agent_id:
                continue
            if isinstance(value, str):
                patterns = [value]
            elif isinstance(value, list):
                patterns = [str(v) for v in value]
            else:
                print(
                    f"ERROR: {var_name} entry for {agent_id!r} must be a "
                    "string or a list of strings.",
                    file=sys.stderr,
                )
                sys.exit(2)
            cleaned = [p.strip() for p in patterns if p and p.strip()]
            if cleaned:
                out[agent_id] = cleaned
        return out
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            print(
                f"ERROR: {var_name} entry {pair!r} is not "
                "'agent_id:pattern|pattern'.",
                file=sys.stderr,
            )
            sys.exit(2)
        agent_id, patterns_raw = pair.split(":", 1)
        agent_id = agent_id.strip()
        cleaned = [p.strip() for p in patterns_raw.split("|") if p.strip()]
        if agent_id and cleaned:
            out[agent_id] = cleaned
    return out


def _resolve_operator_write_token() -> str:
    """Resolve the X-Recto-Operator-Token that gates connections WRITE
    routes (upsert / enable / delete) -- and, by the same field,
    /v0.4/capability/revoke.

    Priority (first non-empty wins):
      1. $env:RECTO_CAPABILITY_OPERATOR_TOKEN -- the canonical name,
         sister of RECTO_CAPABILITY_AGENT_TOKEN. In the dockerized
         topology Recto's host launcher decrypts the vault entry
         (OPERATOR_WRITE_TOKEN) and injects it under this env var
         BEFORE the Linux container spawns -- the container never
         touches DPAPI (it cannot; DPAPI is Windows-bound).
      2. $env:RECTO_OPERATOR_WRITE_TOKEN -- legacy alias.
      3. dpapi-machine fetch from RECTO_CONNECTIONS_VAULT_SERVICE /
         RECTO_OPERATOR_WRITE_SECRET (default OPERATOR_WRITE_TOKEN).
         ONLY works on a Windows host running the bootloader in the
         foreground; no-ops to "" inside a Linux container.

    Returns "" when none resolves; WRITE routes then return 404
    (reads still work). The token never transits PowerShell history,
    command-line args, or stdout in any path.
    """
    for env_name in ("RECTO_CAPABILITY_OPERATOR_TOKEN", "RECTO_OPERATOR_WRITE_TOKEN"):
        env_token = os.environ.get(env_name, "").strip()
        if env_token:
            return env_token

    vault_service = (os.environ.get("RECTO_CONNECTIONS_VAULT_SERVICE") or "").strip()
    if not vault_service:
        return ""
    vault_secret = (
        (os.environ.get("RECTO_OPERATOR_WRITE_SECRET") or "").strip()
        or "OPERATOR_WRITE_TOKEN"
    )
    try:
        source = DpapiMachineSource(vault_service)
        material = source.fetch(vault_secret, {})
    except Exception as ex:
        print(
            f"WARN: vault fetch for operator write token "
            f"{vault_service}/{vault_secret} failed: {type(ex).__name__}: {ex}",
            file=sys.stderr,
        )
        return ""
    return (material.value or "").strip()


def _build_connections_secret_factory():
    """Choose the backend that stores per-connection SECRET VALUES
    (conn.<key>) for runtime set/get through the bootloader's
    /v0.4/connections HTTP surface.

    DPAPI is Windows-bound and CANNOT decrypt inside a Linux container,
    so the dockerized bootloader MUST NOT use the create_server default
    (DpapiMachineSource) -- the first real secret write/read would 500.

    Topology switch via $env:RECTO_CONNECTIONS_SECRET_DIR:
      * SET   -> file-backed store under that directory (point it at a
                 host-private, rebuild-surviving path, e.g. inside the
                 bootloader-data named volume:
                 /var/lib/recto/bootloader/connections-secrets). This is
                 the dockerized / non-Windows path.
      * UNSET -> return None so create_server keeps its DpapiMachineSource
                 default (the foreground Windows-host path, where DPAPI
                 works).

    The value never transits stdout; FileBackedSecretSource persists it
    0o600 under a per-service dir and redacts it from every __repr__.
    """
    secret_dir = (os.environ.get("RECTO_CONNECTIONS_SECRET_DIR") or "").strip()
    if not secret_dir:
        return None  # create_server falls back to DpapiMachineSource
    from recto.secrets.file_backed import FileBackedSecretSource

    return lambda service: FileBackedSecretSource(service, base_dir=secret_dir)


def _build_user_vault_secret_factory():
    """User-vault sister of _build_connections_secret_factory: choose the
    backend that stores per-user secret VALUES (uv.<user_id>.<key>).

    Topology switch via $env:RECTO_USER_VAULT_SECRET_DIR:
      * SET   -> file-backed store under that directory (dockerized /
                 non-Windows path; point it inside the bootloader-data
                 named volume, e.g.
                 /var/lib/recto/bootloader/user-vault-secrets).
      * UNSET -> None, so create_server keeps its DpapiMachineSource
                 default (foreground Windows-host path, blobs under
                 %PROGRAMDATA%\\recto\\<platform>\\uv.*.dpapi).
    """
    secret_dir = (os.environ.get("RECTO_USER_VAULT_SECRET_DIR") or "").strip()
    if not secret_dir:
        return None  # create_server falls back to DpapiMachineSource
    from recto.secrets.file_backed import FileBackedSecretSource

    return lambda service: FileBackedSecretSource(service, base_dir=secret_dir)


# ---------------------------------------------------------------------------
# Production backends (state store + secret source + push senders)
# ---------------------------------------------------------------------------


def _build_prod_secret_source():
    """Construct the production SecretSource selected by
    RECTO_SECRET_SOURCE, or None when unset (dev / single-host posture).

    "azure-keyvault" -> recto.secrets.azure_keyvault.AzureKeyVaultSource
    scoped to RECTO_SECRET_SERVICE (default "recto"); the vault URL
    comes from RECTO_AZURE_KEYVAULT_URL and auth is
    DefaultAzureCredential (Managed Identity inside Azure).

    Fail-loud: an unknown selector or a broken vault config exits 2 at
    startup rather than 500ing on the first secret fetch.
    """
    selector = (os.environ.get("RECTO_SECRET_SOURCE") or "").strip().lower()
    if not selector:
        return None
    service = _env("RECTO_SECRET_SERVICE", default="recto")
    if selector == "azure-keyvault":
        try:
            from recto.secrets.azure_keyvault import AzureKeyVaultSource

            return AzureKeyVaultSource(service)
        except Exception as ex:
            print(
                f"ERROR: RECTO_SECRET_SOURCE=azure-keyvault init failed: "
                f"{type(ex).__name__}: {ex}",
                file=sys.stderr,
            )
            sys.exit(2)
    print(
        f"ERROR: unknown RECTO_SECRET_SOURCE={selector!r} "
        "(supported: 'azure-keyvault').",
        file=sys.stderr,
    )
    sys.exit(2)


def _fetch_prod_secret(secret_source, secret_name: str) -> str | None:
    """Fetch a secret VALUE from the production secret source.

    Returns None (with a stderr WARN) on any failure -- the CALLER
    decides whether the secret is a hard dependency. The value never
    transits stdout (Hard Rule #2).
    """
    if secret_source is None:
        return None
    try:
        material = secret_source.fetch(secret_name, {})
    except Exception as ex:
        print(
            f"WARN: secret fetch {secret_name!r} via "
            f"{type(secret_source).__name__} failed: "
            f"{type(ex).__name__}: {ex}",
            file=sys.stderr,
        )
        return None
    value = (material.value or "").strip()
    return value or None


def _build_state_store(state_dir, secret_source):
    """Choose the bootloader state backend per RECTO_STATE_BACKEND.

    Returns (store, banner_line). "file" (default) keeps the zero-setup
    file-backed StateStore (Hard Rule #4 -- single-file-runnable).
    "postgres" constructs PostgresStateStore against a DSN resolved
    from RECTO_POSTGRES_DSN (direct) or the production secret source
    (RECTO_POSTGRES_DSN_SECRET, default "postgres-dsn"). Fail-loud on
    an unresolvable DSN or unknown backend; the DSN VALUE is never
    echoed in any error path.
    """
    backend = (os.environ.get("RECTO_STATE_BACKEND") or "file").strip().lower()
    if backend in ("", "file"):
        return (
            StateStore(state_dir=state_dir),
            f"file-backed at {state_dir}",
        )
    if backend != "postgres":
        print(
            f"ERROR: unknown RECTO_STATE_BACKEND={backend!r} "
            "(supported: 'file', 'postgres').",
            file=sys.stderr,
        )
        sys.exit(2)

    dsn = (os.environ.get("RECTO_POSTGRES_DSN") or "").strip()
    dsn_origin = "RECTO_POSTGRES_DSN"
    if not dsn:
        secret_name = _env("RECTO_POSTGRES_DSN_SECRET", default="postgres-dsn")
        dsn = _fetch_prod_secret(secret_source, secret_name) or ""
        dsn_origin = f"secret {secret_name!r}"
        if not dsn:
            print(
                "ERROR: RECTO_STATE_BACKEND=postgres but no DSN resolved -- "
                "set RECTO_POSTGRES_DSN, or configure RECTO_SECRET_SOURCE "
                f"and store the DSN under {secret_name!r}.",
                file=sys.stderr,
            )
            sys.exit(2)

    schema = _env("RECTO_POSTGRES_SCHEMA", default="recto_bootloader")
    try:
        from recto.bootloader.state_postgres import PostgresStateStore

        store = PostgresStateStore(dsn, schema=schema, state_dir=state_dir)
    except Exception as ex:
        print(
            f"ERROR: PostgresStateStore init failed (DSN via {dsn_origin}): "
            f"{type(ex).__name__}: {ex}",
            file=sys.stderr,
        )
        sys.exit(2)
    return (store, f"postgres (schema {schema}, DSN via {dsn_origin})")


def _read_text_file(path: str) -> str | None:
    """Read a small credential file; WARN + None on any OS error."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError as ex:
        print(f"WARN: could not read {path!r}: {ex}", file=sys.stderr)
        return None


def _build_push_dispatcher(secret_source):
    """Construct the silent-push wake dispatcher from RECTO_PUSH_* env,
    or None when no sender is fully configured.

    Push is an ENHANCEMENT (polling stays the permanent fallback per
    the wave-C protocol posture), so every failure here is a stderr
    WARN + sender-skip, never an exit.
    """
    senders = []

    team_id = _env("RECTO_PUSH_APNS_TEAM_ID")
    key_id = _env("RECTO_PUSH_APNS_KEY_ID")
    bundle_id = _env("RECTO_PUSH_APNS_BUNDLE_ID")
    if team_id and key_id and bundle_id:
        p8_pem = None
        p8_file = _env("RECTO_PUSH_APNS_P8_FILE")
        if p8_file:
            p8_pem = _read_text_file(p8_file)
        if p8_pem is None:
            p8_secret = _env("RECTO_PUSH_APNS_P8_SECRET")
            if p8_secret:
                p8_pem = _fetch_prod_secret(secret_source, p8_secret)
        if p8_pem:
            try:
                from recto.bootloader.push import ApnsConfig, ApnsPushSender

                use_sandbox = (
                    os.environ.get("RECTO_PUSH_APNS_SANDBOX") or ""
                ).strip() == "1"
                senders.append(
                    ApnsPushSender(
                        ApnsConfig(
                            team_id=team_id,
                            key_id=key_id,
                            p8_key_pem=p8_pem,
                            bundle_id=bundle_id,
                            use_sandbox=use_sandbox,
                        )
                    )
                )
            except Exception as ex:
                print(
                    f"WARN: APNs sender init failed: "
                    f"{type(ex).__name__}: {ex}",
                    file=sys.stderr,
                )
        else:
            print(
                "WARN: APNs env set but no .p8 key resolved "
                "(RECTO_PUSH_APNS_P8_SECRET / _P8_FILE) -- "
                "APNs wake disabled.",
                file=sys.stderr,
            )

    fcm_project = _env("RECTO_PUSH_FCM_PROJECT_ID")
    if fcm_project:
        sa_json = None
        sa_file = _env("RECTO_PUSH_FCM_SA_FILE")
        if sa_file:
            sa_json = _read_text_file(sa_file)
        if sa_json is None:
            sa_secret = _env("RECTO_PUSH_FCM_SA_SECRET")
            if sa_secret:
                sa_json = _fetch_prod_secret(secret_source, sa_secret)
        if sa_json:
            try:
                from recto.bootloader.push import FcmConfig, FcmPushSender

                senders.append(
                    FcmPushSender(
                        FcmConfig(
                            project_id=fcm_project,
                            service_account_json=sa_json,
                        )
                    )
                )
            except Exception as ex:
                print(
                    f"WARN: FCM sender init failed: "
                    f"{type(ex).__name__}: {ex}",
                    file=sys.stderr,
                )
        else:
            print(
                "WARN: RECTO_PUSH_FCM_PROJECT_ID set but no service-account "
                "JSON resolved (RECTO_PUSH_FCM_SA_SECRET / _SA_FILE) -- "
                "FCM wake disabled.",
                file=sys.stderr,
            )

    if not senders:
        return None
    from recto.bootloader.push import PushDispatcher

    return PushDispatcher(senders)


# ---------------------------------------------------------------------------
# Agents manifest (multi-agent mode)
# ---------------------------------------------------------------------------


def _load_agents_manifest(path: str) -> list[dict]:
    """Read RECTO_AGENTS_FILE and return its ``agents`` array.

    Exits with code 2 on file-not-found, JSON parse error, missing or
    empty agents array. The structural validation here is intentionally
    coarse -- per-entry validation (agent_id present, token resolves,
    length check) happens in the main loop where the agent_id is
    available for the error message.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(
            f"ERROR: RECTO_AGENTS_FILE={path!r} not found.",
            file=sys.stderr,
        )
        sys.exit(2)
    except json.JSONDecodeError as ex:
        print(
            f"ERROR: RECTO_AGENTS_FILE={path!r} is not valid JSON: {ex}",
            file=sys.stderr,
        )
        sys.exit(2)

    agents = data.get("agents") if isinstance(data, dict) else None
    if not isinstance(agents, list) or not agents:
        print(
            f"ERROR: RECTO_AGENTS_FILE={path!r} must contain a "
            "non-empty 'agents' array at the top level.",
            file=sys.stderr,
        )
        sys.exit(2)

    return agents


def _resolve_agents() -> list[dict]:
    """Return the unified list of agent dicts (manifest-shape)
    regardless of source.

    If RECTO_AGENTS_FILE is set, returns the manifest's agents array.
    Otherwise, returns a 0- or 1-element list synthesized from the
    single-agent env vars (RECTO_AGENT_ID + RECTO_VAULT_SERVICE +
    RECTO_APP_*) -- 0 elements when RECTO_AGENT_ID is unset (the
    no-agent foreground case where capability endpoints intentionally
    return 404).

    The single-agent env-var path's ``token_env`` is hardcoded to
    "RECTO_AGENT_TOKEN" to preserve the pre-multi-agent contract that
    Recto's launcher (or operators in foreground bring-up) inject the
    token under that exact name.
    """
    agents_file = _env("RECTO_AGENTS_FILE")
    if agents_file:
        return _load_agents_manifest(agents_file)

    agent_id = _env("RECTO_AGENT_ID")
    if not agent_id:
        return []

    return [
        {
            "agent_id": agent_id,
            "token_env": "RECTO_AGENT_TOKEN",
            "vault_service": _env("RECTO_VAULT_SERVICE") or "",
            "vault_secret": _env(
                "RECTO_VAULT_SECRET",
                default="RECTO_CAPABILITY_AGENT_TOKEN",
            ),
            "app": {
                "app_id": os.environ.get("RECTO_APP_ID", "").strip(),
                "app_name": os.environ.get("RECTO_APP_NAME", "").strip(),
                "app_description": os.environ.get(
                    "RECTO_APP_DESCRIPTION", ""
                ).strip(),
                "app_url": os.environ.get("RECTO_APP_URL", "").strip(),
                "app_icon_url": os.environ.get(
                    "RECTO_APP_ICON_URL", ""
                ).strip(),
            },
        }
    ]


# ---------------------------------------------------------------------------
# Devices-pair consumers manifest (Phase H end-user device pairing relay)
# ---------------------------------------------------------------------------


def _load_consumers_manifest(path: str) -> list[dict]:
    """Read RECTO_DEVICES_PAIR_CONSUMERS_FILE and return its
    ``consumers`` array.

    Exits with code 2 on file-not-found, JSON parse error, or missing
    ``consumers`` key. Empty list is ALLOWED (operator deliberately
    disabled the relay endpoint by registering zero consumers); the
    main loop treats an empty list the same as the env var being unset
    -- the /v0.4/devices/pair endpoint returns 404 either way.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(
            f"ERROR: RECTO_DEVICES_PAIR_CONSUMERS_FILE={path!r} not found.",
            file=sys.stderr,
        )
        sys.exit(2)
    except json.JSONDecodeError as ex:
        print(
            f"ERROR: RECTO_DEVICES_PAIR_CONSUMERS_FILE={path!r} is not "
            f"valid JSON: {ex}",
            file=sys.stderr,
        )
        sys.exit(2)

    consumers = data.get("consumers") if isinstance(data, dict) else None
    if not isinstance(consumers, list):
        print(
            f"ERROR: RECTO_DEVICES_PAIR_CONSUMERS_FILE={path!r} must "
            "contain a 'consumers' array at the top level (may be empty).",
            file=sys.stderr,
        )
        sys.exit(2)

    return consumers


def _resolve_consumers() -> list[dict]:
    """Return the consumer-registry list for Phase H end-user device
    pairing relay.

    When RECTO_DEVICES_PAIR_CONSUMERS_FILE is set, returns the
    manifest's consumers array. Otherwise returns an empty list (the
    /v0.4/devices/pair endpoint stays disabled -- 404 -- which is the
    correct posture for bootloaders that don't broker end-user device
    pairing for any consumer).

    No single-consumer env-var fallback (unlike `_resolve_agents` which
    supports both manifest mode and RECTO_AGENT_ID single-tenant mode).
    The relay endpoint is intrinsically multi-tenant by shape -- one
    bootloader can broker pairing for N consumers simultaneously -- so
    a single-consumer env-var path doesn't compose well. Manifest mode
    is the only mode.
    """
    path = _env("RECTO_DEVICES_PAIR_CONSUMERS_FILE")
    if not path:
        return []
    return _load_consumers_manifest(path)


def _resolve_token_for_consumer(consumer: dict) -> str:
    """Resolve the webhook token for one consumer dict (manifest-shape).

    Sister of ``_resolve_token_for_agent`` -- same priority order
    (token_env first, then dpapi-machine vault) -- with one
    difference: the default vault secret name is
    ``"OPENCLAW_WEBHOOK_SECRET"`` rather than
    ``"RECTO_CAPABILITY_AGENT_TOKEN"``. v0 posture (2026-05-19)
    reuses the consumer's existing Openclaw webhook secret as the
    devices-pair webhook token; the dedicated-secret split lands
    later (likely alongside the Hermes-cutover key rename per the
    operator's 2026-05-19 architectural call).

    Returns "" when neither source resolves; caller surfaces the
    error with consumer.base_url context. The token never transits
    PowerShell history, command-line args, or stdout in either path.
    """
    token_env = (consumer.get("token_env") or "").strip()
    if token_env:
        env_token = os.environ.get(token_env, "").strip()
        if env_token:
            return env_token

    vault_service = (consumer.get("vault_service") or "").strip()
    if not vault_service:
        return ""

    vault_secret = (
        (consumer.get("vault_secret") or "").strip()
        or "OPENCLAW_WEBHOOK_SECRET"
    )

    try:
        source = DpapiMachineSource(vault_service)
        material = source.fetch(vault_secret, {})
    except Exception as ex:
        print(
            f"WARN: vault fetch for {vault_service}/{vault_secret} failed: "
            f"{type(ex).__name__}: {ex}",
            file=sys.stderr,
        )
        return ""
    return (material.value or "").strip()


# ---------------------------------------------------------------------------
# AppContext construction
# ---------------------------------------------------------------------------


def _build_app_context_from_dict(app: dict | None) -> AppContext | None:
    """Build AppContext from a manifest-shape app dict. Returns None
    when the dict is empty/missing or both app_id and app_name are
    blank (operator deliberately skipped AppContext registration; the
    phone will show an "Unknown app" warning at approval time, which
    is fine for integration testing).

    If only one of app_id / app_name is present, prints a warning
    and skips registration (avoids partial AppContext on the phone
    side, which renders confusingly).

    Tolerates both the multi-agent manifest path (dict comes from
    the JSON file) and the single-agent env-var path (dict is
    synthesized in ``_resolve_agents`` from RECTO_APP_* env vars).
    """
    if not app:
        return None
    app_id = (app.get("app_id") or "").strip()
    app_name = (app.get("app_name") or "").strip()
    if not app_id and not app_name:
        return None
    if not app_id or not app_name:
        print(
            "WARN: app_id and app_name must both be set to register an "
            "AppContext (or both unset to skip). Skipping AppContext "
            "registration; phone will show 'Unknown app' warning at "
            "approval time.",
            file=sys.stderr,
        )
        return None
    return AppContext(
        app_id=app_id,
        app_name=app_name,
        app_description=(app.get("app_description") or "").strip(),
        app_url=(app.get("app_url") or "").strip(),
        app_icon_url=(app.get("app_icon_url") or "").strip(),
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


# --- GATE 0c: make INFO reach a handler -------------------------------------
# WITHOUT THIS, EVERY logger.info() IN THE SUBSTRATE IS DISCARDED IN PRODUCTION.
#
# Python configures no root handler by default. An unhandled record falls
# through to `logging.lastResort`, which is fixed at WARNING -- so INFO is
# dropped before it reaches stderr and `docker logs` shows nothing.
#
# This was measured on 2026-08-17, on a container that had just been deployed
# and verified by image label. GATE 0b had shipped this line four hours earlier:
#
#     logger.info("connections key ACL: agent %r read secret %r ...")
#
# carrying the comment "INFO, not DEBUG: this has to survive a default logging
# configuration or it is not evidence." The requirement was right. The mechanism
# was backwards: under Python's real default, INFO does NOT survive.
#
# All four GATE 0b tests passed anyway, because pytest's caplog attaches its own
# handler and sets its own level -- so the suite proved the line is LOGGED while
# production proved it is not EMITTED. A test harness that configures logging
# cannot testify about a runtime that does not.
#
# The cost was exact: an operator watched `docker logs -f` for five minutes and
# saw nothing, and "no traffic" and "no possible output" looked identical. That
# ambiguity is the precise thing GATE 0b existed to remove, so until this landed
# the blindness had moved rather than closed.
#
# RECTO_LOG_LEVEL overrides, so a noisy incident can be turned up without a
# rebuild. basicConfig is a no-op when handlers already exist, so an embedding
# host keeps its own configuration.
def _configure_logging() -> int:
    """Install a stderr handler at INFO. Returns the effective level."""
    level_name = os.environ.get("RECTO_LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stderr,
    )
    logging.getLogger().setLevel(level)
    return level


def main() -> int:
    # FIRST statement in main, before any import-time logger can fire on a
    # config that is not yet installed.
    _configure_logging()
    bootloader_id = _env("RECTO_BOOTLOADER_ID", required=True)
    bind_host = _env("RECTO_BIND_HOST", default="0.0.0.0")
    bind_port = _env_int("RECTO_BIND_PORT", default=8765)
    state_dir_str = _env(
        "RECTO_STATE_DIR",
        default=fr"C:\ProgramData\Recto\{bootloader_id}",
    )
    state_dir = pathlib.Path(state_dir_str)
    public_url = _env(
        "RECTO_PUBLIC_URL",
        default=f"http://{bind_host}:{bind_port}",
    )

    agents = _resolve_agents()

    capability_agent_tokens: dict[str, str] = {}
    capability_agent_requestable: dict[str, list[str]] = {}
    principal_apps: dict[str, AppContext] = {}

    for agent in agents:
        agent_id = (agent.get("agent_id") or "").strip()
        if not agent_id:
            print(
                f"ERROR: agent entry missing agent_id: {agent!r}",
                file=sys.stderr,
            )
            return 2

        agent_token = _resolve_token_for_agent(agent)
        if not agent_token:
            token_env = (agent.get("token_env") or "").strip() or "(none declared)"
            vault_service = (agent.get("vault_service") or "").strip() or "(unset)"
            vault_secret = (
                (agent.get("vault_secret") or "").strip()
                or "RECTO_CAPABILITY_AGENT_TOKEN"
            )
            print(
                f"ERROR: agent {agent_id!r}: no token resolvable.\n"
                f"Looked at:\n"
                f"  - $env:{token_env} (unset or empty)\n"
                f"  - dpapi-machine vault {vault_service}/{vault_secret} "
                "(missing or unreadable)\n"
                "Provision via either:\n"
                f"  (a) set $env:{token_env} directly (non-vault deployments), or\n"
                f"  (b) `recto credman set {vault_service} {vault_secret}` "
                "(vault-backed deployments).",
                file=sys.stderr,
            )
            return 2

        if len(agent_token) != 64:
            print(
                f"ERROR: agent {agent_id!r}: token must be 64 hex chars, "
                f"got {len(agent_token)}.",
                file=sys.stderr,
            )
            return 2

        if agent_id in capability_agent_tokens:
            print(
                f"ERROR: duplicate agent_id {agent_id!r} in manifest.",
                file=sys.stderr,
            )
            return 2

        capability_agent_tokens[agent_id] = agent_token

        app_ctx = _build_app_context_from_dict(agent.get("app"))
        if app_ctx is not None:
            principal_apps[agent_id] = app_ctx

        # Optional requestable-action policy. Present = deny-by-default
        # allowlist of action keys this agent may ask for (evaluated
        # server-side before carding); absent = unrestricted at that
        # layer. An explicitly-empty list is refused as a config error:
        # an agent that may request NOTHING should not be registered.
        requestable_raw = agent.get("requestable_actions")
        if requestable_raw is not None:
            if (
                not isinstance(requestable_raw, list)
                or not requestable_raw
                or not all(
                    isinstance(a, str) and a.strip() for a in requestable_raw
                )
            ):
                print(
                    f"ERROR: agent {agent_id!r}: requestable_actions must be "
                    "a non-empty array of action-key strings when present.",
                    file=sys.stderr,
                )
                return 2
            capability_agent_requestable[agent_id] = [
                a.strip() for a in requestable_raw
            ]

    # Phase H end-user device pairing relay (2026-05-19). When the
    # operator registers one or more consumers via
    # RECTO_DEVICES_PAIR_CONSUMERS_FILE, the bootloader exposes
    # POST /v0.4/devices/pair which relays user-signed JWSes to the
    # consumer's /api/v1/devices/pairing/complete endpoint with the
    # registered X-Openclaw-Token header. Empty registry => endpoint
    # returns 404 (zero attack surface for bootloaders that don't
    # broker end-user pairing for any consumer).
    consumers = _resolve_consumers()
    devices_pair_consumer_webhook_tokens: dict[str, str] = {}
    devices_pair_consumer_relay_urls: dict[str, str] = {}

    for consumer in consumers:
        base_url = (consumer.get("base_url") or "").strip()
        if not base_url:
            print(
                f"ERROR: consumer entry missing base_url: {consumer!r}",
                file=sys.stderr,
            )
            return 2

        webhook_token = _resolve_token_for_consumer(consumer)
        if not webhook_token:
            token_env = (consumer.get("token_env") or "").strip() or "(none declared)"
            vault_service = (consumer.get("vault_service") or "").strip() or "(unset)"
            vault_secret = (
                (consumer.get("vault_secret") or "").strip()
                or "OPENCLAW_WEBHOOK_SECRET"
            )
            print(
                f"ERROR: consumer {base_url!r}: no webhook token resolvable.\n"
                f"Looked at:\n"
                f"  - $env:{token_env} (unset or empty)\n"
                f"  - dpapi-machine vault {vault_service}/{vault_secret} "
                "(missing or unreadable)\n"
                "Provision via either:\n"
                f"  (a) set $env:{token_env} directly (non-vault deployments), or\n"
                f"  (b) ensure the consumer's vault carries the named secret\n"
                "      (typical pattern: reuse the consumer's existing\n"
                "      Openclaw webhook secret).",
                file=sys.stderr,
            )
            return 2

        # Canonicalize: strip trailing slash so operator-paste variants
        # match the bootloader-side lookup (server.py strips the same
        # way before its dict lookup, then falls back to the
        # trailing-slash variant for forgiveness).
        normalized_url = base_url.rstrip("/")
        if normalized_url in devices_pair_consumer_webhook_tokens:
            print(
                f"ERROR: duplicate consumer base_url {normalized_url!r} "
                "in manifest.",
                file=sys.stderr,
            )
            return 2

        devices_pair_consumer_webhook_tokens[normalized_url] = webhook_token

        # Optional relay_url: when set, the bootloader forwards to this
        # URL instead of base_url (three-zone architecture commitment #17).
        relay_url = (consumer.get("relay_url") or "").strip()
        if relay_url:
            devices_pair_consumer_relay_urls[normalized_url] = relay_url.rstrip("/")

    # Recto Connections Substrate (2026-06-13). Opt-in via
    # RECTO_CONNECTIONS_FILE -- when unset, ALL /v0.4/connections/*
    # endpoints stay 404 (zero attack surface). When set, reads are
    # agent-token-gated + service-scoped via RECTO_CONNECTIONS_AGENT_SERVICES;
    # writes are operator-gated via the resolved operator write token
    # (the SAME create_server field that gates /v0.4/capability/revoke).
    #
    # RECTO_CONNECTIONS_FILE is the canonical name; in the DOCKERIZED
    # topology point it at a container path inside the rebuild-surviving,
    # host-private bootloader-data named volume, NOT a Windows path the
    # Linux container can't see (e.g. /var/lib/recto/bootloader/connections.json).
    # RECTO_CONNECTIONS_PATH is accepted as a legacy alias.
    connections_path = (
        _env("RECTO_CONNECTIONS_FILE") or _env("RECTO_CONNECTIONS_PATH")
    ) or None
    connections_agent_services = _parse_connections_agent_services(
        os.environ.get("RECTO_CONNECTIONS_AGENT_SERVICES", "")
    )
    # Per-agent KEY allowlist on the secret VALUE read (2026-07-28).
    # RECTO_CONNECTIONS_AGENT_KEYS answers "which of its service's keys?"
    # after the service map has answered "whose keys?". Unset means no
    # agent is allowlisted for anything -- harmless while the gate runs in
    # audit mode (the default), a hard default-deny once
    # RECTO_CONNECTIONS_KEY_ACL_ENFORCE=1 flips it on.
    connections_agent_keys = _parse_connections_agent_keys(
        os.environ.get("RECTO_CONNECTIONS_AGENT_KEYS", "")
    )
    connections_key_acl_enforce = (
        os.environ.get("RECTO_CONNECTIONS_KEY_ACL_ENFORCE", "").strip() == "1"
    )
    operator_write_token = _resolve_operator_write_token() or None
    # Per-connection SECRET VALUES (conn.<key>). In a Linux container the
    # DpapiMachineSource default cannot decrypt (DPAPI is Windows-bound),
    # so set RECTO_CONNECTIONS_SECRET_DIR to a file-backed store inside the
    # named volume; the first real secret write/read 500s otherwise. UNSET
    # keeps the DpapiMachineSource default (foreground Windows-host path).
    connections_secret_factory = _build_connections_secret_factory()

    # Recto User Vault Substrate (2026-07-25). Opt-in via
    # RECTO_USER_VAULT_FILE -- when unset, ALL /v0.4/user-vault/*
    # endpoints stay 404. When set, all four verbs are agent-token-gated
    # + platform-scoped via RECTO_USER_VAULT_AGENT_PLATFORMS (same
    # agent_id:Namespace format as the connections map), and each request
    # carries an X-Recto-User-Id claim scoping it to one user. In the
    # DOCKERIZED topology point the file inside the bootloader-data named
    # volume (e.g. /var/lib/recto/bootloader/user_vault.json) and set
    # RECTO_USER_VAULT_SECRET_DIR beside it -- DPAPI cannot decrypt in a
    # Linux container.
    user_vault_path = _env("RECTO_USER_VAULT_FILE") or None
    user_vault_agent_platforms = _parse_connections_agent_services(
        os.environ.get("RECTO_USER_VAULT_AGENT_PLATFORMS", ""),
        var_name="RECTO_USER_VAULT_AGENT_PLATFORMS",
    )
    user_vault_secret_factory = _build_user_vault_secret_factory()

    quiet = os.environ.get("RECTO_BOOTLOADER_QUIET", "").strip() == "1"

    state_dir.mkdir(parents=True, exist_ok=True)

    # Production backends (banked 2026-07-12): secret source first (the
    # state backend + push senders both resolve credentials through it),
    # then the state store, then the push dispatcher. All three default
    # to the pre-existing dev/single-host behavior when their env vars
    # are unset.
    prod_secret_source = _build_prod_secret_source()
    state, state_banner = _build_state_store(state_dir, prod_secret_source)
    push_dispatcher = _build_push_dispatcher(prod_secret_source)

    # Multi-URL failover list (wave C, primary first). Empty keeps
    # registration responses byte-identical to single-URL v1.
    public_urls = tuple(
        u.strip().rstrip("/")
        for u in (os.environ.get("RECTO_PUBLIC_URLS") or "").split(",")
        if u.strip()
    )

    # Own the ChallengeStore explicitly so we can mint a pairing code
    # from the SAME instance the server consumes at registration time
    # (the mint-side handle for the foreground startup-print
    # convenience). State-BACKED since 2026-07-20: passing the state
    # store through means challenge persistence follows the backend --
    # in-memory on the file store, shared Postgres rows on the
    # production store, so codes survive replica death and any
    # instance behind the load balancer can consume them. (Field
    # lesson: the bare ChallengeStore() here silently bypassed the
    # create_server state-backed default and kept prod pairing
    # per-instance.)
    challenges = ChallengeStore(state=state)

    # Folder-drop event bus (banked 2026-05-19 night alongside the
    # Recto bootloader Docker abstraction). When RECTO_EVENTS_DIR is
    # set + writable, the launcher constructs a FileEventEmitter and
    # wires it as notify_resolved_fn so capability + sign lifecycle
    # events emit as JSONL records to the configured folder.
    # Peer-AIs on the host filesystem (Cowork instances, openclaw
    # skills, audit watchers) tail-watch the daily-rotated files
    # without polling the bootloader's HTTP surface.
    #
    # When RECTO_EVENTS_DIR is unset, construct_events_emitter
    # returns None and notify_resolved_fn stays at its default — the
    # bootloader's pre-events-folder behavior is unchanged. Opt-in is
    # the deployment-time switch.
    events_emitter = construct_events_emitter(bootloader_id=bootloader_id)

    # Capability action manifest (optional). When RECTO_CAPABILITY_MANIFEST_FILE
    # names a readable JSON manifest (recto.capability.manifest schema), the
    # bootloader serves it at GET /v0.4/capability/manifest and uses it for
    # scope evaluation; unset keeps the pre-manifest posture (endpoint 404s
    # with no_manifest_configured). Same bind-mount contract as
    # RECTO_AGENTS_FILE: the manifest is per-deploy operator data, never
    # baked into the image.
    capability_manifest_path = os.environ.get("RECTO_CAPABILITY_MANIFEST_FILE") or None

    server = create_server(
        bind_host=bind_host,
        bind_port=bind_port,
        state=state,
        challenges=challenges,
        bootloader_id=bootloader_id,
        capability_manifest_path=capability_manifest_path,
        capability_agent_tokens=capability_agent_tokens,
        capability_agent_requestable=capability_agent_requestable or None,
        capability_operator_token=operator_write_token,
        principal_apps=principal_apps,
        devices_pair_consumer_webhook_tokens=devices_pair_consumer_webhook_tokens,
        devices_pair_consumer_relay_urls=devices_pair_consumer_relay_urls,
        connections_path=connections_path,
        connections_agent_services=connections_agent_services,
        connections_agent_keys=connections_agent_keys,
        connections_key_acl_enforce=connections_key_acl_enforce,
        connections_secret_source_factory=connections_secret_factory,
        user_vault_path=user_vault_path,
        user_vault_agent_platforms=user_vault_agent_platforms,
        user_vault_secret_source_factory=user_vault_secret_factory,
        notify_resolved_fn=(
            events_emitter.notify_resolved if events_emitter is not None else None
        ),
        push_dispatcher=push_dispatcher,
        public_urls=public_urls or None,
    )

    # ---- Startup banner ------------------------------------------------

    pubkey = state.get_operator_pubkey()
    pubkey_status = (
        f"operator pubkey loaded ({pubkey.hex()[:16]}...)"
        if pubkey is not None
        else (
            "no operator pubkey -- run `recto vault bootstrap <hex>` "
            "for full verifier path"
        )
    )

    print()
    print(f"Recto bootloader listening on http://{bind_host}:{bind_port}/")
    print(f"Public URL:    {public_url}")
    print(f"State dir:     {state_dir}")
    print(f"State backend: {state_banner}")
    print(f"Bootloader id: {bootloader_id}")
    if push_dispatcher is not None:
        print(f"Push wake:     {'+'.join(push_dispatcher.platforms)}")
    else:
        print("Push wake:     (disabled -- no APNs/FCM sender configured)")
    if public_urls:
        print(f"Failover URLs: {', '.join(public_urls)}")
    print(f"{pubkey_status}")
    if events_emitter is not None:
        print(f"Events dir:    {events_emitter.events_dir} (folder-drop bus active)")
    else:
        events_dir_env = (os.environ.get("RECTO_EVENTS_DIR") or "").strip()
        if events_dir_env:
            print(
                f"Events dir:    {events_dir_env} (configured but FileEventEmitter "
                "could not initialize -- events NOT emitted)"
            )

    # Iterate registered agents -- ensures the banner stays accurate
    # across both single-agent (env-var path) and multi-agent
    # (RECTO_AGENTS_FILE manifest path) modes. One line per agent
    # with its AppContext (or "no AppContext" annotation) so the
    # operator can spot misconfigurations at glance.
    if capability_agent_tokens:
        print("Agents:")
        for aid, tok in capability_agent_tokens.items():
            ctx = principal_apps.get(aid)
            if ctx is not None:
                ctx_str = f"AppContext={ctx.app_name} ({ctx.app_id})"
            else:
                ctx_str = "no AppContext (phone shows 'Unknown app' warning)"
            policy = capability_agent_requestable.get(aid)
            if policy is not None:
                ctx_str += f" [requestable: {', '.join(policy)}]"
            print(f"  - {aid} (token = {tok[:8]}...) {ctx_str}")
    # Phase H devices-pair consumer registry (2026-05-19). Same
    # sibling-line shape as Agents: above so the operator can spot
    # misconfigurations at glance. Empty registry => one-line note
    # that the relay endpoint is disabled.
    if devices_pair_consumer_webhook_tokens:
        print("Devices-pair consumers:")
        for url, tok in devices_pair_consumer_webhook_tokens.items():
            print(f"  - {url} (token = {tok[:8]}...)")
    else:
        print(
            "Devices-pair consumers: (none registered -- "
            "/v0.4/devices/pair returns 404)"
        )
    # Recto Connections Substrate (2026-06-13). Sister banner line so the
    # operator can confirm the /v0.4/connections surface is enabled, which
    # agents may read which service, whether writes are armed, and which
    # secret-store backs the per-connection values. Disabled => one-line
    # note (the substrate is opt-in via RECTO_CONNECTIONS_FILE).
    if connections_path:
        print(f"Connections:   {connections_path}")
        if connections_agent_services:
            for aid, svc in connections_agent_services.items():
                print(f"  - read scope: {aid} -> {svc}")
        else:
            print("  - (no agent->service mappings -- reads 403 for every agent)")
        # Per-key ACL posture (2026-07-28) -- printed right under the read
        # scopes because it is the second half of the same answer: the
        # service map says whose keys, this says which of them.
        acl_mode = "ENFORCING" if connections_key_acl_enforce else "audit-only"
        print(f"  - key ACL: {acl_mode}")
        if connections_agent_keys:
            for aid, patterns in connections_agent_keys.items():
                note = " (ALLOW-ALL)" if any(
                    p.strip() == "*" for p in patterns
                ) else ""
                print(f"    - {aid}: {', '.join(patterns)}{note}")
        elif connections_key_acl_enforce:
            print(
                "    - (no allowlists -- every secret read 403s; set "
                "RECTO_CONNECTIONS_AGENT_KEYS)"
            )
        else:
            print(
                "    - (no allowlists -- denials are logged, not blocked; "
                "read the log, then set RECTO_CONNECTIONS_AGENT_KEYS)"
            )
        write_state = (
            "enabled" if operator_write_token else "DISABLED (no operator write token)"
        )
        print(f"  - writes: {write_state}")
        secret_dir = (os.environ.get("RECTO_CONNECTIONS_SECRET_DIR") or "").strip()
        if secret_dir:
            print(f"  - secret store: file-backed at {secret_dir}")
        else:
            print(
                "  - secret store: dpapi-machine (Windows-host default; "
                "set RECTO_CONNECTIONS_SECRET_DIR for Linux containers)"
            )
    else:
        print(
            "Connections:   (RECTO_CONNECTIONS_FILE unset -- "
            "/v0.4/connections/* returns 404)"
        )
    if not capability_agent_tokens:
        print("Agents:        (none registered -- capability endpoints will 404)")
    print()

    if not quiet:
        pairing_code, pairing_exp = challenges.issue_pairing_code(ttl_seconds=3600)
        print("=" * 60)
        print(f"PAIRING CODE:  {pairing_code}")
        print(f"               (valid 60 min; expires unix {pairing_exp})")
        print("=" * 60)
        print()
        print("From the operator's phone, open the Recto MAUI app -> Pair, enter:")
        print(f"   bootloader URL = {public_url}")
        print(f"   pairing code   = {pairing_code}")
        print()
    else:
        print("Quiet mode (RECTO_BOOTLOADER_QUIET=1) -- no pairing code issued at startup.")
        print(
            "Mint codes on demand via POST /v0.4/pairing/code (operator-trusted "
            "agent endpoint), or unset RECTO_BOOTLOADER_QUIET and restart."
        )
        print()

    print("Ctrl-C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
