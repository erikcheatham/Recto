"""Command-line interface for Recto.

Subcommands:
    recto launch <yaml>                       - run the supervised child
    recto credman set <service> <name>        - install a secret in
                                                Windows Credential Manager
                                                (interactive prompt)
    recto credman list <service>              - list installed secret names
                                                for a service
    recto credman delete <service> <name>     - remove an installed secret
    recto secrets set <service> <name>        - install a secret in any
                                                registered backend
                                                (default: dpapi-machine).
                                                Backend-agnostic counterpart
                                                to `recto credman set`.
    recto secrets delete <service> <name>     - remove an installed secret
                                                from any registered backend
                                                (default: dpapi-machine).
    recto status <service>                    - report NSSM service state
    recto migrate-from-nssm <service>         - read NSSM config, generate
                                                YAML, import secrets to
                                                credman, retarget Application,
                                                clear AppEnvironmentExtra
    recto apply <yaml>                        - reconcile NSSM state to
                                                match a service.yaml
                                                (GitOps-style diff + apply)
    recto events <yaml>                       - dump the running launcher's
                                                recent lifecycle events from
                                                the admin UI's in-memory
                                                ring buffer

The CLI is a thin dispatcher. Each subcommand handler delegates to one
of `recto.launcher`, `recto.secrets.credman`, `recto.config`, or
`recto.nssm`. This keeps argparse-related code together and the
domain modules independent.

Testability seam:
    Every external dependency that touches a real system - subprocess.run
    for NSSM, getpass.getpass for secret prompts, Windows Credential
    Manager for write/list/delete - is reachable through a constructor
    arg or factory parameter. tests/test_cli.py wires stubs in.

`python -m recto` is the operator-facing invocation and is wired in
`recto/__main__.py`. The `recto = "recto.cli:main"` console-script
entry in `pyproject.toml` exposes the same `main()`.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO

from recto.config import (
    ConfigValidationError,
    ServiceConfig,
    load_config,
)
from recto.nssm import (
    NssmClient,
    NssmConfig,
    NssmError,
    NssmNotInstalledError,
    NssmServiceNotFoundError,
    NssmStatus,
    split_environment_extra,
)
from recto._migrate import (
    build_migration_plan,
    generate_service_yaml,
    partition_env_entries,
)
from recto.reconcile import (
    ReconcilePlan,
    apply_plan,
    compute_plan,
    render_plan,
)
from recto.secrets import (
    CredManSource,
    SecretNotFoundError,
    SecretSourceError,
)

__all__ = [
    "CredManFactory",
    "NssmFactory",
    "build_parser",
    "main",
]


CredManFactory = Callable[[str], CredManSource]
NssmFactory = Callable[[], NssmClient]
PromptFn = Callable[[str], str]
ConfirmFn = Callable[[str], str]
LaunchFn = Callable[..., int]


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser with all subcommands wired."""
    parser = argparse.ArgumentParser(
        prog="recto",
        description=(
            "Modern Windows-service wrapper. Spiritual successor to NSSM. "
            "See https://github.com/erikcheatham/Recto."
        ),
    )
    parser.add_argument("--version", action="version", version=_version_string())
    sub = parser.add_subparsers(
        dest="command",
        title="subcommands",
        required=True,
        metavar="{launch,credman,secrets,vault,profile,status,migrate-from-nssm,apply,events}",
    )

    # launch
    p_launch = sub.add_parser("launch", help="Run a supervised child from a service.yaml.")
    p_launch.add_argument("yaml_path", help="Path to service.yaml")
    p_launch.add_argument("--once", action="store_true", help="Single-spawn debug mode.")

    # credman
    p_credman = sub.add_parser("credman", help="Manage Credential Manager entries.")
    sub_credman = p_credman.add_subparsers(
        dest="credman_command", required=True, metavar="{set,list,delete}",
    )
    p_credman_set = sub_credman.add_parser("set", help="Install (or replace) a secret value.")
    p_credman_set.add_argument("service")
    p_credman_set.add_argument("name")
    p_credman_set.add_argument("--value", help="Pass the value directly instead of prompting.")
    p_credman_list = sub_credman.add_parser("list", help="List secret names for a service.")
    p_credman_list.add_argument("service")
    p_credman_delete = sub_credman.add_parser("delete", help="Remove an installed secret.")
    p_credman_delete.add_argument("service")
    p_credman_delete.add_argument("name")

    # secrets (Papercut #2: backend-agnostic listing across all
    # registered SecretSource backends. `recto credman list` only
    # walked the per-user credman store, leaving dpapi-machine
    # entries invisible. `recto secrets list` walks every registered
    # backend that supports list_names() and prefixes each line with
    # the backend selector.)
    p_secrets = sub.add_parser(
        "secrets", help="Backend-agnostic secret operations.",
    )
    sub_secrets = p_secrets.add_subparsers(
        dest="secrets_command", required=True, metavar="{set,list,delete}",
    )
    p_secrets_set = sub_secrets.add_parser(
        "set",
        help=(
            "Install (or replace) a secret in any registered backend. "
            "Backend-agnostic counterpart to `recto credman set`. The "
            "default backend is `dpapi-machine` because that's the "
            "production default for service-context decryption "
            "(LocalSystem services can read it; CredMan is per-user)."
        ),
    )
    p_secrets_set.add_argument("service")
    p_secrets_set.add_argument("name")
    p_secrets_set.add_argument(
        "--source",
        default="dpapi-machine",
        help=(
            "Which registered backend to write to (e.g. credman, "
            "dpapi-machine). Default: dpapi-machine."
        ),
    )
    p_secrets_set.add_argument(
        "--value",
        help="Pass the value directly instead of prompting (input hidden by default).",
    )
    p_secrets_list = sub_secrets.add_parser(
        "list",
        help=(
            "List installed secret names for a service across every "
            "registered backend (credman, dpapi-machine, ...). "
            "Output is one line per secret, prefixed with [<backend>]."
        ),
    )
    p_secrets_list.add_argument("service")
    p_secrets_delete = sub_secrets.add_parser(
        "delete",
        help=(
            "Remove an installed secret from any registered backend "
            "(default: dpapi-machine). Backend-agnostic counterpart to "
            "`recto credman delete`."
        ),
    )
    p_secrets_delete.add_argument("service")
    p_secrets_delete.add_argument("name")
    p_secrets_delete.add_argument(
        "--source",
        default="dpapi-machine",
        help="Which registered backend to delete from. Default: dpapi-machine.",
    )

    # vault (Phase 5 Wave C part 4): bootstrap + status for the
    # operator's secp256k1 pubkey trust root. The persisted root
    # lives at <state-dir>/vault_root.json; the bootloader's
    # create_server falls back to the persisted value when no
    # capability_operator_pubkey kwarg is supplied.
    p_vault = sub.add_parser(
        "vault",
        help="Manage the operator's capability-JWT trust root.",
    )
    sub_vault = p_vault.add_subparsers(
        dest="vault_command", required=True,
        metavar="{bootstrap,status,seal-passphrase,verify-passphrase,enrol-member}",
    )
    p_vault_bootstrap = sub_vault.add_parser(
        "bootstrap",
        help=(
            "Install the operator's secp256k1 pubkey as the vault's "
            "trust root. Subsequent capability-JWT verification uses "
            "this pubkey. Refuses to overwrite an existing root unless "
            "--force is passed."
        ),
    )
    p_vault_bootstrap.add_argument(
        "pubkey",
        help=(
            "Operator's 64-byte uncompressed secp256k1 pubkey "
            "(X || Y, no 0x04 prefix), hex-encoded (128 hex chars). "
            "May also be a path to a file containing the hex string."
        ),
    )
    p_vault_bootstrap.add_argument(
        "--force",
        action="store_true",
        help=(
            "Overwrite an existing vault_root.json. Default is to "
            "refuse if the vault is already bootstrapped (the operator "
            "rotates the root by removing the file or passing --force)."
        ),
    )
    p_vault_bootstrap.add_argument(
        "--state-dir",
        default=None,
        help=(
            "Override the bootloader state directory. Default reads "
            "from RECTO_BOOTLOADER_STATE_DIR env var or uses the "
            "per-platform default."
        ),
    )
    p_vault_seal_pass = sub_vault.add_parser(
        "seal-passphrase",
        help=(
            "Seal the PASSPHRASE genesis member. Prompts twice, without "
            "echo. The phrase is never accepted as an argument, never "
            "written, and never logged -- only its public key is stored."
        ),
    )
    p_vault_seal_pass.add_argument(
        "--state-dir", default=None,
        help="Override the bootloader state directory.",
    )
    p_vault_seal_pass.add_argument(
        "--force", action="store_true",
        help=(
            "Replace an already-sealed passphrase member. Default is to "
            "REFUSE -- resealing orphans anything that trusted the old one."
        ),
    )
    p_vault_verify_pass = sub_vault.add_parser(
        "verify-passphrase",
        help=(
            "THE RECOVERY DRILL. Prompts once, without echo, and reports "
            "whether the phrase rebuilds the SEALED passphrase member. "
            "Reads nothing else, writes nothing, reveals nothing. Run it "
            "cold, from the paper, on a day you have not just typed it."
        ),
    )
    p_vault_verify_pass.add_argument(
        "--state-dir", default=None,
        help="Override the bootloader state directory.",
    )
    # GATE 5 -- THE CHAIN WRITER.
    #
    # The chain has had a replay/verify path since GATE 5 and no way to
    # produce one, so no vault held a chain and the tamper detection
    # guarded a shape that existed only in tests. This is the producer.
    #
    # TWO PHASES ON PURPOSE. Every entry after genesis needs a MAJORITY of
    # the current members to sign it, and those signatures come from a
    # phone enclave and a passphrase -- neither of which this process can
    # or should hold. So the command first PRINTS what must be signed
    # (`--show-challenge`) and later ACCEPTS the signatures
    # (`--signature`). A single-phase command would have had to take
    # signing material as an argument, which is the one thing the
    # passphrase prompt exists to prevent.
    p_vault_enrol = sub_vault.add_parser(
        "enrol-member",
        help=(
            "Add or remove a genesis member THROUGH THE CHAIN. Entry 0 is "
            "unsigned (genesis); every entry after it requires a majority "
            "of the current members to sign. Run with --show-challenge to "
            "get the bytes to sign, then again with --signature."
        ),
    )
    p_vault_enrol.add_argument(
        "--kind", required=True,
        help=(
            "Member label, e.g. 'passphrase' or 'recovery-phone'. "
            "Alphanumeric and dashes."
        ),
    )
    p_vault_enrol.add_argument(
        "--pubkey", default=None,
        help=(
            "The member's raw public key, hex-encoded. Required when "
            "adding. Optional with --remove, where it defaults to the "
            "pubkey the chain already records for that kind."
        ),
    )
    p_vault_enrol.add_argument(
        "--algorithm", default="ed25519",
        help="Signature algorithm for the member being added. Default ed25519.",
    )
    p_vault_enrol.add_argument(
        "--remove", action="store_true",
        help=(
            "Remove the named member instead of adding it. This is why the "
            "threshold is a majority and not unanimity: a lost member must "
            "be removable by the members that remain."
        ),
    )
    p_vault_enrol.add_argument(
        "--genesis", action="store_true",
        help=(
            "Write entry 0. Unsigned BY DEFINITION -- there is no prior set "
            "to have signed it. Refuses if a chain already exists."
        ),
    )
    p_vault_enrol.add_argument(
        "--adopt-existing", action="store_true",
        help=(
            "Start the chain from the member already sealed in the flat "
            "pre-chain store, rather than from --pubkey. This is the "
            "migration path for a vault sealed before GATE 5."
        ),
    )
    p_vault_enrol.add_argument(
        "--signature", action="append", default=[], metavar="B64U",
        help=(
            "A member's signature over the challenge, base64url. Repeat "
            "once per signing member."
        ),
    )
    p_vault_enrol.add_argument(
        "--show-challenge", action="store_true",
        help=(
            "Print the exact bytes the members must sign, and who must "
            "sign them, then exit without writing."
        ),
    )
    p_vault_enrol.add_argument(
        "--state-dir", default=None,
        help="Override the bootloader state directory.",
    )
    p_vault_status = sub_vault.add_parser(
        "status",
        help=(
            "Report whether the vault has been bootstrapped, and if "
            "so, the operator's pubkey hex."
        ),
    )
    p_vault_status.add_argument(
        "--state-dir",
        default=None,
        help="Override the bootloader state directory.",
    )

    # profile (Phase 2.0.B integration — list / show / create /
    # master-pubkey are shipped real implementations. add-device /
    # revoke-device / rotate-master remain v2.1+ placeholders pending
    # their own PendingRequest kinds + phone-side approval surfaces.)
    p_profile = sub.add_parser(
        "profile",
        help=(
            "Multi-profile identity (Phase 2.0.B: list, show, create, "
            "master-pubkey shipped; add-device / revoke-device / "
            "rotate-master are v2.1 placeholders)."
        ),
    )
    sub_profile = p_profile.add_subparsers(
        dest="profile_command",
        required=True,
        metavar="{list,show,create,add-device,revoke-device,rotate-master,master-pubkey}",
    )
    p_profile_list = sub_profile.add_parser(
        "list", help="List profiles under this master."
    )
    p_profile_list.add_argument(
        "--state-dir",
        default=None,
        help=(
            "Override the bootloader state directory. Default reads "
            "from RECTO_BOOTLOADER_STATE_DIR env var or uses the "
            "per-platform default."
        ),
    )
    p_profile_list.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of operator-friendly text.",
    )
    p_profile_show = sub_profile.add_parser(
        "show", help="Show one profile's full details."
    )
    p_profile_show.add_argument("profile_id")
    p_profile_show.add_argument("--state-dir", default=None)
    p_profile_show.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of operator-friendly text.",
    )
    p_profile_create = sub_profile.add_parser(
        "create",
        help=(
            "Mint a new profile under the master (operator phone "
            "approval required)."
        ),
    )
    p_profile_create.add_argument(
        "kind",
        help=(
            "Profile kind: personal:child, work, school, contractor, "
            "or a custom operator-defined string."
        ),
    )
    p_profile_create.add_argument(
        "--name",
        required=False,
        default=None,
        help=(
            "Display name shown on the phone approval card. "
            "Defaults to a kind-derived label."
        ),
    )
    p_profile_create.add_argument(
        "--theme",
        required=False,
        default=None,
        help="Optional theme hint (e.g. 'blue', 'green') for the phone picker.",
    )
    p_profile_create.add_argument(
        "--scim-provider",
        required=False,
        default=None,
        help="Optional SCIM provider URL/identifier (work/school/contractor).",
    )
    p_profile_create.add_argument(
        "--bootloader-url",
        default=None,
        help=(
            "URL of the local Recto bootloader. Default reads from "
            "RECTO_BOOTLOADER_URL env var or http://127.0.0.1:8765."
        ),
    )
    p_profile_create.add_argument(
        "--phone-id",
        default=None,
        help=(
            "phone_id to queue the approval against. Default reads "
            "from RECTO_PHONE_ID env var."
        ),
    )
    p_profile_create.add_argument(
        "--agent-id",
        default=None,
        help=(
            "X-Recto-Agent-Id header value. Default reads from "
            "RECTO_AGENT_ID env var."
        ),
    )
    p_profile_create.add_argument(
        "--agent-token",
        default=None,
        help=(
            "X-Recto-Agent-Token header value. Default reads from "
            "RECTO_AGENT_TOKEN env var. Exposes the token in shell "
            "history -- prefer the env var."
        ),
    )
    p_profile_create.add_argument(
        "--candidate-profile-id",
        default=None,
        help=(
            "Override the auto-generated UUID4 idempotency key. "
            "Use the SAME value when retrying a previously-submitted "
            "create to hit the bootloader's idempotent already_exists "
            "path (Milan commitment A). Default: fresh UUID4 per call."
        ),
    )
    p_profile_create.add_argument(
        "--ttl-seconds",
        type=int,
        default=600,
        help=(
            "How long the operator has to approve on the phone "
            "(default 600s = 10 minutes; range 60..86400)."
        ),
    )
    p_profile_create.add_argument(
        "--poll-timeout",
        type=int,
        default=600,
        help=(
            "Wall-clock seconds to wait for the operator to "
            "approve/deny (default 600s)."
        ),
    )
    p_profile_create.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Seconds between result polls (default 2.0).",
    )
    p_profile_create.add_argument(
        "--state-dir",
        default=None,
        help=(
            "Override the bootloader state directory (for post-approval "
            "profile lookup). Default reads RECTO_BOOTLOADER_STATE_DIR."
        ),
    )
    p_profile_create.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of operator-friendly text.",
    )
    p_profile_add_device = sub_profile.add_parser(
        "add-device",
        help=(
            "Append a paired phone to a profile's device_ids tuple. "
            "Phase 2.0.C wave C.5 — operator-master-attested via the "
            "phone enclave; idempotent on (profile_id, new_phone_id)."
        ),
    )
    p_profile_add_device.add_argument(
        "profile_id",
        help="Target profile_id (UUID4) under the bootstrapped master.",
    )
    p_profile_add_device.add_argument(
        "--new-phone-id",
        required=True,
        help=(
            "phone_id of the device being added. Must already be "
            "registered with the bootloader via the v0.4 pair flow."
        ),
    )
    p_profile_add_device.add_argument(
        "--new-phone-label",
        default=None,
        help=(
            "Optional friendly label for the new device (rendered on "
            "the operator's approval card). e.g. 'Pixel 10 Pro Fold'."
        ),
    )
    p_profile_add_device.add_argument(
        "--master-phone-id",
        default=None,
        help=(
            "phone_id of the master device that will sign the "
            "attestation (the phone holding the operator's BIP-39 "
            "mnemonic). Default reads from RECTO_PHONE_ID env var."
        ),
    )
    p_profile_add_device.add_argument(
        "--bootloader-url",
        default=None,
        help=(
            "Bootloader HTTP base URL (e.g. http://127.0.0.1:8765). "
            "Default reads from RECTO_BOOTLOADER_URL env var, falling "
            "back to http://127.0.0.1:8765."
        ),
    )
    p_profile_add_device.add_argument(
        "--agent-id",
        default=None,
        help="X-Recto-Agent-Id header value. Default RECTO_AGENT_ID env.",
    )
    p_profile_add_device.add_argument(
        "--agent-token",
        default=None,
        help=(
            "X-Recto-Agent-Token header value. Default RECTO_AGENT_TOKEN "
            "env. Exposes the token in shell history -- prefer the env."
        ),
    )
    p_profile_add_device.add_argument(
        "--ttl-seconds",
        type=int,
        default=600,
        help=(
            "How long the operator has to approve on the phone "
            "(default 600s = 10 minutes; range 60..86400)."
        ),
    )
    p_profile_add_device.add_argument(
        "--poll-timeout",
        type=int,
        default=600,
        help=(
            "Wall-clock seconds to wait for the operator to "
            "approve/deny (default 600s)."
        ),
    )
    p_profile_add_device.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Seconds between result polls (default 2.0).",
    )
    p_profile_add_device.add_argument(
        "--state-dir",
        default=None,
        help=(
            "Override the bootloader state directory (for post-approval "
            "profile lookup). Default reads RECTO_BOOTLOADER_STATE_DIR."
        ),
    )
    p_profile_add_device.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of operator-friendly text.",
    )
    p_profile_revoke_device = sub_profile.add_parser(
        "revoke-device",
        help=(
            "Remove a paired phone from a profile's device_ids tuple. "
            "Phase 2.0.C wave C.6 — operator-master-attested via the "
            "phone enclave; idempotent on (profile_id, phone_id_to_revoke). "
            "At v1 only K=1 master-only signing is supported; profiles "
            "with revoke_quorum_k >= 2 are rejected with "
            "quorum_not_yet_implemented (banked for v1.1)."
        ),
    )
    p_profile_revoke_device.add_argument(
        "profile_id",
        help="Target profile_id (UUID4) under the bootstrapped master.",
    )
    p_profile_revoke_device.add_argument(
        "--phone-id-to-revoke",
        required=True,
        help=(
            "phone_id of the device being removed from device_ids. "
            "Must currently be a member of the profile's device_ids "
            "(if not, returns immediately with an idempotent "
            "already_not_member status code)."
        ),
    )
    p_profile_revoke_device.add_argument(
        "--revoker-label",
        default=None,
        help=(
            "Optional friendly label for the master device signing "
            "the revocation (rendered on the approval card)."
        ),
    )
    p_profile_revoke_device.add_argument(
        "--master-phone-id",
        default=None,
        help=(
            "phone_id of the master device signing the attestation. "
            "Default reads from RECTO_PHONE_ID env var."
        ),
    )
    p_profile_revoke_device.add_argument(
        "--bootloader-url",
        default=None,
        help=(
            "Bootloader HTTP base URL. Default reads from "
            "RECTO_BOOTLOADER_URL env var, falling back to "
            "http://127.0.0.1:8765."
        ),
    )
    p_profile_revoke_device.add_argument(
        "--agent-id",
        default=None,
        help="X-Recto-Agent-Id header value. Default RECTO_AGENT_ID env.",
    )
    p_profile_revoke_device.add_argument(
        "--agent-token",
        default=None,
        help=(
            "X-Recto-Agent-Token header value. Default RECTO_AGENT_TOKEN "
            "env."
        ),
    )
    p_profile_revoke_device.add_argument(
        "--ttl-seconds",
        type=int,
        default=600,
        help="How long the operator has to approve (default 600s, range 60..86400).",
    )
    p_profile_revoke_device.add_argument(
        "--poll-timeout",
        type=int,
        default=600,
        help="Wall-clock seconds to wait for operator action (default 600s).",
    )
    p_profile_revoke_device.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Seconds between result polls (default 2.0).",
    )
    p_profile_revoke_device.add_argument(
        "--state-dir",
        default=None,
        help=(
            "Override the bootloader state directory. Default reads "
            "RECTO_BOOTLOADER_STATE_DIR."
        ),
    )
    p_profile_revoke_device.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of operator-friendly text.",
    )
    sub_profile.add_parser(
        "rotate-master",
        help="(v2.1) Catastrophic — re-derive every profile from a new master.",
    )
    p_profile_master_pubkey = sub_profile.add_parser(
        "master-pubkey",
        help="Print the master enclave pubkey hex (consumer dedupe).",
    )
    p_profile_master_pubkey.add_argument("--state-dir", default=None)

    # status
    p_status = sub.add_parser("status", help="Report NSSM service state.")
    p_status.add_argument("service")

    # migrate-from-nssm
    p_migrate = sub.add_parser(
        "migrate-from-nssm", help="Migrate an existing NSSM service to Recto-managed config."
    )
    p_migrate.add_argument("service")
    p_migrate.add_argument("--yaml-out")
    p_migrate.add_argument("--python-exe", default="python.exe")
    p_migrate.add_argument("--dry-run", action="store_true")
    p_migrate.add_argument(
        "--keep-as-env",
        default="",
        help=(
            "Comma-separated list of AppEnvironmentExtra keys that should "
            "land in the YAML's spec.env: block instead of CredMan. "
            "Default: empty -- every entry treated as a secret."
        ),
    )
    p_migrate.add_argument(
        "--secret-backend",
        default="credman",
        choices=["credman", "dpapi-machine"],
        help=(
            "Where to install the migrated secrets. 'credman' (default) "
            "uses Windows Credential Manager — but CredMan is per-user, "
            "so the migrating user must match the NSSM service ObjectName "
            "or the service will see ERROR_NOT_FOUND at start time. "
            "'dpapi-machine' uses CryptProtectData with "
            "CRYPTPROTECT_LOCAL_MACHINE flag and stores under "
            "C:\\ProgramData\\recto\\<service>\\, which any process on "
            "the box can decrypt. Use dpapi-machine when the NSSM "
            "service runs as LocalSystem and the operator is migrating "
            "from an admin user account."
        ),
    )

    # events
    p_events = sub.add_parser(
        "events", help="Dump the running launcher's recent lifecycle events.",
    )
    p_events.add_argument("yaml_path")
    p_events.add_argument("--kind", default=None)
    p_events.add_argument("--limit", type=int, default=200)
    p_events.add_argument("--restart-history", action="store_true")

    # apply
    p_apply = sub.add_parser(
        "apply", help="Reconcile NSSM service state to match a service.yaml.",
    )
    p_apply.add_argument("yaml_path")
    # --python-exe defaults to None (Papercut #1, v0.2.x+); when omitted,
    # `recto apply` keeps NSSM's existing Application value verbatim
    # rather than proposing a change to bare 'python.exe'. Explicit
    # value (e.g. C:\Python314\python.exe) still lands as a proposed
    # change. See recto.reconcile.compute_plan for the resolution.
    p_apply.add_argument("--python-exe", default=None)
    p_apply.add_argument("--yes", "-y", action="store_true")
    p_apply.add_argument("--dry-run", action="store_true")

    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    credman_factory: CredManFactory | None = None,
    nssm_factory: NssmFactory | None = None,
    prompt: PromptFn = getpass.getpass,
    confirm: ConfirmFn = input,
    launch_fn: LaunchFn | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out: TextIO = stdout if stdout is not None else sys.stdout
    err: TextIO = stderr if stderr is not None else sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0
    cmd: str = args.command
    try:
        if cmd == "launch":
            return _cmd_launch(args, launch_fn=launch_fn, out=out, err=err)
        if cmd == "credman":
            sub = args.credman_command
            cred = (credman_factory or _default_credman_factory)(args.service)
            if sub == "set":
                return _cmd_credman_set(args, cred=cred, prompt=prompt, out=out, err=err)
            if sub == "list":
                return _cmd_credman_list(args, cred=cred, out=out, err=err)
            if sub == "delete":
                return _cmd_credman_delete(args, cred=cred, out=out, err=err)
            print(f"recto credman: unknown subcommand {sub!r}", file=err)
            return 2
        if cmd == "secrets":
            sub = args.secrets_command
            if sub == "set":
                return _cmd_secrets_set(args, prompt=prompt, out=out, err=err)
            if sub == "list":
                return _cmd_secrets_list(args, out=out, err=err)
            if sub == "delete":
                return _cmd_secrets_delete(args, out=out, err=err)
            print(f"recto secrets: unknown subcommand {sub!r}", file=err)
            return 2
        if cmd == "vault":
            sub = args.vault_command
            if sub == "bootstrap":
                return _cmd_vault_bootstrap(args, out=out, err=err)
            if sub == "status":
                return _cmd_vault_status(args, out=out, err=err)
            if args.vault_command == "seal-passphrase":
                return _cmd_vault_seal_passphrase(args, out=out, err=err)
            if args.vault_command == "verify-passphrase":
                return _cmd_vault_verify_passphrase(args, out=out, err=err)
            if args.vault_command == "enrol-member":
                return _cmd_vault_enrol_member(args, out=out, err=err)
            print(f"recto vault: unknown subcommand {sub!r}", file=err)
            return 2
        if cmd == "profile":
            sub_cmd = getattr(args, "profile_command", None)
            if sub_cmd == "list":
                return _cmd_profile_list(args, out=out, err=err)
            if sub_cmd == "show":
                return _cmd_profile_show(args, out=out, err=err)
            if sub_cmd == "master-pubkey":
                return _cmd_profile_master_pubkey(args, out=out, err=err)
            if sub_cmd == "create":
                return _cmd_profile_create(args, out=out, err=err)
            if sub_cmd == "add-device":
                return _cmd_profile_add_device(args, out=out, err=err)
            if sub_cmd == "revoke-device":
                return _cmd_profile_revoke_device(args, out=out, err=err)
            # rotate-master still v2.1+ placeholder.
            return _cmd_profile_v2_placeholder(args, out=out, err=err)
        if cmd == "status":
            nssm = (nssm_factory or _default_nssm_factory)()
            return _cmd_status(args, nssm=nssm, out=out, err=err)
        if cmd == "migrate-from-nssm":
            nssm = (nssm_factory or _default_nssm_factory)()
            backend_name = getattr(args, "secret_backend", "credman")
            if backend_name == "credman":
                # Honor the credman_factory test-injection seam (existing
                # contract). Most tests in tests/test_cli.py pass a
                # FakeCredManSource via this factory.
                cred = (credman_factory or _default_credman_factory)(args.service)
            else:
                # Non-credman backends resolve via the registered factory.
                # Tests that need to mock these can register_source(...)
                # with a fake before calling main(); this keeps the seam
                # uniform across backends without per-backend factory args.
                from recto.secrets import resolve_source
                cred = resolve_source(backend_name, args.service)
            return _cmd_migrate_from_nssm(args, nssm=nssm, cred=cred, out=out, err=err)
        if cmd == "apply":
            nssm = (nssm_factory or _default_nssm_factory)()
            return _cmd_apply(args, nssm=nssm, confirm=confirm, out=out, err=err)
        if cmd == "events":
            return _cmd_events(args, out=out, err=err)
    except KeyboardInterrupt:
        print("\nrecto: interrupted", file=err)
        return 130
    print(f"recto: unknown command {cmd!r}", file=err)
    return 2


def _detect_user_objectname_mismatch(nssm, service: str) -> tuple[str, str] | None:
    """Return (current_user, object_name) if there's a mismatch between
    the migrating user and the NSSM service's ObjectName that would
    cause CredMan secrets to be invisible to the service. Returns None
    if there's no mismatch (or if we can't determine).

    The mismatch matters because Windows Credential Manager is per-user
    (CRED_PERSIST_LOCAL_MACHINE only persists across logons of the SAME
    user, not across users). If the service runs as LocalSystem and the
    operator runs the migrator as themselves, the service won't see the
    operator's CredMan entries.

    Heuristic:
        - Any of {"LocalSystem", "NT AUTHORITY\\SYSTEM",
          ".\\LocalSystem"} (case-insensitive) means the service runs as
          SYSTEM; the migrating user is almost certainly not SYSTEM.
        - "NT AUTHORITY\\NetworkService" / "NT AUTHORITY\\LocalService"
          are also service accounts the operator probably can't match.
        - Any other ObjectName (a real user account like "DOMAIN\\user")
          is compared case-insensitively to the current username.

    On non-Windows we don't have a meaningful current user concept for
    this check, and migrate-from-nssm doesn't apply there anyway, so we
    return None.
    """
    import getpass

    if sys.platform != "win32":
        return None
    try:
        object_name = nssm.get(service, "ObjectName").strip()
    except NssmError:
        # Couldn't read ObjectName — let the apply attempt proceed; if
        # CredMan reads later fail, the user gets the underlying error.
        return None
    if not object_name:
        return None

    current_user = getpass.getuser()
    service_accounts_lower = {
        "localsystem",
        "nt authority\\system",
        ".\\localsystem",
        "nt authority\\networkservice",
        "nt authority\\localservice",
    }
    object_lower = object_name.lower()
    user_lower = current_user.lower()

    # If the service runs as a well-known service account and the user
    # isn't running as SYSTEM (which would itself be unusual), it's a
    # mismatch.
    if object_lower in service_accounts_lower:
        if user_lower not in {"system", "networkservice", "localservice"}:
            return current_user, object_name
        return None

    # If the service runs as a real user account, compare username forms.
    # The ObjectName might be "DOMAIN\\User" or just "User" — accept a
    # match against either segment.
    object_user = object_lower.rsplit("\\", 1)[-1]
    if object_user != user_lower:
        return current_user, object_name
    return None


def _default_credman_factory(service: str) -> CredManSource:
    return CredManSource(service)


def _default_nssm_factory() -> NssmClient:
    return NssmClient()


def _cmd_launch(args, *, launch_fn, out, err):
    yaml_path = Path(args.yaml_path)
    try:
        config: ServiceConfig = load_config(yaml_path)
    except ConfigValidationError as exc:
        print(f"recto launch: invalid config: {exc}", file=err)
        return 1
    except FileNotFoundError:
        print(f"recto launch: file not found: {yaml_path}", file=err)
        return 1
    if launch_fn is None:
        from recto.launcher import launch as _launch_once
        from recto.launcher import run as _launch_run
        launch_fn = _launch_once if args.once else _launch_run
    return int(launch_fn(config))


def _cmd_credman_set(args, *, cred, prompt, out, err):
    service, name = args.service, args.name
    if args.value is not None:
        value = args.value
    else:
        value = prompt(f"Value for recto:{service}:{name} (input hidden): ")
        if not value:
            print("recto credman set: refusing to install empty value; use --value '' if you really mean it", file=err)
            return 1
    try:
        cred.write(name, value)
    except SecretSourceError as exc:
        print(f"recto credman set: {exc}", file=err)
        return 1
    print(f"installed recto:{service}:{name}", file=out)
    return 0


def _cmd_credman_list(args, *, cred, out, err):
    try:
        names = cred.list_names()
    except SecretSourceError as exc:
        print(f"recto credman list: {exc}", file=err)
        return 1
    for n in names:
        print(n, file=out)
    return 0


def _cmd_credman_delete(args, *, cred, out, err):
    name, service = args.name, args.service
    try:
        cred.delete(name)
    except SecretNotFoundError:
        print(f"recto credman delete: recto:{service}:{name} does not exist", file=err)
        return 1
    except SecretSourceError as exc:
        print(f"recto credman delete: {exc}", file=err)
        return 1
    print(f"deleted recto:{service}:{name}", file=out)
    return 0


def _cmd_secrets_set(args, *, prompt, out, err):
    """Backend-agnostic secret install (counterpart to `recto credman set`).

    Resolves the requested backend via the secrets registry and calls
    its `write()` method. The default backend is `dpapi-machine` because
    that's the production default for any service running under
    `LocalSystem` (CredMan is per-user and produces ERROR_NOT_FOUND when
    the service account differs from the writing user).

    Refuses to install an empty value unless `--value ''` is passed
    explicitly, mirroring `recto credman set`'s safety guard. Empty
    values are almost always a paste error; the explicit form is the
    way to say "I really do mean a zero-length secret."

    Test injection: the resolution path goes through
    `recto.secrets.resolve_source`, which respects any
    `register_source` overrides installed by tests. There is no
    `secrets_factory` parameter on `main()` because the registry IS
    the seam — tests register a fake backend under a chosen selector
    name and pass `--source <that-name>`.
    """
    from recto.secrets import resolve_source

    service, name, source_name = args.service, args.name, args.source
    if args.value is not None:
        value = args.value
    else:
        value = prompt(f"Value for recto:{service}:{name} (input hidden): ")
        if not value:
            print(
                "recto secrets set: refusing to install empty value; "
                "use --value '' if you really mean it",
                file=err,
            )
            return 1
    try:
        source = resolve_source(source_name, service)
    except SecretSourceError as exc:
        print(f"recto secrets set: {exc}", file=err)
        return 1
    write_fn = getattr(source, "write", None)
    if write_fn is None or not callable(write_fn):
        print(
            f"recto secrets set: backend {source_name!r} does not support "
            f"write() (read-only or external-vault backend)",
            file=err,
        )
        return 1
    try:
        write_fn(name, value)
    except SecretSourceError as exc:
        print(f"recto secrets set: {exc}", file=err)
        return 1
    print(f"[{source_name}] installed recto:{service}:{name}", file=out)
    return 0


def _cmd_secrets_delete(args, *, out, err):
    """Backend-agnostic secret deletion (counterpart to `recto credman delete`).

    Defaults to `dpapi-machine` for symmetry with `recto secrets set`.
    Returns exit code 1 if the secret doesn't exist (rather than silently
    succeeding) so operator scripts can distinguish "deleted" from
    "wasn't there."
    """
    from recto.secrets import resolve_source

    service, name, source_name = args.service, args.name, args.source
    try:
        source = resolve_source(source_name, service)
    except SecretSourceError as exc:
        print(f"recto secrets delete: {exc}", file=err)
        return 1
    delete_fn = getattr(source, "delete", None)
    if delete_fn is None or not callable(delete_fn):
        print(
            f"recto secrets delete: backend {source_name!r} does not support "
            f"delete() (read-only or external-vault backend)",
            file=err,
        )
        return 1
    try:
        delete_fn(name)
    except SecretNotFoundError:
        print(
            f"recto secrets delete: [{source_name}] recto:{service}:{name} "
            f"does not exist",
            file=err,
        )
        return 1
    except SecretSourceError as exc:
        print(f"recto secrets delete: {exc}", file=err)
        return 1
    print(f"[{source_name}] deleted recto:{service}:{name}", file=out)
    return 0


def _cmd_secrets_list(args, *, out, err):
    """Backend-agnostic secret listing (Papercut #2).

    Iterates every registered SecretSource backend, instantiates each
    via its registered factory with the service name, and lists the
    secret names found in each. Backends that don't support listing
    (no `list_names` method, e.g. EnvSource which reads from the
    process environment with no enumeration primitive) are skipped
    silently -- their absence isn't an error, they just don't have a
    listable inventory.

    Output format: one line per secret, prefixed with `[<backend>]`
    so an operator can grep by backend (`recto secrets list svc |
    grep '\\[dpapi-machine\\]'`) or strip the prefix
    (`recto secrets list svc | awk '{print $2}'`). Backend order is
    sorted by selector name for deterministic output.
    """
    from recto.secrets import registered_sources, resolve_source

    service = args.service
    for backend_name in registered_sources():
        try:
            source = resolve_source(backend_name, service)
        except SecretSourceError as exc:
            print(
                f"recto secrets list: skipping {backend_name!r}: {exc}",
                file=err,
            )
            continue
        list_names = getattr(source, "list_names", None)
        if list_names is None or not callable(list_names):
            # Backend doesn't support enumeration (e.g. env passthrough).
            # Not an error; just nothing to list.
            continue
        try:
            names = list_names()
        except SecretSourceError as exc:
            print(
                f"recto secrets list: {backend_name!r}: {exc}",
                file=err,
            )
            continue
        except OSError as exc:
            # Backend-specific I/O failure (e.g. dpapi-machine can't
            # read C:\ProgramData\recto\<service>\). Surface the error
            # but continue with other backends.
            print(
                f"recto secrets list: {backend_name!r}: {exc}",
                file=err,
            )
            continue
        for n in names:
            print(f"[{backend_name}] {n}", file=out)
    # Return 0 even when no secrets are found -- an empty inventory is
    # valid state (a freshly migrated service before any secrets have
    # been installed).
    return 0


def _cmd_vault_bootstrap(args, *, out, err):
    """Install the operator's secp256k1 pubkey as the vault trust root.

    Writes ``vault_root.json`` in the bootloader's state dir.
    Refuses to overwrite unless ``--force`` is passed.

    The pubkey argument may be either:
    - A hex string (128 chars, optionally 0x-prefixed and stripped)
    - A path to a file whose contents are the hex string

    Phase 5 Wave C part 4. CLI-only at v1; HTTP bootstrap with a
    bootstrap-token auth path is a future iteration.
    """
    from recto.bootloader.state import StateStore, default_state_dir
    from pathlib import Path

    raw = args.pubkey.strip()
    # If it looks like an existing file, read the hex from disk.
    candidate = Path(raw)
    if candidate.is_file():
        raw = candidate.read_text(encoding="utf-8").strip()
    # Strip optional 0x prefix.
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    if len(raw) != 128:
        print(
            f"recto vault bootstrap: pubkey must be 128 hex chars "
            f"(64-byte uncompressed X || Y); got {len(raw)} chars.",
            file=err,
        )
        return 2
    try:
        pubkey_bytes = bytes.fromhex(raw)
    except ValueError as exc:
        print(f"recto vault bootstrap: invalid hex: {exc}", file=err)
        return 2
    state_dir = Path(args.state_dir) if args.state_dir else None
    state_dir = state_dir if state_dir is not None else default_state_dir()
    state = StateStore(state_dir=state_dir)
    if state.is_vault_bootstrapped() and not args.force:
        existing = state.get_operator_pubkey()
        existing_hex = existing.hex() if existing else "(unreadable)"
        print(
            f"recto vault bootstrap: vault is already bootstrapped at "
            f"{state.state_dir / 'vault_root.json'} with pubkey "
            f"{existing_hex}.\n"
            f"Pass --force to overwrite, or remove the file manually if "
            f"you want a clean rotation.",
            file=err,
        )
        return 1
    try:
        state.put_operator_pubkey(pubkey_bytes)
    except ValueError as exc:
        print(f"recto vault bootstrap: {exc}", file=err)
        return 2
    print(
        f"recto vault: bootstrapped trust root at "
        f"{state.state_dir / 'vault_root.json'}",
        file=out,
    )
    print(f"  operator pubkey: {pubkey_bytes.hex()}", file=out)
    print(
        "Subsequent bootloader starts pick up this pubkey automatically "
        "via create_server's fallback. Remove the file (or re-run with "
        "--force) to rotate.",
        file=out,
    )
    return 0


PASSPHRASE_MEMBER_KIND = "passphrase"


def _resolve_state_dir(args):
    """Same resolution `vault status` uses -- explicit flag, else default."""
    from recto.bootloader.state import default_state_dir
    from pathlib import Path
    return Path(args.state_dir) if args.state_dir else default_state_dir()


def _prompt_passphrase(label: str) -> str:
    """Read a phrase with NO ECHO.

    `getpass` reads from the controlling terminal, not stdin, so the phrase
    does not land in a shell history, a pipe, a process listing, or a scroll
    buffer. **The CLI must never accept the phrase as an argument** -- argv is
    visible in `ps` to every user on the box and is recorded by most shells.
    That is why `vault bootstrap` taking its pubkey positionally is fine (a
    pubkey is public) and would be catastrophic here.
    """
    import getpass
    import sys

    # REFUSE WITHOUT A TTY. `getpass` does NOT fail when it cannot reach a
    # terminal -- it emits a GetPassWarning and falls back to input(), WHICH
    # ECHOES. In a `docker exec` without -it, or under a pipe, that would
    # print the passphrase into a terminal log or CI output and nobody would
    # notice until it was too late to unsee.
    #
    # A fallback that silently downgrades a no-echo prompt to an echoing one
    # is the same shape as every other defect this sprint has caught: it
    # succeeds, it looks right, and the failure is invisible.
    if not sys.stdin.isatty():
        raise SystemExit(
            "REFUSING: no terminal. This prompt must not echo, and without a "
            "TTY getpass silently falls back to an echoing read.\n"
            "If running in Docker, use:  docker exec -it <container> ...\n"
            "The -i and the -t are both required."
        )
    return getpass.getpass(f"  {label}: ")


def _cmd_vault_seal_passphrase(args, *, out, err):
    """Seal the passphrase member. Two prompts, then an explicit confirmation.

    WHY TWO PROMPTS AND NOT ONE: a single entry seals whatever was typed,
    including a typo, and the failure is silent forever after.

    WHY THAT IS STILL NOT ENOUGH, and why `verify-passphrase` exists: two
    entries ten seconds apart catch a SLIP, not a MISREADING. If the fourth
    word is read wrong off the paper it will be read wrong twice. Only a cold
    third entry, later, from the paper, catches that -- and by then the seal
    has happened, which is precisely why the drill must be runnable at any
    time and must never require the vault to be unsealed to run.
    """
    from recto.bootloader.state import StateStore
    from recto.profile.passphrase_member import (
        WeakPassphraseError, normalize_passphrase, passphrase_member_pubkey,
    )
    state = StateStore(state_dir=_resolve_state_dir(args))

    existing = state.get_genesis_member(PASSPHRASE_MEMBER_KIND)
    if existing is not None and not getattr(args, "force", False):
        print(
            "REFUSING: a passphrase member is already sealed "
            f"({existing.hex()[:16]}...). Resealing orphans anything that "
            "trusted the old one. Pass --force only if you mean to replace it.",
            file=err,
        )
        return 2

    # AN UNREADABLE MEMBER MUST BLOCK A SEAL EXACTLY AS A READABLE ONE DOES.
    # Without this the reseal guard reads `existing is None`, concludes the
    # slot is free, and QUIETLY OVERWRITES A DAMAGED MEMBER -- turning a
    # recoverable problem into an unrecoverable one, on the exact command an
    # operator would reach for after seeing an error.
    if existing is None and not getattr(args, "force", False):
        unreadable = state.list_unreadable_genesis_members()
        reason = unreadable.get(PASSPHRASE_MEMBER_KIND) or unreadable.get("<file>")
        if reason:
            print(
                "REFUSING: a passphrase member IS stored but cannot be "
                f"loaded -- {reason}\n"
                "Sealing now would overwrite it. Restore the state directory "
                "from backup first. Use --force only if you have decided the "
                "stored member is genuinely lost.",
                file=err,
            )
            return 3

    print("  The PASSPHRASE is entered here and nowhere else -- never on a", file=out)
    print("  phone, never as an argument, never into an agent.", file=out)
    print("  Eight words, separated by single spaces, letters only.", file=out)
    print("", file=out)
    first = _prompt_passphrase("Passphrase (not echoed)")
    second = _prompt_passphrase("Confirm              ")
    if normalize_passphrase(first) != normalize_passphrase(second):
        print("REFUSING: the two entries differ. Nothing was sealed.", file=err)
        return 2
    del second

    try:
        pubkey = passphrase_member_pubkey(first)
    except WeakPassphraseError as exc:
        print(f"REFUSING: {exc}", file=err)
        return 2
    finally:
        del first

    print("", file=out)
    print(f"  Derived passphrase member: {pubkey.hex()}", file=out)
    print("", file=out)
    print("  Sealing stores ONLY this public key. The words are not written.", file=out)
    answer = input("  Type SEAL to write it to the vault: ").strip()
    if answer != "SEAL":
        print("Not sealed (confirmation not given).", file=err)
        return 2

    state.put_genesis_member(PASSPHRASE_MEMBER_KIND, pubkey)
    print("", file=out)
    print("  SEALED.", file=out)
    print("", file=out)
    print("  NEXT, AND DO NOT SKIP IT: tomorrow, cold, from the paper, run", file=out)
    print("      recto vault verify-passphrase", file=out)
    print("  Two entries a minute apart cannot catch a MISREADING. A cold", file=out)
    print("  third entry can, and it is the only thing that can.", file=out)
    return 0


def _cmd_vault_verify_passphrase(args, *, out, err):
    """THE DRILL. Prompt once; report match against the sealed member.

    Reveals nothing on failure beyond the fact of failure -- no hint about
    which word, no partial match, because a partial-match oracle would turn
    this convenience into an attack surface for anyone with host access.
    """
    from recto.bootloader.state import StateStore
    from recto.profile.passphrase_member import (
        WeakPassphraseError, passphrase_member_pubkey,
    )
    state = StateStore(state_dir=_resolve_state_dir(args))
    sealed = state.get_genesis_member(PASSPHRASE_MEMBER_KIND)
    if sealed is None:
        # A DAMAGED MEMBER MUST NEVER REPORT AS AN ABSENT ONE. Told "nothing
        # is sealed" during a real recovery, an operator concludes the vault
        # is empty and starts over -- destroying what was still there.
        unreadable = state.list_unreadable_genesis_members()
        reason = unreadable.get(PASSPHRASE_MEMBER_KIND) or unreadable.get("<file>")
        if reason:
            print(
                "UNREADABLE: a passphrase member IS stored but cannot be "
                f"loaded -- {reason}\n"
                "This is NOT an empty vault. Do not re-seal: that would "
                "overwrite the stored member. Restore the state directory "
                "from backup, or seal a new member only after deciding the "
                "stored one is genuinely lost.",
                file=err,
            )
            return 3
        print("No passphrase member is sealed. Run `recto vault seal-passphrase`.",
              file=err)
        return 2

    entered = _prompt_passphrase("Passphrase (not echoed)")
    try:
        candidate = passphrase_member_pubkey(entered)
    except WeakPassphraseError as exc:
        print(f"REFUSED: {exc}", file=err)
        return 2
    finally:
        del entered

    import hmac
    if hmac.compare_digest(candidate, sealed):
        print("  MATCHES the sealed passphrase member.", file=out)
        return 0
    print("DOES NOT MATCH the sealed passphrase member.", file=err)
    print("Nothing is wrong with the vault -- the phrase entered is not the "
          "one that was sealed. Check the paper, not the software.", file=err)
    return 1


def _cmd_vault_enrol_member(args, *, out, err):
    """GATE 5 -- write one entry into the genesis membership chain.

    THIS COMMAND CANNOT PRODUCE A BROKEN CHAIN. It hands the candidate to
    `append_genesis_chain_entry`, which replays the WHOLE resulting chain and
    raises before writing. Every refusal below is therefore about telling the
    operator something useful EARLIER than the store would -- the store is the
    guard, these are the manners.
    """
    import base64

    from recto.bootloader.genesis_chain import (
        ChainError, entry_hash, required_signatures, signing_bytes,
    )
    from recto.bootloader.state import StateStore

    def _b64u(raw: bytes) -> str:
        return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")

    state = StateStore(state_dir=_resolve_state_dir(args))

    if not state.supports_genesis_chain():
        print(
            f"REFUSING: this backend ({type(state).__name__}) has no membership "
            f"chain. Membership there is a flat table with no tamper detection, "
            f"and writing a chain the reader will never consult would be worse "
            f"than not writing one.",
            file=err,
        )
        return 2

    kind = (args.kind or "").strip().lower()
    if not kind or not kind.replace("-", "").isalnum():
        print(f"REFUSING: --kind must be alphanumeric; got {args.kind!r}", file=err)
        return 2

    try:
        chain = state.read_genesis_chain()
    except ChainError as exc:
        # UNREADABLE IS NOT ABSENT. Starting a fresh chain here would write a
        # brand-new genesis over the top of one we could not parse.
        print(f"REFUSING: the stored chain cannot be read -- {exc}", file=err)
        print(
            "This is a tamper or corruption signal, NOT an empty vault. Restore "
            "genesis_members.json from backup before writing anything.",
            file=err,
        )
        return 3

    seq = len(chain)
    prev = None
    current: dict[str, object] = {}
    if chain:
        from recto.bootloader.genesis_chain import build_entry, replay
        try:
            entries = [
                build_entry(
                    seq=e["seq"], op=e["op"], kind=e["kind"],
                    pubkey=bytes.fromhex(e["pubkey"]), algorithm=e["algorithm"],
                    prev=e.get("prev"),
                    signatures=[
                        base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
                        for s in (e.get("signatures") or [])
                    ],
                )
                for e in chain
            ]
            current = replay(entries)
            prev = entry_hash(entries[-1])
        except (ChainError, KeyError, ValueError) as exc:
            print(f"REFUSING: the stored chain does not verify -- {exc}", file=err)
            return 3

    op = "remove" if args.remove else "add"

    # ---------------------------------------------------------------- genesis
    if seq == 0:
        flat = state.list_genesis_members_full()
        if args.remove:
            print(
                "REFUSING: entry 0 cannot be a removal -- there is no member yet "
                "to remove.",
                file=err,
            )
            return 2

        if args.adopt_existing:
            if not flat:
                print(
                    "REFUSING: --adopt-existing found no member in the flat "
                    "pre-chain store. There is nothing to adopt; use --genesis "
                    "with --pubkey to start a chain from scratch.",
                    file=err,
                )
                return 2
            # --kind MUST NAME AN ACTUAL SEALED MEMBER. No "there is only one,
            # so they must have meant that one" fallback: adoption picks which
            # key becomes the root of the whole chain, and a command that
            # silently adopts a different member than the one named has made
            # that choice on the operator's behalf.
            #
            # Adoption writes ONE entry, because entry 0 is the only unsigned
            # one. A second flat member is enrolled afterwards through the
            # normal signed path -- which requires the adopted member to sign
            # it, and that is the correct amount of ceremony for admitting a
            # key to the set.
            if kind not in flat:
                print(
                    f"REFUSING: --adopt-existing needs --kind to name a member "
                    f"that is actually sealed in the flat store. "
                    f"{kind!r} is not one of: {', '.join(sorted(flat))}.\n"
                    f"Adopt one of those as genesis, then enrol the rest with "
                    f"--signature from the adopted member.",
                    file=err,
                )
                return 2
            member = flat[kind]
            pubkey, algorithm = member.pubkey, member.algorithm
            print(
                f"  Adopting the already-sealed member {member.kind!r} as "
                f"genesis.", file=out,
            )
            if len(flat) > 1:
                remaining = sorted(k for k in flat if k != kind)
                print(
                    f"  NOTE: {len(remaining)} other sealed member(s) are NOT "
                    f"in the chain and will stop being visible: "
                    f"{', '.join(remaining)}.\n"
                    f"  Enrol each with --signature from {kind!r}.",
                    file=out,
                )
        else:
            if not args.genesis:
                print(
                    "REFUSING: there is no chain yet, so this would be entry 0, "
                    "and entry 0 is unsigned by definition. Say so explicitly:\n"
                    "  --genesis --pubkey <hex>        start a new chain, or\n"
                    "  --adopt-existing                start from the member "
                    "already sealed in the flat store.",
                    file=err,
                )
                return 2
            if flat:
                print(
                    f"REFUSING: {len(flat)} member(s) are already sealed in the "
                    f"flat pre-chain store ({', '.join(sorted(flat))}). Once a "
                    f"chain exists the flat store is NEVER read again, so a "
                    f"fresh genesis would silently orphan them.\n"
                    f"Use --adopt-existing to bring the sealed member into the "
                    f"chain instead.",
                    file=err,
                )
                return 2
            if not args.pubkey:
                print("REFUSING: --genesis needs --pubkey.", file=err)
                return 2
            try:
                pubkey = bytes.fromhex(args.pubkey.strip())
            except ValueError as exc:
                print(f"REFUSING: --pubkey is not valid hex: {exc}", file=err)
                return 2
            algorithm = args.algorithm

        record = {
            "seq": 0, "op": "add", "kind": kind,
            "pubkey": bytes(pubkey).hex(), "algorithm": algorithm,
            "prev": None, "signatures": [],
        }
        if args.show_challenge:
            print("  Entry 0 is UNSIGNED -- there is nothing to sign.", file=out)
            return 0
        try:
            state.append_genesis_chain_entry(record)
        except ChainError as exc:
            print(f"REFUSING: {exc}", file=err)
            return 3
        print(f"  Chain started. Entry 0: add {kind!r} ({algorithm}).", file=out)
        print(
            "  The flat pre-chain store is left in place as a rollback "
            "artifact and is no longer read.", file=out,
        )
        return 0

    # ------------------------------------------------------- signed entries
    if args.genesis or args.adopt_existing:
        print(
            f"REFUSING: a chain already exists ({seq} entries). --genesis and "
            f"--adopt-existing only apply to an empty chain.",
            file=err,
        )
        return 2

    if args.remove:
        if kind not in current:
            print(
                f"REFUSING: {kind!r} is not a current member. Members: "
                f"{', '.join(sorted(current)) or '<none>'}",
                file=err,
            )
            return 2
        if len(current) == 1:
            print(
                "REFUSING: that is the last member. A set with no members can "
                "never authorise another change -- the vault would be "
                "permanently unmanageable.",
                file=err,
            )
            return 2
        existing_entry = current[kind]
        pubkey = existing_entry.pubkey          # type: ignore[union-attr]
        algorithm = existing_entry.algorithm    # type: ignore[union-attr]
        if args.pubkey:
            try:
                supplied = bytes.fromhex(args.pubkey.strip())
            except ValueError as exc:
                print(f"REFUSING: --pubkey is not valid hex: {exc}", file=err)
                return 2
            if supplied != pubkey:
                # A removal names a member by KIND, but the entry carries the
                # pubkey too. If the operator supplied one and it disagrees
                # with the chain, they are not looking at the vault they think
                # they are -- and quietly using the chain's value would hide
                # that.
                print(
                    "REFUSING: the --pubkey supplied does not match the pubkey "
                    f"the chain records for {kind!r}. Omit --pubkey to remove "
                    f"the member the chain actually holds.",
                    file=err,
                )
                return 2
    else:
        if not args.pubkey:
            print("REFUSING: adding a member needs --pubkey.", file=err)
            return 2
        try:
            pubkey = bytes.fromhex(args.pubkey.strip())
        except ValueError as exc:
            print(f"REFUSING: --pubkey is not valid hex: {exc}", file=err)
            return 2
        algorithm = args.algorithm

    challenge = signing_bytes(
        seq=seq, op=op, kind=kind, pubkey=pubkey, algorithm=algorithm, prev=prev,
    )
    needed = required_signatures(len(current))

    if args.show_challenge or not args.signature:
        print(f"  Entry {seq}: {op} {kind!r} ({algorithm})", file=out)
        print(f"  Current members ({len(current)}): "
              f"{', '.join(sorted(current))}", file=out)
        print(f"  Signatures required: {needed} of {len(current)} (a majority)",
              file=out)
        if len(current) == 2:
            # Named because the chain's own docstring calls this the window to
            # minimise: at N=2 a majority IS both members, so the set has no
            # fault tolerance. Worth saying at the moment an operator is
            # standing in it.
            print("  NOTE: at two members a majority is BOTH of them, so the "
                  "set cannot yet survive losing one. Get to three.", file=out)
        print("", file=out)
        print("  Bytes to sign (base64url):", file=out)
        print(f"    {_b64u(challenge)}", file=out)
        print("", file=out)
        print("  Re-run with --signature <b64u> once per signing member.",
              file=out)
        if not args.show_challenge:
            # Reached because no signatures were supplied. That is a usage
            # error, not a success -- exiting 0 here would let a script
            # "enrol" a member and write nothing.
            print("REFUSING: no --signature supplied; nothing was written.",
                  file=err)
            return 2
        return 0

    signatures = []
    for raw in args.signature:
        s = raw.strip()
        try:
            signatures.append(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        except Exception as exc:
            print(f"REFUSING: --signature {s[:12]}... is not base64url: {exc}",
                  file=err)
            return 2

    record = {
        "seq": seq, "op": op, "kind": kind,
        "pubkey": bytes(pubkey).hex(), "algorithm": algorithm,
        "prev": prev, "signatures": [_b64u(s) for s in signatures],
    }
    try:
        state.append_genesis_chain_entry(record)
    except ChainError as exc:
        print(f"REFUSING: {exc}", file=err)
        return 3

    after = state.list_genesis_members_full()
    print(f"  Entry {seq} written: {op} {kind!r}.", file=out)
    print(f"  Members now ({len(after)}): {', '.join(sorted(after))}", file=out)
    return 0


def _cmd_vault_status(args, *, out, err):
    """Report vault bootstrapping state.

    Phase 5 Wave C part 4. Prints whether vault_root.json exists +
    the operator pubkey hex (audit-friendly; the pubkey isn't
    sensitive on its own, only the corresponding private key is).
    """
    from recto.bootloader.state import StateStore, default_state_dir
    from pathlib import Path

    state_dir = Path(args.state_dir) if args.state_dir else None
    state_dir = state_dir if state_dir is not None else default_state_dir()
    state = StateStore(state_dir=state_dir)
    if not state.is_vault_bootstrapped():
        print(f"recto vault: NOT bootstrapped (no {state.state_dir / 'vault_root.json'})", file=out)
        print(
            "Run `recto vault bootstrap <pubkey>` to install the "
            "operator's secp256k1 pubkey as the trust root.",
            file=out,
        )
        return 0
    pubkey = state.get_operator_pubkey()
    if pubkey is None:
        print(
            f"recto vault: vault_root.json exists at "
            f"{state.state_dir / 'vault_root.json'} but pubkey is "
            f"unreadable (file may be corrupt). Run `recto vault "
            f"bootstrap <pubkey> --force` to overwrite.",
            file=err,
        )
        return 1
    print(f"recto vault: bootstrapped at {state.state_dir / 'vault_root.json'}", file=out)
    print(f"  operator pubkey: {pubkey.hex()}", file=out)
    return 0


def _cmd_profile_list(args, *, out, err):
    """List every profile under the master.

    Phase 2.0.B integration. Read-only call into
    ``recto.profile.manage.list_profiles``. Outputs:

    * Text mode (default): one line per profile with profile_id, kind,
      display_name, derivation index, parent linkage, revoked flag.
      Master row is marked explicitly.
    * ``--json`` mode: a JSON array of objects with full field
      coverage for downstream tooling.

    Exit 0 if a master is bootstrapped (even if zero child profiles
    exist — master itself is always returned); exit 1 if no master
    has been bootstrapped (operator must run ``recto vault
    bootstrap`` + provision a master first).
    """
    from pathlib import Path

    from recto.profile.manage import list_profiles
    from recto.profile.store import load_master_identity

    state_dir = Path(args.state_dir) if args.state_dir else None
    mi = load_master_identity(state_dir=state_dir)
    if mi is None:
        if getattr(args, "json", False):
            print(_jsondump({"profiles": [], "master_bootstrapped": False}), file=out)
            return 1
        print(
            "recto profile list: no master is bootstrapped at this "
            "state directory. Use `recto vault bootstrap` to install "
            "the operator pubkey + provision a master.",
            file=err,
        )
        return 1

    profiles = list_profiles(state_dir=state_dir)
    if getattr(args, "json", False):
        rows = [_profile_to_json_row(p, master_id=mi.master_profile_id) for p in profiles]
        print(
            _jsondump({
                "master_bootstrapped": True,
                "master_pubkey_hex": mi.master_pubkey_hex,
                "master_profile_id": mi.master_profile_id,
                "label": mi.label,
                "profiles": rows,
            }),
            file=out,
        )
        return 0

    print(
        f"recto profile list ({len(profiles)} profile(s) under master "
        f"{mi.master_pubkey_hex[:8]}...{mi.master_pubkey_hex[-8:]}):",
        file=out,
    )
    for p in profiles:
        is_master = p.profile_id == mi.master_profile_id
        marker = "★ master" if is_master else "  child "
        revoked = " [REVOKED]" if p.revoked else ""
        derivation_label = (
            f"coin_type={p.derivation.profile_coin_type} "
            f"index={p.derivation.profile_index}"
        )
        print(
            f"  {marker} {p.profile_id}  "
            f"kind={p.kind}  name={p.display_name!r}  "
            f"{derivation_label}{revoked}",
            file=out,
        )
    return 0


def _cmd_profile_show(args, *, out, err):
    """Show one profile's full detail by profile_id.

    Phase 2.0.B integration. Wraps
    ``recto.profile.manage.get_profile_by_id`` and renders every
    field operators may need (kind, display name, derivation path
    in BIP-32 notation, theme hint, SCIM provider, inherited
    deny-actions, creation timestamp, revoked flag, parent linkage).

    Exit 0 on hit; exit 1 if the profile_id is not found OR if no
    master has been bootstrapped.
    """
    from pathlib import Path

    from recto.profile.manage import get_profile_by_id
    from recto.profile.store import load_master_identity

    state_dir = Path(args.state_dir) if args.state_dir else None
    mi = load_master_identity(state_dir=state_dir)
    if mi is None:
        if getattr(args, "json", False):
            print(_jsondump({"found": False, "master_bootstrapped": False}), file=out)
            return 1
        print(
            "recto profile show: no master is bootstrapped at this "
            "state directory.",
            file=err,
        )
        return 1
    profile = get_profile_by_id(args.profile_id, state_dir=state_dir)
    if profile is None:
        if getattr(args, "json", False):
            print(
                _jsondump({"found": False, "master_bootstrapped": True}),
                file=out,
            )
            return 1
        print(
            f"recto profile show: profile_id {args.profile_id!r} not "
            f"found under master {mi.master_pubkey_hex[:8]}...{mi.master_pubkey_hex[-8:]}.",
            file=err,
        )
        return 1
    if getattr(args, "json", False):
        print(
            _jsondump({
                "found": True,
                "master_pubkey_hex": mi.master_pubkey_hex,
                "profile": _profile_to_json_row(
                    profile, master_id=mi.master_profile_id
                ),
            }),
            file=out,
        )
        return 0
    is_master = profile.profile_id == mi.master_profile_id
    print(f"recto profile show {profile.profile_id}:", file=out)
    print(f"  role: {'master' if is_master else 'child'}", file=out)
    print(f"  kind: {profile.kind}", file=out)
    print(f"  display_name: {profile.display_name!r}", file=out)
    print(f"  derivation: {profile.derivation.as_bip32_string()}", file=out)
    print(
        f"    purpose={profile.derivation.purpose} "
        f"coin_type={profile.derivation.profile_coin_type} "
        f"index={profile.derivation.profile_index}",
        file=out,
    )
    print(f"  parent_profile_id: {profile.parent_profile_id}", file=out)
    print(f"  theme_hint: {profile.theme_hint}", file=out)
    print(f"  scim_provider: {profile.scim_provider}", file=out)
    if profile.deny_actions_inherited:
        print(
            f"  deny_actions_inherited ({len(profile.deny_actions_inherited)}):",
            file=out,
        )
        for action in profile.deny_actions_inherited:
            print(f"    - {action}", file=out)
    else:
        print("  deny_actions_inherited: (none)", file=out)
    print(f"  created_at_unix: {profile.created_at_unix}", file=out)
    print(f"  revoked: {profile.revoked}", file=out)
    return 0


def _cmd_profile_master_pubkey(args, *, out, err):
    """Print the master enclave pubkey hex.

    Phase 2.0.B integration. Wraps
    ``recto.profile.manage.get_master_pubkey_hex``. Pubkey is NOT
    sensitive on its own (the corresponding private key, which lives
    on the operator's phone enclave, is what matters). Downstream
    consumers use this for cross-profile identity deduplication
    (e.g. a consumer's user-record public-key column per its
    architectural commitment #11).

    Exit 0 on success; exit 1 if no master is bootstrapped.
    """
    from pathlib import Path

    from recto.profile.manage import get_master_pubkey_hex

    state_dir = Path(args.state_dir) if args.state_dir else None
    pubkey = get_master_pubkey_hex(state_dir=state_dir)
    if pubkey is None:
        print(
            "recto profile master-pubkey: no master is bootstrapped at "
            "this state directory.",
            file=err,
        )
        return 1
    print(pubkey, file=out)
    return 0


def _cmd_profile_create(args, *, out, err):
    """Mint a new profile under the master.

    Phase 2.0.B integration. The code-heavy CLI surface: POSTs to the
    bootloader's ``/v0.4/profile/create`` endpoint with a caller-
    authored ``candidate_profile_id`` (Milan commitment A — same key
    used for queue lookup, idempotency check, persist key, audit
    trail), polls ``/v0.4/profile/result/<request_id>`` on a fixed
    cadence until the operator approves/denies on the phone, and
    renders the resulting Profile (read fresh from
    ``master_identity.json`` after approval).

    Three outcomes:
      * **approved** — exit 0; profile_id printed + the full
        ``recto profile show`` body rendered for convenience.
      * **denied** / **signature_error** — exit 1; reason surfaced.
      * **timeout** (operator never tapped) — exit 1; recovery hint
        printed (re-run with the SAME ``--candidate-profile-id``
        OR wait for the request to expire and try fresh).

    Idempotency-key safety: if the bootloader recognizes the
    ``candidate_profile_id`` and a Profile already exists under it
    (caller restarted mid-poll, network glitched, etc.), the
    bootloader returns HTTP 200 + ``status=already_exists``; the CLI
    exits 0 with the existing profile_id rendered.
    """
    import os
    import time
    import urllib.error
    import urllib.request
    import uuid
    from pathlib import Path

    # Resolve network + auth knobs from flags / env vars.
    bootloader_url = (
        args.bootloader_url
        or os.environ.get("RECTO_BOOTLOADER_URL")
        or "http://127.0.0.1:8765"
    ).rstrip("/")
    phone_id = args.phone_id or os.environ.get("RECTO_PHONE_ID")
    agent_id = args.agent_id or os.environ.get("RECTO_AGENT_ID")
    agent_token = args.agent_token or os.environ.get("RECTO_AGENT_TOKEN")

    missing: list[str] = []
    if not phone_id:
        missing.append("--phone-id (or RECTO_PHONE_ID env var)")
    if not agent_id:
        missing.append("--agent-id (or RECTO_AGENT_ID env var)")
    if not agent_token:
        missing.append("--agent-token (or RECTO_AGENT_TOKEN env var)")
    if missing:
        print(
            "recto profile create: missing required arg(s): "
            + ", ".join(missing),
            file=err,
        )
        return 2

    # ttl_seconds bounds check mirrors the bootloader's validation
    # (60..86400). Catching client-side gives a clearer error.
    if not (60 <= args.ttl_seconds <= 86400):
        print(
            "recto profile create: --ttl-seconds must be in [60, 86400] "
            "(1 minute - 24 hours)",
            file=err,
        )
        return 2

    if args.poll_timeout <= 0 or args.poll_interval <= 0:
        print(
            "recto profile create: --poll-timeout and --poll-interval "
            "must be positive",
            file=err,
        )
        return 2

    # Default display name from kind if --name not supplied.
    display_name = args.name or _default_display_name_for_kind(args.kind)
    candidate_profile_id = args.candidate_profile_id or str(uuid.uuid4())

    body: dict = {
        "phone_id": phone_id,
        "candidate_profile_id": candidate_profile_id,
        "kind": args.kind,
        "display_name": display_name,
        "ttl_seconds": args.ttl_seconds,
    }
    if args.theme is not None:
        body["theme_hint"] = args.theme
    if args.scim_provider is not None:
        body["scim_provider"] = args.scim_provider

    create_url = f"{bootloader_url}/v0.4/profile/create"
    try:
        post_resp = _profile_http_post_json(
            create_url,
            body,
            headers={
                "X-Recto-Agent-Id": agent_id,
                "X-Recto-Agent-Token": agent_token,
            },
        )
    except urllib.error.HTTPError as exc:
        return _render_profile_create_http_error(exc, out=out, err=err,
                                                  json_mode=args.json)
    except urllib.error.URLError as exc:
        print(
            f"recto profile create: could not reach bootloader at "
            f"{create_url}: {exc.reason}",
            file=err,
        )
        return 1

    status_code = post_resp["_status"]
    payload = post_resp["_body"]

    # Idempotent already_exists hit (HTTP 200) — render the existing
    # profile and exit 0.
    if status_code == 200 and payload.get("status") == "already_exists":
        existing_id = payload.get("profile_id")
        if args.json:
            print(
                _jsondump({
                    "status": "already_exists",
                    "profile_id": existing_id,
                    "candidate_profile_id": candidate_profile_id,
                    "reason": payload.get("reason"),
                }),
                file=out,
            )
        else:
            print(
                f"recto profile create: candidate_profile_id "
                f"{candidate_profile_id!r} already corresponds to "
                f"profile {existing_id} (idempotent hit; nothing "
                f"new queued).",
                file=out,
            )
        return 0

    # Expected: HTTP 201 + request_id + result_url
    if status_code != 201:
        print(
            f"recto profile create: unexpected status {status_code} "
            f"from bootloader: {payload}",
            file=err,
        )
        return 1

    request_id = payload.get("request_id")
    result_url_path = payload.get("result_url", f"/v0.4/profile/result/{request_id}")
    expires_at_unix = payload.get("expires_at_unix")
    if not request_id:
        print(
            f"recto profile create: bootloader returned malformed 201 "
            f"(no request_id): {payload}",
            file=err,
        )
        return 1

    if not args.json:
        print(
            f"recto profile create: queued (request_id={request_id}, "
            f"candidate_profile_id={candidate_profile_id}); "
            f"polling for operator approval on phone_id "
            f"{phone_id}...",
            file=out,
        )

    # Poll loop. The bootloader's GET /v0.4/profile/result/<id> returns
    # 200 + status="pending" while in-flight, 200 + status="approved"
    # / "denied" / "signature_error" once resolved, or 404 if the
    # request has expired or never existed.
    result_url = f"{bootloader_url}{result_url_path}"
    deadline = time.monotonic() + args.poll_timeout
    last_status: str | None = None
    while True:
        try:
            poll_resp = _profile_http_get_json(
                result_url,
                headers={
                    "X-Recto-Agent-Id": agent_id,
                    "X-Recto-Agent-Token": agent_token,
                },
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                print(
                    f"recto profile create: request {request_id} "
                    f"returned 404 (expired or unknown). Re-run with "
                    f"--candidate-profile-id {candidate_profile_id} "
                    f"to retry safely.",
                    file=err,
                )
                return 1
            return _render_profile_create_http_error(exc, out=out, err=err,
                                                      json_mode=args.json)
        except urllib.error.URLError as exc:
            print(
                f"recto profile create: lost contact with bootloader "
                f"mid-poll: {exc.reason}",
                file=err,
            )
            return 1

        payload = poll_resp["_body"]
        status = payload.get("status")
        if status != last_status and status == "pending" and not args.json:
            # Print the "still waiting" line once on first transition
            # to pending. Subsequent ticks stay silent to avoid noise.
            print("  ... operator has not responded yet ...", file=out)
        last_status = status

        if status == "approved":
            new_profile_id = payload.get("profile_id")
            return _render_profile_create_approved(
                args,
                profile_id=new_profile_id,
                candidate_profile_id=candidate_profile_id,
                out=out,
                err=err,
            )
        if status in ("denied", "signature_error"):
            reason = payload.get("reason") or "(no reason supplied)"
            if args.json:
                print(
                    _jsondump({
                        "status": status,
                        "request_id": request_id,
                        "candidate_profile_id": candidate_profile_id,
                        "reason": reason,
                    }),
                    file=out,
                )
            else:
                print(
                    f"recto profile create: {status}: {reason}",
                    file=err,
                )
                if status == "signature_error" and reason.startswith("persist_error:"):
                    print(
                        "  ^ disk-write failed AFTER phone signed; "
                        "fix host state and retry with the SAME "
                        f"--candidate-profile-id {candidate_profile_id}",
                        file=err,
                    )
            return 1

        if status != "pending":
            print(
                f"recto profile create: unexpected status {status!r} "
                f"from bootloader: {payload}",
                file=err,
            )
            return 1

        if time.monotonic() >= deadline:
            print(
                f"recto profile create: polled for {args.poll_timeout}s "
                f"without operator action. Approval card is still on "
                f"the phone; re-poll with --candidate-profile-id "
                f"{candidate_profile_id} or wait for the request to "
                f"expire (expires_at_unix={expires_at_unix}).",
                file=err,
            )
            return 1
        time.sleep(args.poll_interval)


def _cmd_profile_add_device(args, *, out, err):
    """Append a paired phone to a profile's device_ids tuple.

    Phase 2.0.C wave C.5.c — operator-master-attested via the
    phone enclave. The code-heavy CLI surface: POSTs to the
    bootloader's ``/v0.4/profile/<profile_id>/add-device`` endpoint,
    polls ``/v0.4/profile/add-device-result/<request_id>`` on a
    fixed cadence until the operator approves/denies on the phone,
    and renders the result.

    Four outcomes:
      * **approved** — exit 0; profile_id + new_phone_id printed.
        The new phone is now in the profile's device_ids tuple
        (verified by reading from master_identity.json after
        approval, per Milan commitment B).
      * **already_member** — exit 0; idempotent hit at the endpoint
        pre-flight (new_phone_id was already in device_ids). No
        phone prompt fired.
      * **denied** / **signature_error** — exit 1; reason surfaced.
        signature_error with reason prefix ``persist_error:``
        indicates the operator approved but disk-write failed; fix
        the host state and retry safely (the same profile_id +
        new_phone_id is idempotent).
      * **timeout** (operator never tapped) — exit 1; recovery hint
        printed (the approval card stays on the phone until
        expires_at_unix; retry is safe).
    """
    import os
    import time
    import urllib.error
    import urllib.request
    from pathlib import Path

    bootloader_url = (
        args.bootloader_url
        or os.environ.get("RECTO_BOOTLOADER_URL")
        or "http://127.0.0.1:8765"
    ).rstrip("/")
    master_phone_id = args.master_phone_id or os.environ.get("RECTO_PHONE_ID")
    agent_id = args.agent_id or os.environ.get("RECTO_AGENT_ID")
    agent_token = args.agent_token or os.environ.get("RECTO_AGENT_TOKEN")

    missing: list[str] = []
    if not master_phone_id:
        missing.append("--master-phone-id (or RECTO_PHONE_ID env var)")
    if not agent_id:
        missing.append("--agent-id (or RECTO_AGENT_ID env var)")
    if not agent_token:
        missing.append("--agent-token (or RECTO_AGENT_TOKEN env var)")
    if missing:
        print(
            "recto profile add-device: missing required arg(s): "
            + ", ".join(missing),
            file=err,
        )
        return 2

    if not (60 <= args.ttl_seconds <= 86400):
        print(
            "recto profile add-device: --ttl-seconds must be in "
            "[60, 86400] (1 minute - 24 hours)",
            file=err,
        )
        return 2

    if args.poll_timeout <= 0 or args.poll_interval <= 0:
        print(
            "recto profile add-device: --poll-timeout and --poll-interval "
            "must be positive",
            file=err,
        )
        return 2

    body: dict = {
        "master_phone_id": master_phone_id,
        "new_phone_id": args.new_phone_id,
        "ttl_seconds": args.ttl_seconds,
    }
    if args.new_phone_label is not None:
        body["new_phone_label"] = args.new_phone_label

    add_url = f"{bootloader_url}/v0.4/profile/{args.profile_id}/add-device"
    try:
        post_resp = _profile_http_post_json(
            add_url,
            body,
            headers={
                "X-Recto-Agent-Id": agent_id,
                "X-Recto-Agent-Token": agent_token,
            },
        )
    except urllib.error.HTTPError as exc:
        return _render_profile_create_http_error(
            exc, out=out, err=err, json_mode=args.json
        )
    except urllib.error.URLError as exc:
        print(
            f"recto profile add-device: could not reach bootloader at "
            f"{add_url}: {exc.reason}",
            file=err,
        )
        return 1

    status_code = post_resp["_status"]
    payload = post_resp["_body"]

    # Idempotent already_member hit (HTTP 200) — exit 0.
    if status_code == 200 and payload.get("status") == "already_member":
        if args.json:
            print(
                _jsondump({
                    "status": "already_member",
                    "profile_id": payload.get("profile_id"),
                    "new_phone_id": payload.get("new_phone_id"),
                    "reason": payload.get("reason"),
                }),
                file=out,
            )
        else:
            print(
                f"recto profile add-device: new_phone_id "
                f"{args.new_phone_id!r} is already in profile "
                f"{args.profile_id!r}'s device_ids (idempotent hit; "
                f"nothing new queued).",
                file=out,
            )
        return 0

    # Expected: HTTP 201 + request_id + result_url
    if status_code != 201:
        print(
            f"recto profile add-device: unexpected status "
            f"{status_code} from bootloader: {payload}",
            file=err,
        )
        return 1

    request_id = payload.get("request_id")
    result_url_path = payload.get(
        "result_url",
        f"/v0.4/profile/add-device-result/{request_id}",
    )
    expires_at_unix = payload.get("expires_at_unix")
    if not request_id:
        print(
            f"recto profile add-device: bootloader returned malformed "
            f"201 (no request_id): {payload}",
            file=err,
        )
        return 1

    if not args.json:
        print(
            f"recto profile add-device: queued (request_id="
            f"{request_id}); polling for operator approval on "
            f"master_phone_id {master_phone_id}...",
            file=out,
        )

    # Poll loop. The bootloader's GET /v0.4/profile/add-device-result/<id>
    # returns 200 + status="pending" while in-flight, 200 + status=
    # approved/already_member/denied/signature_error once resolved, or
    # 404 if the request has expired or never existed.
    result_url = f"{bootloader_url}{result_url_path}"
    deadline = time.monotonic() + args.poll_timeout
    last_status: str | None = None
    while True:
        try:
            poll_resp = _profile_http_get_json(
                result_url,
                headers={
                    "X-Recto-Agent-Id": agent_id,
                    "X-Recto-Agent-Token": agent_token,
                },
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                print(
                    f"recto profile add-device: request {request_id} "
                    f"returned 404 (expired or unknown). The same "
                    f"(profile_id, new_phone_id) tuple is idempotent; "
                    f"retry is safe.",
                    file=err,
                )
                return 1
            return _render_profile_create_http_error(
                exc, out=out, err=err, json_mode=args.json
            )
        except urllib.error.URLError as exc:
            print(
                f"recto profile add-device: lost contact with bootloader "
                f"mid-poll: {exc.reason}",
                file=err,
            )
            return 1

        payload = poll_resp["_body"]
        status = payload.get("status")
        if status != last_status and status == "pending" and not args.json:
            print("  ... operator has not responded yet ...", file=out)
        last_status = status

        if status == "approved":
            return _render_profile_add_device_approved(
                args,
                profile_id=payload.get("profile_id") or args.profile_id,
                new_phone_id=payload.get("new_phone_id") or args.new_phone_id,
                out=out,
                err=err,
            )
        if status == "already_member":
            # Rare — would normally have been caught at endpoint
            # pre-flight, but the respond-handler reasserts as
            # defense-in-depth.
            if args.json:
                print(
                    _jsondump({
                        "status": "already_member",
                        "profile_id": payload.get("profile_id"),
                        "new_phone_id": payload.get("new_phone_id"),
                        "reason": payload.get("reason"),
                    }),
                    file=out,
                )
            else:
                print(
                    f"recto profile add-device: already_member "
                    f"(operator approval was unnecessary; new_phone_id "
                    f"was already in device_ids).",
                    file=out,
                )
            return 0
        if status in ("denied", "signature_error"):
            reason = payload.get("reason") or "(no reason supplied)"
            if args.json:
                print(
                    _jsondump({
                        "status": status,
                        "request_id": request_id,
                        "profile_id": args.profile_id,
                        "new_phone_id": args.new_phone_id,
                        "reason": reason,
                    }),
                    file=out,
                )
            else:
                print(
                    f"recto profile add-device: {status}: {reason}",
                    file=err,
                )
                if status == "signature_error" and reason.startswith(
                    "persist_error:"
                ):
                    print(
                        "  ^ disk-write failed AFTER phone signed; "
                        "fix host state and retry safely (same "
                        "(profile_id, new_phone_id) tuple is "
                        "idempotent).",
                        file=err,
                    )
            return 1

        if status != "pending":
            print(
                f"recto profile add-device: unexpected status "
                f"{status!r} from bootloader: {payload}",
                file=err,
            )
            return 1

        if time.monotonic() >= deadline:
            print(
                f"recto profile add-device: polled for "
                f"{args.poll_timeout}s without operator action. "
                f"Approval card is still on the phone (expires_at_unix="
                f"{expires_at_unix}); retry with the same "
                f"(profile_id, new_phone_id) is idempotent.",
                file=err,
            )
            return 1
        time.sleep(args.poll_interval)


def _render_profile_add_device_approved(
    args, *, profile_id, new_phone_id, out, err
):
    """Approval lander for add-device — verify the new phone is now in
    the profile's device_ids tuple by reading master_identity.json
    fresh (Milan commitment B: persist is source of truth).
    """
    from pathlib import Path

    from recto.profile.manage import get_profile_by_id

    state_dir = Path(args.state_dir) if args.state_dir else None
    profile = (
        get_profile_by_id(profile_id, state_dir=state_dir)
        if profile_id is not None
        else None
    )

    if args.json:
        out_obj: dict = {
            "status": "approved",
            "profile_id": profile_id,
            "new_phone_id": new_phone_id,
        }
        if profile is not None:
            out_obj["device_ids"] = list(profile.device_ids)
        print(_jsondump(out_obj), file=out)
        return 0

    print(
        f"recto profile add-device: approved (profile_id={profile_id}, "
        f"new_phone_id={new_phone_id}).",
        file=out,
    )
    if profile is not None:
        device_count = len(profile.device_ids)
        print(
            f"  Profile '{profile.display_name}' "
            f"(kind={profile.kind}) now has {device_count} device(s): "
            f"{', '.join(profile.device_ids)}",
            file=out,
        )
    return 0


def _cmd_profile_revoke_device(args, *, out, err):
    """Remove a paired phone from a profile's device_ids tuple.

    Phase 2.0.C wave C.6.c — operator-master-attested via the
    phone enclave. Sister of _cmd_profile_add_device but for the
    inverse mutation. POSTs to the bootloader's
    /v0.4/profile/<profile_id>/revoke-device endpoint, polls
    /v0.4/profile/revoke-device-result/<request_id> on a fixed
    cadence, renders the result.

    Outcomes:
      * approved — exit 0; profile_id + phone_id_revoked printed.
      * already_not_member — exit 0; idempotent hit at endpoint
        pre-flight (phone_id_to_revoke wasn't in device_ids).
      * denied / signature_error — exit 1; reason surfaced.
        persist_error: prefix indicates approve-then-disk-failed;
        retry safe with same (profile_id, phone_id_to_revoke).
      * quorum_not_yet_implemented (400 at POST time) — exit 1;
        profile's revoke_quorum_k >= 2, v1 doesn't support K-of-N
        aggregation yet. Banked for v1.1.
      * last_device_guard (400 at POST time) — exit 1; cannot
        revoke the only device on a profile (would brick it).
      * timeout — exit 1; idempotent-retry hint printed.
    """
    import os
    import time
    import urllib.error
    import urllib.request
    from pathlib import Path

    bootloader_url = (
        args.bootloader_url
        or os.environ.get("RECTO_BOOTLOADER_URL")
        or "http://127.0.0.1:8765"
    ).rstrip("/")
    master_phone_id = args.master_phone_id or os.environ.get("RECTO_PHONE_ID")
    agent_id = args.agent_id or os.environ.get("RECTO_AGENT_ID")
    agent_token = args.agent_token or os.environ.get("RECTO_AGENT_TOKEN")

    missing: list[str] = []
    if not master_phone_id:
        missing.append("--master-phone-id (or RECTO_PHONE_ID env var)")
    if not agent_id:
        missing.append("--agent-id (or RECTO_AGENT_ID env var)")
    if not agent_token:
        missing.append("--agent-token (or RECTO_AGENT_TOKEN env var)")
    if missing:
        print(
            "recto profile revoke-device: missing required arg(s): "
            + ", ".join(missing),
            file=err,
        )
        return 2

    if not (60 <= args.ttl_seconds <= 86400):
        print(
            "recto profile revoke-device: --ttl-seconds must be in "
            "[60, 86400]",
            file=err,
        )
        return 2

    if args.poll_timeout <= 0 or args.poll_interval <= 0:
        print(
            "recto profile revoke-device: --poll-timeout and "
            "--poll-interval must be positive",
            file=err,
        )
        return 2

    body: dict = {
        "master_phone_id": master_phone_id,
        "phone_id_to_revoke": args.phone_id_to_revoke,
        "ttl_seconds": args.ttl_seconds,
    }
    if args.revoker_label is not None:
        body["revoker_label"] = args.revoker_label

    rev_url = f"{bootloader_url}/v0.4/profile/{args.profile_id}/revoke-device"
    try:
        post_resp = _profile_http_post_json(
            rev_url,
            body,
            headers={
                "X-Recto-Agent-Id": agent_id,
                "X-Recto-Agent-Token": agent_token,
            },
        )
    except urllib.error.HTTPError as exc:
        return _render_profile_create_http_error(
            exc, out=out, err=err, json_mode=args.json
        )
    except urllib.error.URLError as exc:
        print(
            f"recto profile revoke-device: could not reach bootloader at "
            f"{rev_url}: {exc.reason}",
            file=err,
        )
        return 1

    status_code = post_resp["_status"]
    payload = post_resp["_body"]

    # Idempotent already_not_member hit
    if status_code == 200 and payload.get("status") == "already_not_member":
        if args.json:
            print(
                _jsondump({
                    "status": "already_not_member",
                    "profile_id": payload.get("profile_id"),
                    "phone_id_to_revoke": payload.get("phone_id_to_revoke"),
                    "reason": payload.get("reason"),
                }),
                file=out,
            )
        else:
            print(
                f"recto profile revoke-device: phone_id "
                f"{args.phone_id_to_revoke!r} is not in profile "
                f"{args.profile_id!r}'s device_ids (idempotent hit; "
                f"nothing new queued).",
                file=out,
            )
        return 0

    if status_code != 201:
        print(
            f"recto profile revoke-device: unexpected status "
            f"{status_code} from bootloader: {payload}",
            file=err,
        )
        return 1

    request_id = payload.get("request_id")
    result_url_path = payload.get(
        "result_url",
        f"/v0.4/profile/revoke-device-result/{request_id}",
    )
    expires_at_unix = payload.get("expires_at_unix")
    if not request_id:
        print(
            f"recto profile revoke-device: bootloader returned malformed "
            f"201 (no request_id): {payload}",
            file=err,
        )
        return 1

    if not args.json:
        print(
            f"recto profile revoke-device: queued (request_id="
            f"{request_id}); polling for operator approval on "
            f"master_phone_id {master_phone_id}...",
            file=out,
        )

    result_url = f"{bootloader_url}{result_url_path}"
    deadline = time.monotonic() + args.poll_timeout
    last_status: str | None = None
    while True:
        try:
            poll_resp = _profile_http_get_json(
                result_url,
                headers={
                    "X-Recto-Agent-Id": agent_id,
                    "X-Recto-Agent-Token": agent_token,
                },
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                print(
                    f"recto profile revoke-device: request {request_id} "
                    f"returned 404. Retry with the same (profile_id, "
                    f"phone_id_to_revoke) is idempotent.",
                    file=err,
                )
                return 1
            return _render_profile_create_http_error(
                exc, out=out, err=err, json_mode=args.json
            )
        except urllib.error.URLError as exc:
            print(
                f"recto profile revoke-device: lost contact with "
                f"bootloader mid-poll: {exc.reason}",
                file=err,
            )
            return 1

        payload = poll_resp["_body"]
        status = payload.get("status")
        if status != last_status and status == "pending" and not args.json:
            print("  ... operator has not responded yet ...", file=out)
        last_status = status

        if status == "approved":
            return _render_profile_revoke_device_approved(
                args,
                profile_id=payload.get("profile_id") or args.profile_id,
                phone_id_revoked=payload.get("phone_id_revoked") or args.phone_id_to_revoke,
                out=out,
                err=err,
            )
        if status == "already_not_member":
            if args.json:
                print(
                    _jsondump({
                        "status": "already_not_member",
                        "profile_id": payload.get("profile_id"),
                        "phone_id_revoked": payload.get("phone_id_revoked"),
                        "reason": payload.get("reason"),
                    }),
                    file=out,
                )
            else:
                print(
                    f"recto profile revoke-device: already_not_member "
                    f"(operator approval unnecessary; phone wasn't in "
                    f"device_ids).",
                    file=out,
                )
            return 0
        if status in ("denied", "signature_error"):
            reason = payload.get("reason") or "(no reason supplied)"
            if args.json:
                print(
                    _jsondump({
                        "status": status,
                        "request_id": request_id,
                        "profile_id": args.profile_id,
                        "phone_id_to_revoke": args.phone_id_to_revoke,
                        "reason": reason,
                    }),
                    file=out,
                )
            else:
                print(
                    f"recto profile revoke-device: {status}: {reason}",
                    file=err,
                )
                if status == "signature_error" and reason.startswith(
                    "persist_error:"
                ):
                    print(
                        "  ^ disk-write failed AFTER phone signed; "
                        "fix host state and retry safely (same "
                        "(profile_id, phone_id_to_revoke) is "
                        "idempotent).",
                        file=err,
                    )
            return 1

        if status != "pending":
            print(
                f"recto profile revoke-device: unexpected status "
                f"{status!r} from bootloader: {payload}",
                file=err,
            )
            return 1

        if time.monotonic() >= deadline:
            print(
                f"recto profile revoke-device: polled for "
                f"{args.poll_timeout}s without operator action. "
                f"Approval card is still on the phone (expires_at_unix="
                f"{expires_at_unix}); retry with the same "
                f"(profile_id, phone_id_to_revoke) is idempotent.",
                file=err,
            )
            return 1
        time.sleep(args.poll_interval)


def _render_profile_revoke_device_approved(
    args, *, profile_id, phone_id_revoked, out, err
):
    """Approval lander for revoke-device — verify the phone is no
    longer in the profile's device_ids tuple by reading
    master_identity.json fresh (Milan commitment B)."""
    from pathlib import Path

    from recto.profile.manage import get_profile_by_id

    state_dir = Path(args.state_dir) if args.state_dir else None
    profile = (
        get_profile_by_id(profile_id, state_dir=state_dir)
        if profile_id is not None
        else None
    )

    if args.json:
        out_obj: dict = {
            "status": "approved",
            "profile_id": profile_id,
            "phone_id_revoked": phone_id_revoked,
        }
        if profile is not None:
            out_obj["device_ids"] = list(profile.device_ids)
        print(_jsondump(out_obj), file=out)
        return 0

    print(
        f"recto profile revoke-device: approved (profile_id="
        f"{profile_id}, phone_id_revoked={phone_id_revoked}).",
        file=out,
    )
    if profile is not None:
        device_count = len(profile.device_ids)
        device_list = ", ".join(profile.device_ids) if profile.device_ids else "(none)"
        print(
            f"  Profile '{profile.display_name}' "
            f"(kind={profile.kind}) now has {device_count} device(s): "
            f"{device_list}",
            file=out,
        )
    return 0


def _render_profile_create_approved(args, *, profile_id, candidate_profile_id,
                                     out, err):
    """Approval lander — read the freshly-persisted profile + render it.

    Phase 2.0.B Milan commitment B: master_identity.json is the
    source of truth. We pull the row from there rather than from
    the result-store payload so the operator sees the canonical
    derivation index + creation timestamp the bootloader actually
    wrote, not a derived projection.
    """
    from pathlib import Path

    from recto.profile.manage import get_profile_by_id
    from recto.profile.store import load_master_identity

    state_dir = Path(args.state_dir) if args.state_dir else None
    mi = load_master_identity(state_dir=state_dir)
    profile = (
        get_profile_by_id(profile_id, state_dir=state_dir)
        if profile_id is not None
        else None
    )

    if args.json:
        body: dict = {
            "status": "approved",
            "profile_id": profile_id,
            "candidate_profile_id": candidate_profile_id,
        }
        if profile is not None and mi is not None:
            body["profile"] = _profile_to_json_row(
                profile, master_id=mi.master_profile_id
            )
            body["master_pubkey_hex"] = mi.master_pubkey_hex
        print(_jsondump(body), file=out)
        return 0

    print(
        f"recto profile create: approved. profile_id={profile_id}",
        file=out,
    )
    if profile is None:
        # Approved per the result-store but disk read came back empty —
        # unusual (would indicate a race or test isolation issue).
        # Surface as a partial-success warning.
        print(
            f"  warning: profile_id {profile_id} reported approved "
            f"but is not yet visible in master_identity.json at "
            f"{args.state_dir or '(default state-dir)'}. Retry "
            f"`recto profile show {profile_id}` in a moment.",
            file=err,
        )
        return 0
    print(f"  kind: {profile.kind}", file=out)
    print(f"  display_name: {profile.display_name!r}", file=out)
    print(f"  derivation: {profile.derivation.as_bip32_string()}", file=out)
    print(f"  theme_hint: {profile.theme_hint}", file=out)
    print(f"  scim_provider: {profile.scim_provider}", file=out)
    print(f"  created_at_unix: {profile.created_at_unix}", file=out)
    return 0


# ---------------------------------------------------------------------------
# Profile-CLI helpers
# ---------------------------------------------------------------------------


def _default_display_name_for_kind(kind: str) -> str:
    """Pick a sensible default display name when --name is omitted.

    Canonical kinds get title-cased labels; custom strings get
    returned as-is (operators picking custom kinds are presumably
    aware enough to also pass --name).
    """
    canonical = {
        "personal:master": "Personal (master)",
        "personal:child": "Personal (pseudonym)",
        "work": "Work",
        "school": "School",
        "contractor": "Contractor",
    }
    return canonical.get(kind, kind)


def _profile_to_json_row(profile, *, master_id: str) -> dict:
    """Project a Profile dataclass into a JSON-friendly dict.

    Used by --json output paths so callers (scripts, CI) get a stable
    machine-readable shape that's independent of the human-friendly
    text renderer.
    """
    return {
        "profile_id": profile.profile_id,
        "kind": profile.kind,
        "display_name": profile.display_name,
        "is_master": profile.profile_id == master_id,
        "derivation": {
            "purpose": profile.derivation.purpose,
            "profile_coin_type": profile.derivation.profile_coin_type,
            "profile_index": profile.derivation.profile_index,
            "bip32": profile.derivation.as_bip32_string(),
        },
        "parent_profile_id": profile.parent_profile_id,
        "theme_hint": profile.theme_hint,
        "scim_provider": profile.scim_provider,
        "deny_actions_inherited": list(profile.deny_actions_inherited),
        "created_at_unix": profile.created_at_unix,
        "revoked": profile.revoked,
    }


def _jsondump(obj) -> str:
    """One-line JSON for CLI output. Sorted keys for determinism."""
    import json as _json

    return _json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _profile_http_post_json(url: str, body: dict, *, headers: dict) -> dict:
    """POST JSON to a Recto bootloader endpoint, parse JSON response.

    Returns ``{"_status": int, "_body": dict}``. Raises
    ``urllib.error.HTTPError`` on >=400 responses (caller decides
    whether to render or re-raise); raises ``urllib.error.URLError``
    on connection failures.

    Stdlib-only — same shape as the rest of the recto package (no
    `requests` dependency).
    """
    import json as _json
    import urllib.request

    payload_bytes = _json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload_bytes,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            **headers,
        },
    )
    with urllib.request.urlopen(req) as resp:  # noqa: S310 (operator-local URL)
        raw = resp.read()
        parsed = _json.loads(raw) if raw else {}
        return {"_status": resp.status, "_body": parsed}


def _profile_http_get_json(url: str, *, headers: dict) -> dict:
    """GET a Recto bootloader endpoint, parse JSON response."""
    import json as _json
    import urllib.request

    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", **headers},
    )
    with urllib.request.urlopen(req) as resp:  # noqa: S310 (operator-local URL)
        raw = resp.read()
        parsed = _json.loads(raw) if raw else {}
        return {"_status": resp.status, "_body": parsed}


def _render_profile_create_http_error(exc, *, out, err, json_mode: bool) -> int:
    """Pretty-print a non-2xx HTTP error from the bootloader.

    The bootloader emits JSON error bodies with ``{"error": "...",
    "detail": "..."}`` shape on auth/validation failures; we surface
    that verbatim so operators can diagnose without a debugger.
    """
    import json as _json

    try:
        body = exc.read()
        parsed = _json.loads(body) if body else {}
    except Exception:
        parsed = {}
    if json_mode:
        print(
            _jsondump({
                "status": "http_error",
                "http_status": exc.code,
                "error": parsed,
            }),
            file=out,
        )
    else:
        print(
            f"recto profile create: HTTP {exc.code} from bootloader: "
            f"{parsed or exc.reason}",
            file=err,
        )
    return 1


def _cmd_profile_v2_placeholder(args, *, out, err):
    """v1.x placeholder for the v2.0 multi-profile identity surface.

    Every `recto profile <subcommand>` invocation in v1.x prints a
    "v2.0 — coming soon" notice + pointers to the architectural-
    decision-record (ARCHITECTURE.md) and the spec (recto/profile/
    SPEC.md). The wire-protocol types DO ship in v1.x at
    `recto.profile.types` so downstream consumers can write v2.0-
    aware code paths today; this CLI surface is the operator-facing
    foothold that activates when v2.0's runtime ships.

    Returns 0 (informational); operator scripts that grep for
    'coming soon' as a marker can rely on the literal string.
    """
    sub = getattr(args, "profile_command", None) or "<unspecified>"
    print(f"recto profile {sub}: v2.0 — coming soon.", file=out)
    print("", file=out)
    print("v1.x ships the type contracts only (see recto/profile/types.py).", file=out)
    print("The runtime — BIP-32 master-to-profile derivation, the", file=out)
    print("profile_create / profile_add_device / profile_revoke_device", file=out)
    print("PendingRequest handlers, the capability-JWS parent_profile", file=out)
    print("extension, the SCIM provisioning surface, the phone-side", file=out)
    print("profile picker — ships in v2.0.", file=out)
    print("", file=out)
    print("Design rationale + threat model + trust hierarchy:", file=out)
    print("  ARCHITECTURE.md → 'Multi-profile identity:", file=out)
    print("    personal-as-master-key hierarchy (DESIGN BANKED)'", file=out)
    print("", file=out)
    print("Implementation-facing wire-protocol + CLI + UX contracts:", file=out)
    print("  recto/profile/SPEC.md", file=out)
    print("", file=out)
    print("Downstream consumers can import recto.profile.types today", file=out)
    print("and write conditional code paths that activate when v2.0", file=out)
    print("lands — the type names + field shapes are the binding", file=out)
    print("contract.", file=out)
    return 0


def _cmd_status(args, *, nssm, out, err):
    service = args.service
    try:
        status = nssm.status(service)
    except NssmNotInstalledError as exc:
        print(f"recto status: {exc}", file=err)
        return 1
    except NssmError as exc:
        print(f"recto status: {exc}", file=err)
        return 1
    print(status, file=out)
    return 0 if status == NssmStatus.SERVICE_RUNNING else 1


def _cmd_migrate_from_nssm(args, *, nssm, cred, out, err):
    service = args.service
    yaml_out_path = Path(args.yaml_out if args.yaml_out else f"{service}.service.yaml")
    python_exe = args.python_exe
    dry_run = bool(args.dry_run)
    backend_name = getattr(args, "secret_backend", "credman")
    try:
        nssm_cfg = nssm.get_all(service)
    except NssmServiceNotFoundError:
        print(f"recto migrate-from-nssm: NSSM service {service!r} not found", file=err)
        return 1
    except NssmNotInstalledError as exc:
        print(f"recto migrate-from-nssm: {exc}", file=err)
        return 1
    except NssmError as exc:
        print(f"recto migrate-from-nssm: {exc}", file=err)
        return 1
    # Pre-flight check: when the backend is per-user (credman), the
    # migrating user MUST match the NSSM service's ObjectName, otherwise
    # the service will read ERROR_NOT_FOUND at start time. Detect at
    # apply time so the operator gets a clear remediation message
    # before any side effects.
    if backend_name == "credman" and not dry_run:
        mismatch = _detect_user_objectname_mismatch(nssm, service)
        if mismatch is not None:
            current_user, object_name = mismatch
            print(
                f"recto migrate-from-nssm: refusing to apply with "
                f"--secret-backend=credman.\n"
                f"\n"
                f"  Current user: {current_user}\n"
                f"  NSSM ObjectName: {object_name}\n"
                f"\n"
                f"Windows Credential Manager is per-user; secrets written "
                f"by the current user are NOT visible to processes running "
                f"under a different account (the service will fail with "
                f"ERROR_NOT_FOUND on first start).\n"
                f"\n"
                f"Recommended fix:\n"
                f"  Re-run with --secret-backend=dpapi-machine. The new\n"
                f"  backend uses CryptProtectData with\n"
                f"  CRYPTPROTECT_LOCAL_MACHINE so any process on this\n"
                f"  machine can decrypt regardless of user account.\n"
                f"\n"
                f"Alternatives:\n"
                f"  - Re-run as the service account via\n"
                f"    `schtasks /create /sc once /ru SYSTEM /tr \"...\"`\n"
                f"    so the migrator writes secrets in the service\n"
                f"    account's CredMan store.\n"
                f"  - Change the service's NSSM ObjectName to a user account.\n",
                file=err,
            )
            return 1
    all_entries = list(split_environment_extra("\n".join(nssm_cfg.app_environment_extra)))
    keep_as_env = (
        [k.strip() for k in args.keep_as_env.split(",") if k.strip()]
        if args.keep_as_env else []
    )
    # Warn on any --keep-as-env entry not present in the source env.
    # Without this warning the silent skip leaves operators chasing a
    # phantom "expected N entries, got N-1" mismatch downstream. The
    # partition still proceeds with whatever names DO match. Caught
    # during second-consumer migration 2026-04-26.
    if keep_as_env:
        source_keys = {k for k, _ in all_entries}
        for name in keep_as_env:
            if name not in source_keys:
                print(
                    f"recto migrate-from-nssm: warning: --keep-as-env entry "
                    f"{name!r} not found in source AppEnvironmentExtra "
                    f"(skipping)",
                    file=err,
                )
    secrets, plain_env = partition_env_entries(all_entries, keep_as_env=keep_as_env)
    plan = build_migration_plan(
        nssm_cfg=nssm_cfg, secrets=secrets, yaml_out=yaml_out_path,
        python_exe=python_exe, plain_env=plain_env,
    )
    plan["secret_backend"] = backend_name
    print(json.dumps(plan, indent=2, default=str), file=out)
    if dry_run:
        print("recto migrate-from-nssm: --dry-run; no changes made", file=out)
        return 0
    try:
        for key, value in secrets:
            cred.write(key, value, comment=f"Migrated from NSSM:{service}")
        yaml_text = generate_service_yaml(
            service=service, nssm_cfg=nssm_cfg,
            secret_keys=[k for k, _ in secrets], plain_env=plain_env,
            secret_backend=backend_name,
        )
        yaml_out_path.write_text(yaml_text, encoding="utf-8")
        nssm.set(service, "Application", python_exe)
        nssm.set(service, "AppParameters", f"-m recto launch {yaml_out_path}")
        nssm.reset(service, "AppEnvironmentExtra")
    except (SecretSourceError, NssmError, OSError) as exc:
        print(f"recto migrate-from-nssm: apply failed: {exc}", file=err)
        return 1
    print(
        f"recto migrate-from-nssm: migrated {service!r}; yaml at {yaml_out_path}; "
        f"installed {len(secrets)} secret(s); NSSM AppEnvironmentExtra cleared.",
        file=out,
    )
    return 0


def _cmd_apply(args, *, nssm, confirm, out, err):
    yaml_path = Path(args.yaml_path).resolve()
    try:
        cfg: ServiceConfig = load_config(yaml_path)
    except ConfigValidationError as exc:
        print(f"recto apply: invalid config: {exc}", file=err)
        return 1
    except FileNotFoundError:
        print(f"recto apply: file not found: {yaml_path}", file=err)
        return 1
    service = cfg.metadata.name
    try:
        current = nssm.get_all(service)
    except NssmServiceNotFoundError:
        print(
            f"recto apply: NSSM service {service!r} not found. "
            f"Either register it first via `nssm install {service}`, "
            f"or use `recto migrate-from-nssm <service>` if you're "
            f"migrating an existing non-Recto service.",
            file=err,
        )
        return 1
    except NssmNotInstalledError as exc:
        print(f"recto apply: {exc}", file=err)
        return 1
    except NssmError as exc:
        print(f"recto apply: {exc}", file=err)
        return 1
    # Papercut #1 resolution: when --python-exe wasn't passed
    # explicitly (args.python_exe is None), preserve NSSM's existing
    # Application value rather than proposing a change to bare
    # 'python.exe'. The pre-fix default silently overwrote a fully-
    # qualified C:\Python314\python.exe to a bare name, breaking
    # service-account contexts whose PATH didn't resolve correctly.
    # Fall back to "python.exe" only if NSSM has nothing on file
    # (a freshly `nssm install`ed service that's never been started).
    if args.python_exe is not None:
        resolved_python_exe = args.python_exe
    elif current.app_path:
        resolved_python_exe = current.app_path
    else:
        resolved_python_exe = "python.exe"
    plan: ReconcilePlan = compute_plan(
        cfg, current, yaml_path=yaml_path, python_exe=resolved_python_exe
    )
    print(render_plan(plan), file=out)
    if plan.is_noop:
        return 0
    if args.dry_run:
        print("recto apply: --dry-run; no changes made", file=out)
        return 0
    if not args.yes:
        try:
            answer = confirm("Apply these changes? (y/N): ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("recto apply: aborted (no changes made)", file=out)
            return 0
    try:
        apply_plan(plan, nssm)
    except NssmError as exc:
        print(f"recto apply: apply failed: {exc}", file=err)
        return 1
    summary = f"recto apply: applied {len(plan.changes)} change(s)"
    if plan.clear_environment_extra:
        summary += " + cleared AppEnvironmentExtra"
    summary += "."
    print(summary, file=out)
    return 0


def _cmd_events(args, *, out, err, fetch_url=None):
    """Handle ``recto events <yaml> [--kind K] [--limit N] [--restart-history]``."""
    yaml_path = Path(args.yaml_path)
    try:
        cfg: ServiceConfig = load_config(yaml_path)
    except ConfigValidationError as exc:
        print(f"recto events: invalid config: {exc}", file=err)
        return 1
    except FileNotFoundError:
        print(f"recto events: file not found: {yaml_path}", file=err)
        return 1
    if not cfg.spec.admin_ui.enabled:
        print(
            "recto events: spec.admin_ui.enabled is false in this YAML "
            "-- the launcher isn't running an admin UI to query. "
            "Check NSSM's AppStdout log file for the JSON event stream.",
            file=err,
        )
        return 1
    bind = cfg.spec.admin_ui.bind or "127.0.0.1:5050"
    endpoint = "restart-history" if args.restart_history else "events"
    url = f"http://{bind}/api/{endpoint}?limit={int(args.limit)}"
    if args.kind:
        from urllib.parse import quote
        for k in args.kind.split(","):
            k = k.strip()
            if k:
                url += f"&kind={quote(k)}"
    if fetch_url is None:
        fetch_url = _default_fetch_url
    try:
        body = fetch_url(url, 5.0)
    except Exception as exc:  # noqa: BLE001
        print(
            f"recto events: failed to reach the admin UI at {bind} "
            f"({type(exc).__name__}: {exc}). Is the service running? "
            f"Check `nssm status <service>` or the launcher's AppStdout log.",
            file=err,
        )
        return 1
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("utf-8", errors="replace")
    print(text, file=out)
    return 0


def _default_fetch_url(url: str, timeout: float) -> bytes:
    """stdlib urllib GET. Returns the raw response body bytes."""
    import urllib.request
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return bytes(resp.read())


def _version_string() -> str:
    """Build the --version output string."""
    from recto import __version__
    return f"recto {__version__}"
