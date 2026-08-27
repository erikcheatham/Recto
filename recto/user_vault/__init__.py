"""
Recto User Vault Substrate — per-USER secret storage ("bring your own
key"), generic across whatever consuming platform Recto is installed
alongside of.

The Connections Substrate (`recto.connections`) holds PLATFORM-tier
credentials: one namespace per consuming service, operator-managed. The
User Vault is its USER-tier sister: each end user of a consuming platform
owns a private namespace of provider API keys, written and released at
runtime by the platform on that user's behalf. The consuming platform's
own store interface (e.g. an `IUserVaultStore` seam) fronts this HTTP
surface so user keys survive the platform's deploys — durable at the
substrate, ephemeral nowhere.

Architecture (deliberate mirrors + deliberate divergences from connections):
  * SECRET VALUES live in the same at-rest backends as connections: the
    dpapi-machine vault on a Windows host
    (`C:\\ProgramData\\recto\\<platform>\\uv.<user_id>.<key>.dpapi`) or the
    file-backed store inside a container volume — selected through the
    same injectable `SecretSourceFactory` seam. The `uv.` prefix keeps
    user entries disjoint from `conn.` platform entries sharing a
    service directory.
  * METADATA (display_name, category, has_secret, timestamps) lives in a
    non-secret sidecar JSON (`user_vault.json`), keyed
    (platform, user_id, key) — sister of connections.json. It NEVER
    carries a value; `has_secret` is the only signal.
  * ALL FOUR VERBS (set / list / release / delete) are agent-token-gated
    and platform-scoped — a divergence from connections, where writes
    are operator-gated. Rationale: user-vault writes are the platform
    acting for its own user at runtime (the user pasted a key into the
    platform's UI); there is no operator in the loop. The platform
    supplies the user-id scoping claim (`X-Recto-User-Id`) and the
    bootloader namespaces every operation under (platform, user_id).
  * RELEASE is async + deniable BY CONTRACT: the response carries a
    `status` field (`released` | `unset` today) so the Hard Rule #9
    endgame — phone-resident user secrets with release-on-approval —
    slots in later as new statuses (`pending` | `denied`) with zero
    contract change. Consumers must treat any non-`released` status as
    value-absent and tolerate latency + denial.

Hard rules in play:
  - #2: secrets never logged / serialized / echoed. UserVaultEntryMeta
    carries no value field by construction; only the release path
    returns a value, with Cache-Control: no-store.
  - #6: SecretSource ABC is the storage contract; dpapi-machine is the
    Windows-host default, file-backed the container substitute.
  - #8/#15: nothing here embeds a deployment-specific literal; platform
    names, paths, and tokens all arrive through config.
  - #9: phone enclave is the unconditional root of trust — the release
    `status` field is the pre-cut seam for phone release-on-approval.

The metadata + management primitives live in `recto.user_vault.manage`;
the HTTP surface lands in `recto.bootloader.server` (`/v0.4/user-vault/*`);
the data contract every layer shares lives in `recto.user_vault.types`.
"""

from __future__ import annotations

from .types import (
    UserVaultEntryMeta,
    UserVaultStore,
    normalize_user_id,
    user_vault_secret_name,
)

__all__ = [
    "UserVaultEntryMeta",
    "UserVaultStore",
    "normalize_user_id",
    "user_vault_secret_name",
]
