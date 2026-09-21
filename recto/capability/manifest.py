"""
Capability action manifest — load, lookup, and scope-evaluation helpers.

The manifest is the single source of truth for which actions exist,
which groups they belong to, and what their foundation-counts are. JWTs
reference the manifest version (`CapabilityClause.registry_version`)
they were issued against; verifiers fetch that version's manifest at
validation time.

Phase 5 Wave A scope (this module):
  - load_manifest:         read and parse a manifest JSON file
  - resolve_actions:       expand a CapabilityClause's groups into the
                           full effective action set
  - evaluate_scope:        check whether a requested action is permitted
                           by a CapabilityClause given the current
                           manifest

Manifest distribution / vault-storage / version-fetching is a Wave C
concern; this module operates on already-loaded manifest data.

Pure stdlib. No new dependencies.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from recto.capability.types import (
    ActionDefinition,
    ActionManifest,
    CapabilityClause,
    GroupDefinition,
)


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------


def load_manifest(path: str | Path) -> ActionManifest:
    """Load a capability action manifest from a JSON file.

    Validates the shape — every action key referenced in any group MUST
    exist in the actions table. Raises ValueError on shape errors with
    a descriptive message naming the offending key.
    """
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    return load_manifest_from_dict(raw)


def load_manifest_from_dict(raw: dict[str, Any]) -> ActionManifest:
    """Parse an in-memory dict into an ActionManifest.

    Same validation as load_manifest — useful when the manifest comes
    from a vault fetch rather than disk.
    """
    version = raw.get("version")
    if not version or not isinstance(version, str):
        raise ValueError("Manifest missing or invalid 'version' field")

    actions_raw = raw.get("actions", {})
    if not isinstance(actions_raw, dict):
        raise ValueError("Manifest 'actions' must be an object")

    actions: dict[str, ActionDefinition] = {}
    for key, defn in actions_raw.items():
        if not isinstance(defn, dict):
            raise ValueError(f"Action '{key}' definition must be an object")
        count = defn.get("count")
        if not isinstance(count, int) or count < 0:
            raise ValueError(
                f"Action '{key}' must have a non-negative integer 'count'"
            )
        description = defn.get("description", "")
        if not isinstance(description, str):
            raise ValueError(f"Action '{key}' 'description' must be a string")
        actions[key] = ActionDefinition(count=count, description=description)

    groups_raw = raw.get("groups", {})
    if not isinstance(groups_raw, dict):
        raise ValueError("Manifest 'groups' must be an object")

    groups: dict[str, GroupDefinition] = {}
    for key, defn in groups_raw.items():
        if not isinstance(defn, dict):
            raise ValueError(f"Group '{key}' definition must be an object")
        member_actions = defn.get("actions", [])
        if not isinstance(member_actions, list):
            raise ValueError(f"Group '{key}' 'actions' must be a list")
        # Validate every member action exists in the actions table
        for action_key in member_actions:
            if action_key not in actions:
                raise ValueError(
                    f"Group '{key}' references unknown action '{action_key}'"
                )
        groups[key] = GroupDefinition(actions=list(member_actions))

    return ActionManifest(version=version, actions=actions, groups=groups)


# ---------------------------------------------------------------------------
# Scope resolution
# ---------------------------------------------------------------------------


def resolve_actions(
    clause: CapabilityClause, manifest: ActionManifest
) -> set[str]:
    """Expand a CapabilityClause's groups + allow_actions into the full
    effective action set, with deny_actions subtracted.

    Returns a set of action keys the capability authorizes. Used by
    verifiers to check whether a specific requested action is permitted.

    Raises ValueError if the clause references unknown groups or actions
    in this manifest version (caller should fail closed and refuse the
    capability rather than continue with partial scope).
    """
    if clause.registry_version != manifest.version:
        raise ValueError(
            f"Clause registry_version '{clause.registry_version}' does not "
            f"match manifest version '{manifest.version}'"
        )

    permitted: set[str] = set()

    # Add all actions from the named groups
    for group_key in clause.groups:
        if group_key not in manifest.groups:
            raise ValueError(
                f"Clause references unknown group '{group_key}' in "
                f"manifest version '{manifest.version}'"
            )
        for action_key in manifest.groups[group_key].actions:
            permitted.add(action_key)

    # Add explicit allow_actions
    for action_key in clause.allow_actions:
        if action_key not in manifest.actions:
            raise ValueError(
                f"Clause allow_actions references unknown action "
                f"'{action_key}' in manifest version '{manifest.version}'"
            )
        permitted.add(action_key)

    # Subtract deny_actions
    for action_key in clause.deny_actions:
        permitted.discard(action_key)

    return permitted


def evaluate_scope(
    requested_action: str,
    clause: CapabilityClause,
    manifest: ActionManifest,
    *,
    parent_profile_deny_actions: tuple[str, ...] | None = None,
) -> bool:
    """Check whether a requested action is permitted by a CapabilityClause.

    Convenience wrapper around resolve_actions for the common single-
    action check at verification time. Returns True if the action is
    in the resolved permitted set AND is not in
    ``parent_profile_deny_actions`` (Phase 2.0.C wave C.2 extension);
    False otherwise.

    Note: this checks only the action-set membership. Verifier callers
    must additionally check:
      - signature validity (jwt.verify_jws — pass state_dir for
        parent_profile dispatch)
      - jti not in revocation list (Wave C)
      - rate limits (clause.limits) — caller-side accounting
      - environment / service / repo scope (clause.scope) — caller-side
        contextual matching, since these are application-specific

    Args:
        requested_action: the action key the caller is asking about.
        clause: the CapabilityClause from the verified JWS claims.
        manifest: the action manifest to resolve groups against.
        parent_profile_deny_actions: Phase 2.0.C wave C.2 — when the
            JWS has a non-None parent_profile claim, the verified
            claims point at a child profile in MasterIdentity. That
            profile carries a ``deny_actions_inherited`` tuple (SCIM-
            pushed or operator-configured per-profile bans). Pass the
            tuple here so evaluate_scope subtracts those actions from
            the resolved permitted set BEFORE the membership check.
            Default None — for JWSes without parent_profile (or for
            callers that don't care about profile-level bans), this
            kwarg is irrelevant. To do a complete verify-time check
            on a v2.0.C-style JWS, callers compose verify_jws (with
            state_dir for parent_profile dispatch) + look up the
            profile's deny_actions_inherited from the same
            MasterIdentity + pass the tuple here.
    """
    try:
        permitted = resolve_actions(clause, manifest)
    except ValueError:
        # Unknown group or action -> fail closed
        return False
    if parent_profile_deny_actions:
        permitted = permitted - set(parent_profile_deny_actions)
    return requested_action in permitted


# ---------------------------------------------------------------------------
# Weight calculation (informational at v1; runtime-enforced at v2)
# ---------------------------------------------------------------------------


def clause_weight_breakdown(
    clause: CapabilityClause, manifest: ActionManifest
) -> dict[str, Any]:
    """Compute the foundation-count breakdown for a CapabilityClause.

    Returns a dict suitable for rendering the phone-side approval UI:

        {
            "total": 18,
            "tier": 1,
            "tier_ceiling": 30,
            "groups": [
                {"key": "darwin:doc-edits", "weight": 3,
                 "actions": [{"key": "doc:edit", "count": 1}, ...]},
                ...
            ],
            "extra_actions": [
                {"key": "some:explicit", "count": 5},
                ...
            ],
            "denied_actions": ["secret:rotate"]
        }

    At v1 this output is informational-only — surfaced on the phone UI
    so the operator sees the trust-transfer quantitatively. v2 adds
    runtime budget-spending where the total becomes a spend ceiling
    enforced by every verifier.

    FAILS CLOSED, like :func:`resolve_actions` (2026-08-09). Raises
    ``ValueError`` on a registry-version mismatch, an unknown group, or an
    unknown ``allow_actions`` entry.

    This function previously SKIPPED all three: unknown groups hit a bare
    ``continue`` and unknown actions were filtered by an ``if key in
    manifest.actions`` guard, while ``resolve_actions`` raised on exactly
    the same inputs. Same input class, opposite failure mode — an asymmetry
    against our own fail-closed doctrine, found by a defensive review.

    Why it must raise even though v1 output is "only" a display number:
    the number is what the operator reads when deciding whether to APPROVE a
    trust transfer, and every skip made it read LOW. Silently dropping an
    unrecognised group renders a capability as cheaper than it is, which is
    the one direction a consent UI must never round. At v2 the same total
    becomes a spend ceiling, so the identical bug graduates from a misleading
    display to granted headroom. Refusing to render beats rendering a number
    that understates what is being handed over.
    """
    from recto.capability.types import TIER_WEIGHT_CEILINGS

    if clause.registry_version != manifest.version:
        raise ValueError(
            f"Clause registry_version '{clause.registry_version}' does not "
            f"match manifest version '{manifest.version}'"
        )

    breakdown: dict[str, Any] = {
        "tier": clause.tier,
        "tier_ceiling": TIER_WEIGHT_CEILINGS.get(clause.tier),
        "groups": [],
        "extra_actions": [],
        "denied_actions": list(clause.deny_actions),
    }

    total = 0

    for group_key in clause.groups:
        if group_key not in manifest.groups:
            raise ValueError(
                f"Clause references unknown group '{group_key}' in "
                f"manifest version '{manifest.version}'"
            )
        actions = []
        group_weight = 0
        for action_key in manifest.groups[group_key].actions:
            count = manifest.actions[action_key].count
            actions.append({"key": action_key, "count": count})
            group_weight += count
        breakdown["groups"].append(
            {"key": group_key, "weight": group_weight, "actions": actions}
        )
        total += group_weight

    for action_key in clause.allow_actions:
        if action_key not in manifest.actions:
            raise ValueError(
                f"Clause allow_actions references unknown action "
                f"'{action_key}' in manifest version '{manifest.version}'"
            )
        count = manifest.actions[action_key].count
        breakdown["extra_actions"].append(
            {"key": action_key, "count": count}
        )
        total += count

    breakdown["total"] = total
    return breakdown
