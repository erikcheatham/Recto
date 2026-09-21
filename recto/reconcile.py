"""GitOps reconcile: bring NSSM state in line with a service.yaml.

`recto apply <yaml>` reads a service.yaml, reads the current NSSM state
for the named service, computes a diff (the "plan"), and applies it.
Replaces the imperative `nssm set <service> Application ...` PowerShell
that v0.1 consumers were running by hand.

Why this matters
----------------

NSSM stores service config in the registry as a flat collection of
keys. With v0.1, the way to wrap a service in Recto was a hand-edited
PowerShell sequence:

    nssm set mytradingapp Application C:\\Python312\\python.exe
    nssm set mytradingapp AppParameters "-m recto launch C:\\path\\to\\mytradingapp.service.yaml"
    nssm reset mytradingapp AppEnvironmentExtra

That works once. It does not survive review, drift, or "what is the
current config" questions. `recto apply <yaml>` makes the YAML the
source of truth: edit the YAML, commit it, run `recto apply`, and
NSSM matches the YAML. Diffs are surfaced before they're applied so
operators see what's about to change.

What this module reconciles
---------------------------

Five NSSM scalar fields, plus the AppEnvironmentExtra clear:

- Application -- the python.exe (or other interpreter) NSSM invokes.
  (NSSM names this parameter `Application`, not `AppPath` — the "App"
  prefix is not uniform across NSSM's params.)
- AppParameters -- ``-m recto launch <abs-path-to-yaml>``. This is the
  permanent shape; once you've migrated to Recto, NSSM never invokes
  the child directly -- it always goes through the launcher so secrets,
  healthz, restart policy, and comms dispatch all work.
- AppDirectory -- mirrors ``spec.working_dir``.
- DisplayName -- ``metadata.description`` if set, else ``metadata.name``.
- Description -- ``metadata.description``.
- AppEnvironmentExtra -- always cleared if currently non-empty. The
  v0.1 `migrate-from-nssm` path imports those entries to Credential
  Manager once; from then on, they belong in CredMan, not the
  registry. If you're running ``recto apply`` and AppEnvironmentExtra
  has anything in it, that's plaintext secrets sitting in the registry
  -- the plan will surface that and the apply will clear it.

What this module does NOT touch
-------------------------------

- Service registration. NSSM still owns ``nssm install <service>``;
  that's a separate one-time step. ``recto apply`` errors with a
  clear message if the service doesn't exist yet.
- Credential Manager entries. Secrets live in CredMan, managed via
  ``recto credman set/list/delete``. ``recto apply`` does not read,
  write, or even reason about secret VALUES -- only the YAML's
  ``spec.secrets[]`` declarations, which are themselves not secret.
- The launcher's runtime behavior. ``spec.env``, ``spec.healthz``,
  ``spec.restart``, ``spec.comms`` are consumed by the launcher at
  child-spawn time, not by NSSM. ``recto apply`` doesn't try to
  push them into NSSM-side fields.

Test strategy
-------------

``compute_plan`` and ``render_plan`` are pure -- no I/O. Tests pass
synthetic ``ServiceConfig`` + ``NssmConfig`` inputs and assert on the
returned ``ReconcilePlan`` / formatted string. ``apply_plan`` is the
only side-effecting function and routes through an injected
``NssmClient`` (production passes the real one; tests pass a
``FakeNssmClient`` that records every set/reset call).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from recto.config import ServiceConfig
from recto.nssm import NssmClient, NssmConfig

__all__ = [
    "FieldChange",
    "ReconcilePlan",
    "apply_plan",
    "compute_plan",
    "render_plan",
]


@dataclass(frozen=True, slots=True)
class FieldChange:
    """A single NSSM scalar field's current and desired values.

    ``changed`` is True iff current != desired -- the canonical "is this
    a no-op?" predicate. Construction does not validate; the plan
    builder assembles a tuple of these for every field it considers,
    and the apply step skips unchanged ones.
    """

    field: str
    current: str
    desired: str

    @property
    def changed(self) -> bool:
        return self.current != self.desired


@dataclass(frozen=True, slots=True)
class ReconcilePlan:
    """Diff between a YAML config and current NSSM state.

    ``field_changes`` is the full list of fields considered (changed +
    unchanged). ``changes`` is just the changed subset, useful for
    counts in confirm-prompt copy and for short-circuit logic.
    ``clear_environment_extra`` is special-cased: AppEnvironmentExtra
    is a multi-string, not a scalar, and the v0.2 contract is "always
    clear it if non-empty," so we don't model it as a FieldChange.
    """

    service: str
    yaml_path: Path
    field_changes: tuple[FieldChange, ...]
    clear_environment_extra: bool

    @property
    def changes(self) -> tuple[FieldChange, ...]:
        return tuple(c for c in self.field_changes if c.changed)

    @property
    def is_noop(self) -> bool:
        return not self.changes and not self.clear_environment_extra


def compute_plan(
    cfg: ServiceConfig,
    current: NssmConfig,
    *,
    yaml_path: Path,
    python_exe: str = "python.exe",
) -> ReconcilePlan:
    """Compare ``cfg`` against ``current`` NSSM state; return the plan.

    Args:
        cfg: Parsed ServiceConfig (from ``recto.config.load_config``).
        current: Snapshot of NSSM state (from ``NssmClient.get_all``).
        yaml_path: Absolute path to the service.yaml. Goes verbatim
            into ``-m recto launch <yaml_path>`` for AppParameters, so
            a relative path here would yield a non-portable
            AppParameters value on disk.
        python_exe: The interpreter NSSM should invoke. Default
            ``python.exe`` (resolved via PATH at service-start time).
            Override for environments that need a specific interpreter
            (e.g. ``C:\\Python312\\python.exe``). Note: the
            ``recto apply`` CLI does NOT use this default directly --
            it resolves an unset ``--python-exe`` to the existing NSSM
            ``Application`` value first (Papercut #1) and only falls
            back to ``"python.exe"`` if NSSM has nothing on file.

    Returns:
        ReconcilePlan with one FieldChange per considered field plus
        the clear_environment_extra flag.
    """
    desired_app_path = python_exe
    desired_app_parameters = f"-m recto launch {yaml_path}"
    desired_app_directory = cfg.spec.working_dir
    # DisplayName: prefer explicit `metadata.display_name` (Papercut #3
    # additive field, v0.2.x+); else fall back to v0.2.0 behavior of
    # using `metadata.description`; else the service name. NSSM shows
    # DisplayName in the Services snap-in. Description is the longer
    # "what is this service for" string and stays mapped 1:1 from
    # `metadata.description` so existing YAMLs that only set
    # description keep working unchanged.
    desired_display_name = (
        cfg.metadata.display_name
        or cfg.metadata.description
        or cfg.metadata.name
    )
    desired_description = cfg.metadata.description

    field_changes = (
        FieldChange("Application", current.app_path, desired_app_path),
        FieldChange(
            "AppParameters", current.app_parameters, desired_app_parameters
        ),
        FieldChange(
            "AppDirectory", current.app_directory, desired_app_directory
        ),
        FieldChange(
            "DisplayName", current.display_name, desired_display_name
        ),
        FieldChange("Description", current.description, desired_description),
    )

    return ReconcilePlan(
        service=cfg.metadata.name,
        yaml_path=yaml_path,
        field_changes=field_changes,
        clear_environment_extra=bool(current.app_environment_extra),
    )


def render_plan(plan: ReconcilePlan) -> str:
    """Format a ReconcilePlan for human review.

    Output shape:

        recto apply: <service> (from <yaml_path>)
          ~ <Field>: <current> -> <desired>           # changed fields
            <Field>: unchanged                         # unchanged fields
          ! AppEnvironmentExtra: will be cleared      # if non-empty

    Or for a no-op plan:

        recto apply: <service> (from <yaml_path>)
          no changes needed

    The leading marker (~ for changed, blank for unchanged, ! for the
    AppEnvironmentExtra clear) is intentional: it makes a diff scan
    fast for an operator skimming a long plan.
    """
    lines: list[str] = []
    lines.append(f"recto apply: {plan.service} (from {plan.yaml_path})")
    if plan.is_noop:
        lines.append("  no changes needed")
        return "\n".join(lines)
    for c in plan.field_changes:
        if c.changed:
            lines.append(
                f"  ~ {c.field}: {c.current!r} -> {c.desired!r}"
            )
        else:
            lines.append(f"    {c.field}: unchanged ({c.current!r})")
    if plan.clear_environment_extra:
        lines.append(
            "  ! AppEnvironmentExtra: will be cleared "
            "(secrets belong in CredMan, not the registry)"
        )
    return "\n".join(lines)


def apply_plan(plan: ReconcilePlan, nssm: NssmClient) -> None:
    """Execute every change in ``plan`` via the NssmClient.

    Skips unchanged fields (no spurious set calls). The
    AppEnvironmentExtra clear, if present, is the last operation --
    so a partial failure leaves the secret-containing field intact
    rather than half-cleared. NssmError propagates for the caller
    to surface; the caller is responsible for distinguishing
    user-facing messages from raw stack traces.
    """
    for c in plan.field_changes:
        if not c.changed:
            continue
        nssm.set(plan.service, c.field, c.desired)
    if plan.clear_environment_extra:
        nssm.reset(plan.service, "AppEnvironmentExtra")
