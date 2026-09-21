"""Tests for recto.reconcile -- compute_plan / render_plan / apply_plan."""

from __future__ import annotations

from pathlib import Path

import pytest

from recto.config import HealthzSpec, ServiceConfig, ServiceMeta, ServiceSpec
from recto.nssm import NssmConfig
from recto.reconcile import (
    FieldChange,
    ReconcilePlan,
    apply_plan,
    compute_plan,
    render_plan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_cfg(
    *,
    name: str = "myservice",
    description: str = "",
    display_name: str = "",
    working_dir: str = "C:\\path\\to\\myservice",
    exec_: str = "python.exe",
) -> ServiceConfig:
    return ServiceConfig(
        apiVersion="recto/v1",
        kind="Service",
        metadata=ServiceMeta(
            name=name, description=description, display_name=display_name
        ),
        spec=ServiceSpec(exec=exec_, working_dir=working_dir),
    )


def make_nssm(
    *,
    service: str = "myservice",
    app_path: str = "",
    app_parameters: str = "",
    app_directory: str = "",
    display_name: str = "",
    description: str = "",
    app_environment_extra: tuple[str, ...] = (),
) -> NssmConfig:
    return NssmConfig(
        service=service,
        app_path=app_path,
        app_parameters=app_parameters,
        app_directory=app_directory,
        display_name=display_name,
        description=description,
        app_environment_extra=app_environment_extra,
    )


class FakeNssm:
    """Records every set/reset call so the test can assert on them."""

    def __init__(self) -> None:
        self.set_calls: list[tuple[str, str, str]] = []
        self.reset_calls: list[tuple[str, str]] = []

    def set(self, service: str, field: str, value: str) -> None:
        self.set_calls.append((service, field, value))

    def reset(self, service: str, field: str) -> None:
        self.reset_calls.append((service, field))


# ---------------------------------------------------------------------------
# FieldChange
# ---------------------------------------------------------------------------


class TestFieldChange:
    def test_changed_when_different(self) -> None:
        c = FieldChange(field="X", current="a", desired="b")
        assert c.changed is True

    def test_unchanged_when_same(self) -> None:
        c = FieldChange(field="X", current="a", desired="a")
        assert c.changed is False

    def test_empty_strings_compare_equal(self) -> None:
        c = FieldChange(field="X", current="", desired="")
        assert c.changed is False


# ---------------------------------------------------------------------------
# compute_plan
# ---------------------------------------------------------------------------


class TestComputePlan:
    def test_empty_nssm_state_produces_full_change_set(self, tmp_path: Path) -> None:
        # Service exists in NSSM but every field is empty -- a freshly
        # `nssm install`ed service that hasn't been configured yet.
        cfg = make_cfg(
            name="myservice",
            description="A test service",
            working_dir="C:\\path\\to\\myservice",
        )
        current = make_nssm(service="myservice")
        yaml_path = tmp_path / "myservice.service.yaml"
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        assert plan.service == "myservice"
        assert plan.yaml_path == yaml_path
        # All five scalar fields should be flagged as changes (empty -> something).
        changed_fields = {c.field for c in plan.changes}
        assert changed_fields == {
            "Application",
            "AppParameters",
            "AppDirectory",
            "DisplayName",
            "Description",
        }
        assert plan.clear_environment_extra is False

    def test_matching_state_is_noop(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "myservice.service.yaml"
        cfg = make_cfg(
            name="myservice",
            description="A test service",
            working_dir="C:\\path\\to\\myservice",
        )
        # Build the current state to exactly match what cfg implies.
        current = make_nssm(
            service="myservice",
            app_path="python.exe",
            app_parameters=f"-m recto launch {yaml_path}",
            app_directory="C:\\path\\to\\myservice",
            display_name="A test service",
            description="A test service",
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        assert plan.is_noop is True
        assert plan.changes == ()

    def test_single_field_change(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "myservice.service.yaml"
        cfg = make_cfg(
            name="myservice",
            description="desc",
            working_dir="C:\\new\\path",
        )
        current = make_nssm(
            service="myservice",
            app_path="python.exe",
            app_parameters=f"-m recto launch {yaml_path}",
            app_directory="C:\\old\\path",  # only this differs
            display_name="desc",
            description="desc",
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        assert len(plan.changes) == 1
        assert plan.changes[0].field == "AppDirectory"
        assert plan.changes[0].current == "C:\\old\\path"
        assert plan.changes[0].desired == "C:\\new\\path"

    def test_environment_extra_clear_when_non_empty(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "myservice.service.yaml"
        cfg = make_cfg(name="myservice", description="x", working_dir="C:\\x")
        current = make_nssm(
            service="myservice",
            app_path="python.exe",
            app_parameters=f"-m recto launch {yaml_path}",
            app_directory="C:\\x",
            display_name="x",
            description="x",
            app_environment_extra=("MY_API_KEY=leftover-from-pre-recto",),
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        # All scalar fields match, but AppEnvironmentExtra is non-empty
        # so the plan still has work to do.
        assert plan.changes == ()
        assert plan.clear_environment_extra is True
        assert plan.is_noop is False

    def test_description_falls_back_to_name_for_display_name(
        self, tmp_path: Path
    ) -> None:
        yaml_path = tmp_path / "myservice.service.yaml"
        cfg = make_cfg(name="myservice", description="")
        current = make_nssm(service="myservice")
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        # When description is empty, DisplayName falls back to the name.
        display = next(
            c for c in plan.field_changes if c.field == "DisplayName"
        )
        assert display.desired == "myservice"
        # Description itself stays empty.
        desc = next(c for c in plan.field_changes if c.field == "Description")
        assert desc.desired == ""

    def test_display_name_explicit_takes_precedence_over_description(
        self, tmp_path: Path
    ) -> None:
        """Papercut #3: when metadata.display_name is set, it lands in
        NSSM DisplayName independently of description. NSSM Description
        stays mapped 1:1 from metadata.description so the two registry
        fields can carry distinct values (the standard NSSM convention)."""
        yaml_path = tmp_path / "myservice.service.yaml"
        cfg = make_cfg(
            name="myservice",
            description="A long description that operators read in the Services snap-in detail pane.",
            display_name="MyService",
        )
        current = make_nssm(service="myservice")
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        display = next(
            c for c in plan.field_changes if c.field == "DisplayName"
        )
        desc = next(c for c in plan.field_changes if c.field == "Description")
        # The two NSSM fields now carry their distinct YAML values.
        assert display.desired == "MyService"
        assert desc.desired == (
            "A long description that operators read in the Services snap-in detail pane."
        )

    def test_display_name_empty_keeps_v0_2_0_fallback(
        self, tmp_path: Path
    ) -> None:
        """Papercut #3 backward-compat: when display_name is omitted
        (the v0.2.0 schema shape), DisplayName still derives from
        description -> name as before. Existing service.yaml files keep
        working unchanged."""
        yaml_path = tmp_path / "myservice.service.yaml"
        cfg = make_cfg(
            name="myservice",
            description="A test service",
            # display_name omitted -> defaults to ""
        )
        current = make_nssm(service="myservice")
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        display = next(
            c for c in plan.field_changes if c.field == "DisplayName"
        )
        desc = next(c for c in plan.field_changes if c.field == "Description")
        # Backward-compat: DisplayName picks up description.
        assert display.desired == "A test service"
        assert desc.desired == "A test service"

    def test_python_exe_override_lands_in_app_path(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "x.yaml"
        cfg = make_cfg(name="x", description="x", working_dir="")
        current = make_nssm(service="x")
        plan = compute_plan(
            cfg,
            current,
            yaml_path=yaml_path,
            python_exe="C:\\Python312\\python.exe",
        )
        app_path = next(c for c in plan.field_changes if c.field == "Application")
        assert app_path.desired == "C:\\Python312\\python.exe"

    def test_app_parameters_uses_yaml_path_verbatim(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "very" / "specific" / "path.yaml"
        cfg = make_cfg(name="x", description="x", working_dir="")
        current = make_nssm(service="x")
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        app_params = next(
            c for c in plan.field_changes if c.field == "AppParameters"
        )
        assert app_params.desired == f"-m recto launch {yaml_path}"


# ---------------------------------------------------------------------------
# render_plan
# ---------------------------------------------------------------------------


class TestRenderPlan:
    def test_noop_says_no_changes(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "myservice.service.yaml"
        cfg = make_cfg(
            name="myservice",
            description="A test service",
            working_dir="C:\\path",
        )
        current = make_nssm(
            service="myservice",
            app_path="python.exe",
            app_parameters=f"-m recto launch {yaml_path}",
            app_directory="C:\\path",
            display_name="A test service",
            description="A test service",
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        out = render_plan(plan)
        assert "no changes needed" in out
        assert "myservice" in out

    def test_changed_lines_use_tilde_marker(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "x.yaml"
        cfg = make_cfg(name="x", description="x", working_dir="C:\\new")
        current = make_nssm(
            service="x",
            app_path="python.exe",
            app_parameters=f"-m recto launch {yaml_path}",
            app_directory="C:\\old",
            display_name="x",
            description="x",
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        out = render_plan(plan)
        assert "~ AppDirectory:" in out
        # render uses repr() so backslashes are doubled in the output.
        assert repr("C:\\old") in out
        assert repr("C:\\new") in out

    def test_unchanged_lines_have_no_marker(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "x.yaml"
        cfg = make_cfg(name="x", description="x", working_dir="C:\\new")
        current = make_nssm(
            service="x",
            app_path="python.exe",
            app_parameters=f"-m recto launch {yaml_path}",
            app_directory="C:\\old",
            display_name="x",
            description="x",
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        out = render_plan(plan)
        # Application matches in this scenario; should appear with "unchanged".
        assert "Application: unchanged" in out

    def test_environment_extra_clear_uses_bang_marker(
        self, tmp_path: Path
    ) -> None:
        yaml_path = tmp_path / "x.yaml"
        cfg = make_cfg(name="x", description="x", working_dir="C:\\x")
        current = make_nssm(
            service="x",
            app_path="python.exe",
            app_parameters=f"-m recto launch {yaml_path}",
            app_directory="C:\\x",
            display_name="x",
            description="x",
            app_environment_extra=("LEFTOVER_KEY=value",),
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        out = render_plan(plan)
        assert "! AppEnvironmentExtra: will be cleared" in out
        # The plan output MUST NOT include the leftover secret VALUE.
        assert "LEFTOVER_KEY" not in out
        assert "value" not in out


# ---------------------------------------------------------------------------
# apply_plan
# ---------------------------------------------------------------------------


class TestApplyPlan:
    def test_noop_plan_calls_nothing(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "x.yaml"
        cfg = make_cfg(name="x", description="x", working_dir="C:\\x")
        current = make_nssm(
            service="x",
            app_path="python.exe",
            app_parameters=f"-m recto launch {yaml_path}",
            app_directory="C:\\x",
            display_name="x",
            description="x",
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        nssm = FakeNssm()
        apply_plan(plan, nssm)
        assert nssm.set_calls == []
        assert nssm.reset_calls == []

    def test_applies_only_changed_fields(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "x.yaml"
        cfg = make_cfg(name="x", description="x", working_dir="C:\\new")
        current = make_nssm(
            service="x",
            app_path="python.exe",  # matches
            app_parameters=f"-m recto launch {yaml_path}",  # matches
            app_directory="C:\\old",  # differs
            display_name="x",  # matches
            description="x",  # matches
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        nssm = FakeNssm()
        apply_plan(plan, nssm)
        # Only AppDirectory should have been written.
        assert nssm.set_calls == [("x", "AppDirectory", "C:\\new")]
        assert nssm.reset_calls == []

    def test_applies_all_changes_for_fresh_service(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "myservice.service.yaml"
        cfg = make_cfg(
            name="myservice",
            description="A test service",
            working_dir="C:\\path",
        )
        current = make_nssm(service="myservice")  # all fields empty
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        nssm = FakeNssm()
        apply_plan(plan, nssm)
        # All five scalar fields should be set.
        set_fields = {field for (_, field, _) in nssm.set_calls}
        assert set_fields == {
            "Application",
            "AppParameters",
            "AppDirectory",
            "DisplayName",
            "Description",
        }
        assert nssm.reset_calls == []

    def test_environment_extra_clear_resets(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "x.yaml"
        cfg = make_cfg(name="x", description="x", working_dir="C:\\x")
        current = make_nssm(
            service="x",
            app_path="python.exe",
            app_parameters=f"-m recto launch {yaml_path}",
            app_directory="C:\\x",
            display_name="x",
            description="x",
            app_environment_extra=("MY_API_KEY=leftover",),
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        nssm = FakeNssm()
        apply_plan(plan, nssm)
        assert nssm.set_calls == []  # all scalar fields matched
        assert nssm.reset_calls == [("x", "AppEnvironmentExtra")]

    def test_environment_extra_clear_runs_after_sets(self, tmp_path: Path) -> None:
        # If a partial failure happens during the scalar sets, the
        # AppEnvironmentExtra clear (which is a destructive op on
        # plaintext secrets) should not yet have run. Verify ordering:
        # all sets first, then the reset.
        yaml_path = tmp_path / "x.yaml"
        cfg = make_cfg(name="x", description="x", working_dir="C:\\new")
        current = make_nssm(
            service="x",
            app_path="OLD",
            app_parameters="OLD",
            app_directory="OLD",
            display_name="OLD",
            description="OLD",
            app_environment_extra=("KEY=value",),
        )
        plan = compute_plan(
            cfg, current, yaml_path=yaml_path, python_exe="python.exe"
        )
        events: list[str] = []

        class OrderedNssm:
            def set(self, _service: str, field: str, _value: str) -> None:
                events.append(f"set:{field}")

            def reset(self, _service: str, field: str) -> None:
                events.append(f"reset:{field}")

        apply_plan(plan, OrderedNssm())
        # The reset should be the last event.
        assert events[-1] == "reset:AppEnvironmentExtra"
        # And there should be 5 sets before it.
        assert sum(1 for e in events if e.startswith("set:")) == 5
