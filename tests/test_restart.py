"""Tests for recto.restart — pure-function policy module.

The whole point of restart being stateless is that tests are trivial:
construct a RestartSpec, call the function, assert the return value.
No fixtures, no clocks, no Popen mocks.
"""

from __future__ import annotations

import pytest

from recto.config import RestartSpec
from recto.restart import MaxAttemptsReachedError, next_delay, should_restart

# ---------------------------------------------------------------------------
# should_restart
# ---------------------------------------------------------------------------


class TestShouldRestart:
    def test_always_restarts_on_clean_exit(self) -> None:
        policy = RestartSpec(policy="always")
        assert should_restart(0, policy) is True

    def test_always_restarts_on_failure_exit(self) -> None:
        policy = RestartSpec(policy="always")
        assert should_restart(1, policy) is True

    def test_never_does_not_restart_on_clean_exit(self) -> None:
        policy = RestartSpec(policy="never")
        assert should_restart(0, policy) is False

    def test_never_does_not_restart_on_failure_exit(self) -> None:
        policy = RestartSpec(policy="never")
        assert should_restart(99, policy) is False

    def test_on_failure_does_not_restart_on_clean_exit(self) -> None:
        policy = RestartSpec(policy="on-failure")
        assert should_restart(0, policy) is False

    def test_on_failure_restarts_on_non_zero_exit(self) -> None:
        policy = RestartSpec(policy="on-failure")
        assert should_restart(1, policy) is True
        assert should_restart(-1, policy) is True
        assert should_restart(137, policy) is True  # SIGKILL


# ---------------------------------------------------------------------------
# next_delay — backoff curves
# ---------------------------------------------------------------------------


class TestNextDelayConstant:
    def test_constant_returns_initial_delay(self) -> None:
        policy = RestartSpec(
            backoff="constant",
            initial_delay_seconds=5,
            max_delay_seconds=60,
            max_attempts=0,  # unlimited so we can probe high attempt counts
        )
        assert next_delay(1, policy) == 5.0
        assert next_delay(10, policy) == 5.0  # never grows
        assert next_delay(100, policy) == 5.0


class TestNextDelayLinear:
    def test_linear_grows_with_attempt(self) -> None:
        policy = RestartSpec(
            backoff="linear",
            initial_delay_seconds=2,
            max_delay_seconds=100,
            max_attempts=0,
        )
        assert next_delay(1, policy) == 2.0
        assert next_delay(2, policy) == 4.0
        assert next_delay(3, policy) == 6.0
        assert next_delay(10, policy) == 20.0

    def test_linear_caps_at_max_delay(self) -> None:
        policy = RestartSpec(
            backoff="linear",
            initial_delay_seconds=10,
            max_delay_seconds=25,
            max_attempts=0,
        )
        assert next_delay(1, policy) == 10.0
        assert next_delay(2, policy) == 20.0
        assert next_delay(3, policy) == 25.0  # capped: would be 30, capped to 25
        assert next_delay(100, policy) == 25.0


class TestNextDelayExponential:
    def test_exponential_doubles_per_attempt(self) -> None:
        policy = RestartSpec(
            backoff="exponential",
            initial_delay_seconds=1,
            max_delay_seconds=10000,
            max_attempts=0,
        )
        assert next_delay(1, policy) == 1.0   # 1 * 2**0
        assert next_delay(2, policy) == 2.0   # 1 * 2**1
        assert next_delay(3, policy) == 4.0   # 1 * 2**2
        assert next_delay(4, policy) == 8.0
        assert next_delay(8, policy) == 128.0

    def test_exponential_caps_at_max_delay(self) -> None:
        policy = RestartSpec(
            backoff="exponential",
            initial_delay_seconds=1,
            max_delay_seconds=60,
            max_attempts=0,
        )
        assert next_delay(7, policy) == 60.0  # 1 * 2**6 = 64, capped to 60
        assert next_delay(20, policy) == 60.0  # would be huge, capped

    def test_exponential_giant_attempt_does_not_overflow(self) -> None:
        # The launcher could conceivably hit very high attempt counts
        # under unlimited retries — make sure the math saturates rather
        # than blowing up Python's integer cleverness.
        policy = RestartSpec(
            backoff="exponential",
            initial_delay_seconds=1,
            max_delay_seconds=300,
            max_attempts=0,
        )
        assert next_delay(10_000, policy) == 300.0


# ---------------------------------------------------------------------------
# next_delay — attempt edge cases
# ---------------------------------------------------------------------------


class TestNextDelayEdges:
    def test_attempt_zero_returns_zero(self) -> None:
        # Convenience: launcher's first iteration can call next_delay(0, ...)
        # and get 0.0 back instead of branching.
        policy = RestartSpec()
        assert next_delay(0, policy) == 0.0

    def test_negative_attempt_raises(self) -> None:
        policy = RestartSpec()
        with pytest.raises(ValueError):
            next_delay(-1, policy)

    def test_attempt_exceeds_max_attempts_raises(self) -> None:
        policy = RestartSpec(max_attempts=3)
        # attempt 1, 2, 3 are fine; attempt 4 exceeds the budget.
        next_delay(1, policy)
        next_delay(2, policy)
        next_delay(3, policy)
        with pytest.raises(MaxAttemptsReachedError) as exc:
            next_delay(4, policy)
        assert "max_attempts=3" in str(exc.value)

    def test_max_attempts_zero_means_unlimited(self) -> None:
        policy = RestartSpec(
            backoff="constant",
            initial_delay_seconds=1,
            max_delay_seconds=10,
            max_attempts=0,
        )
        # Arbitrarily high attempt — must not raise MaxAttemptsReachedError.
        assert next_delay(10_000, policy) == 1.0

    def test_unknown_backoff_falls_back_to_constant(self) -> None:
        # Defensive — config validation rejects unknown backoffs, but if
        # one slipped through (hand-constructed RestartSpec in tests, future
        # hot-reload bugs, etc.), we should land on a sane delay rather
        # than spinning at zero.
        # We can't construct such a RestartSpec via __post_init__, so the
        # branch is harder to exercise. Skip via a manually-constructed
        # instance using object.__setattr__.
        policy = RestartSpec()
        object.__setattr__(policy, "backoff", "totally-unknown-curve")
        # initial_delay default is 1; max_delay default is 60.
        assert next_delay(1, policy) == 1.0
