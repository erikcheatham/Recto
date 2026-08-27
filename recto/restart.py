"""Restart policy: pure functions over a RestartSpec.

The launcher holds the attempt counter and the loop; this module just
answers "should we restart, and if so how long should we wait." Keeping
restart stateless makes it trivial to unit-test (no fixtures, no clocks)
and lets the launcher swap policies cleanly when the YAML changes via
hot-reload (planned v0.2).

Concepts
--------

`attempt` is 1-indexed for retries. attempt=0 is the initial launch;
the launcher does not call `next_delay(0, ...)` because there's no
delay before the first spawn. After the child exits, the launcher
increments attempt and asks `should_restart` + `next_delay` for the
next cycle.

`max_attempts` semantics from the YAML schema:
    0  → unlimited (the launcher never gives up).
    N  → at most N restart attempts; after that, emit
         'max_attempts_reached' and exit.

A "clean" exit is returncode == 0. "on-failure" policy restarts only
on non-zero returncode; "always" restarts regardless; "never" never
restarts.

Why we don't just put this in launcher.py
-----------------------------------------

The hot-reload story (v0.2): the admin UI lets ops update the YAML
without taking the service down. The launcher's restart loop will pick
up the new policy on the NEXT cycle, not in the middle of a backoff
sleep. Keeping these functions pure means hot-reload is "re-read the
RestartSpec and pass it to the next call" — no shared state to
reconcile.
"""

from __future__ import annotations

from recto.config import RestartSpec

__all__ = [
    "MaxAttemptsReachedError",
    "next_delay",
    "should_restart",
]


class MaxAttemptsReachedError(Exception):
    """Raised by the launcher's run-loop when policy.max_attempts is
    finite and the latest attempt exhausted the budget. The launcher
    catches this and emits a 'max_attempts_reached' event before exiting
    non-zero. Defined here (not in launcher.py) so callers that wrap
    `recto.restart.next_delay` directly don't need a launcher import.
    """


def should_restart(returncode: int, policy: RestartSpec) -> bool:
    """Decide whether the child should be restarted given its exit code.

    Pure function. Does NOT consult `attempt` — that's `next_delay`'s
    concern. The launcher composes both: first asks should_restart, and
    if True, asks next_delay(attempt) for how long to wait.
    """
    if policy.policy == "never":
        return False
    if policy.policy == "always":
        return True
    if policy.policy == "on-failure":
        return returncode != 0
    # Config validation should have caught any other value, but be
    # defensive: an unknown policy should fail closed (no restart) rather
    # than fail open (infinite restart loop on unrelated config bugs).
    return False


def next_delay(attempt: int, policy: RestartSpec) -> float:
    """Compute the seconds-to-sleep before the `attempt`-th restart.

    Args:
        attempt: 1-indexed retry counter. attempt=1 is the FIRST restart
            after the initial launch; attempt=2 is the second; etc.
            Callers pass attempt=0 only if they want a 0-second result
            (no-op convenience for the launcher's first iteration).
        policy: RestartSpec from the YAML.

    Returns:
        Delay in seconds, capped at policy.max_delay_seconds. attempt=0
        always returns 0.0.

    Raises:
        MaxAttemptsReachedError: policy.max_attempts is non-zero and `attempt`
            exceeds it. The launcher catches this and emits the
            corresponding event.

    Backoff curves
    --------------
    Let i = policy.initial_delay_seconds, m = policy.max_delay_seconds.

    - exponential: min(i * 2 ** (attempt - 1), m). attempt=1 → i,
      attempt=2 → 2i, attempt=3 → 4i, ... clipped at m.
    - linear:      min(i * attempt, m). attempt=1 → i, 2i, 3i, ...
    - constant:    min(i, m). Always i (or m if i > m, which is
      already prevented at config-validation time).
    """
    if attempt < 0:
        raise ValueError(f"attempt must be >= 0, got {attempt}")
    if attempt == 0:
        return 0.0

    if policy.max_attempts > 0 and attempt > policy.max_attempts:
        raise MaxAttemptsReachedError(
            f"restart attempt {attempt} exceeds max_attempts="
            f"{policy.max_attempts}"
        )

    initial = policy.initial_delay_seconds
    cap = policy.max_delay_seconds

    if policy.backoff == "constant":
        delay: float = float(initial)
    elif policy.backoff == "linear":
        delay = float(initial * attempt)
    elif policy.backoff == "exponential":
        # 2 ** (attempt - 1): attempt=1 → 1x, attempt=2 → 2x, ...
        # Cap the exponent before multiplying to avoid Python integer
        # blowup if attempt is huge (e.g. unlimited retries running
        # for days). We saturate at the cap anyway.
        # Cap exponent at 62 (2**62 > 4.6e18 sec, far past any sane cap)
        # to avoid Python's bigint slow path on absurd attempt counts.
        delay = (
            float(cap)
            if attempt - 1 > 62
            else float(initial * (2 ** (attempt - 1)))
        )
    else:
        # Defensive: config-validation should have caught this. Fall
        # back to constant so the launcher doesn't spin uselessly.
        delay = float(initial)

    return min(delay, float(cap))
