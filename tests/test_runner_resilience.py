"""Tests for run_sweep()'s per-episode fault isolation.

One provider error (e.g. Groq's occasional malformed tool-call response)
must not abort an entire sweep -- it should retry a couple of times, and if
still failing, skip just that seed and keep going. No real time.sleep in
these tests: the retry backoff is mocked out so the suite stays fast.
"""

from __future__ import annotations

import pytest

from tripwire.adapters.base import EpisodeSpec, NormalizedTrace
from tripwire.harness.runner import run_sweep


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    monkeypatch.setattr("tripwire.harness.runner.time.sleep", lambda *_: None)


class _FixedAttack:
    name = "fixed"

    def render(self, canary: str) -> str:  # noqa: ARG002
        return "payload"


class _FlakyAdapter:
    """Fails on specific seeds (permanently or for a limited number of
    attempts), succeeds on the rest -- simulates the real Groq quirk."""

    name = "flaky"

    def __init__(self, fail_seeds: set[int] | None = None, fail_once_seeds: set[int] | None = None):
        self.fail_seeds = fail_seeds or set()
        self.fail_once_seeds = fail_once_seeds or set()
        self._fail_once_used: set[int] = set()
        self.calls: list[int] = []

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        seed = spec.environment_seed
        self.calls.append(seed)
        if seed in self.fail_seeds:
            raise RuntimeError(f"simulated permanent provider error for seed {seed}")
        if seed in self.fail_once_seeds and seed not in self._fail_once_used:
            self._fail_once_used.add(seed)
            raise RuntimeError(f"simulated transient provider error for seed {seed}")
        return NormalizedTrace(steps=[], final_output="ok")


def test_permanently_failing_seed_is_skipped_not_raised():
    adapter = _FlakyAdapter(fail_seeds={1})
    episodes, _ = run_sweep([adapter], ["m"], [_FixedAttack()], [0, 1, 2])
    # No exception propagated, and only the 2 good seeds made it into results.
    assert {e.seed for e in episodes} == {0, 2}
    assert len(episodes) == 2


def test_transient_failure_recovers_via_retry():
    adapter = _FlakyAdapter(fail_once_seeds={0})
    episodes, _ = run_sweep([adapter], ["m"], [_FixedAttack()], [0])
    # Failed once, retried, succeeded -- still counted.
    assert len(episodes) == 1
    assert episodes[0].seed == 0
    assert adapter.calls == [0, 0]  # first attempt + one retry


def test_one_bad_seed_does_not_abort_the_rest_of_the_sweep():
    adapter = _FlakyAdapter(fail_seeds={2})
    episodes, _ = run_sweep([adapter], ["m"], [_FixedAttack()], [0, 1, 2, 3, 4])
    assert {e.seed for e in episodes} == {0, 1, 3, 4}
    assert len(episodes) == 4


def test_skipped_run_prints_warning_to_stderr(capsys):
    adapter = _FlakyAdapter(fail_seeds={0})
    run_sweep([adapter], ["m"], [_FixedAttack()], [0])
    err = capsys.readouterr().err
    assert "skipping" in err
    assert "seed=0" in err


def test_skip_message_includes_full_traceback(capsys):
    """On final give-up the full traceback is printed, not just the exception
    type -- so a real bug in a user's --agent adapter is debuggable instead of
    reading as a vague 'provider error'."""
    adapter = _FlakyAdapter(fail_seeds={0})
    run_sweep([adapter], ["m"], [_FixedAttack()], [0])
    err = capsys.readouterr().err
    assert "Traceback (most recent call last)" in err
    assert "RuntimeError: simulated permanent provider error" in err
    assert 'raise RuntimeError' in err  # a source line from the traceback


def test_all_seeds_succeeding_produces_no_warning(capsys):
    adapter = _FlakyAdapter()
    run_sweep([adapter], ["m"], [_FixedAttack()], [0, 1, 2])
    assert capsys.readouterr().err == ""


def test_retries_are_bounded():
    """A permanently-failing seed is attempted exactly _MAX_EPISODE_RETRIES + 1
    times, not retried forever."""
    adapter = _FlakyAdapter(fail_seeds={0})
    run_sweep([adapter], ["m"], [_FixedAttack()], [0])
    assert len(adapter.calls) == 3  # 1 initial + 2 retries
