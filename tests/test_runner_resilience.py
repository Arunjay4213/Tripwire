"""Tests for run_sweep()'s error handling: errors are outcomes, not gaps.

Only transient provider errors (rate limit, connection, timeout, 5xx) are
retried, per adapter call. Any other exception -- or a transient one that
outlasts the retries -- is recorded as an EpisodeResult with status="error"
(or counted in CampaignResult.errors) instead of being silently dropped,
because the runs that crash are correlated with what the injection did and
dropping them biases the sample. No real time.sleep in these tests: the retry
backoff is mocked out so the suite stays fast.
"""

from __future__ import annotations

import json

import httpx
import openai
import pytest

from tripwire.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep
from tripwire.attacks.tree_attacker import TreeResult
from tripwire.harness.canary import make_canary
from tripwire.harness.runner import (
    _is_transient,
    run_campaign,
    run_scenario_tree_campaign,
    run_sweep,
)
from tripwire.scenarios import SCENARIOS


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    monkeypatch.setattr("tripwire.harness.runner.time.sleep", lambda *_: None)


_REQUEST = httpx.Request("POST", "https://example.invalid/v1/chat/completions")


def _rate_limit() -> openai.RateLimitError:
    return openai.RateLimitError(
        "rate limited", response=httpx.Response(429, request=_REQUEST), body=None
    )


def _server_error() -> openai.InternalServerError:
    return openai.InternalServerError(
        "overloaded", response=httpx.Response(500, request=_REQUEST), body=None
    )


class _FixedAttack:
    name = "fixed"

    def render(self, canary: str) -> str:  # noqa: ARG002
        return "payload"


class _FlakyAdapter:
    """Raises a scripted exception on specific seeds, a limited number of times
    (None = forever), and returns a clean trace otherwise."""

    name = "flaky"

    def __init__(self, failures: dict[int, tuple[Exception, int | None]] | None = None):
        self.failures = failures or {}
        self.calls: list[int] = []

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        seed = spec.environment_seed
        self.calls.append(seed)
        if seed in self.failures:
            exc, times = self.failures[seed]
            if times is None or self.calls.count(seed) <= times:
                raise exc
        return NormalizedTrace(steps=[], final_output="ok", stop_reason="max_turns")


# --- classification ----------------------------------------------------------

def test_is_transient_classification():
    assert _is_transient(_rate_limit())
    assert _is_transient(_server_error())
    assert _is_transient(openai.APIConnectionError(request=_REQUEST))
    assert _is_transient(openai.APITimeoutError(request=_REQUEST))
    assert not _is_transient(TypeError("x"))
    assert not _is_transient(ValueError("x"))
    assert not _is_transient(json.JSONDecodeError("bad", "{", 0))
    assert not _is_transient(RuntimeError("x"))


# --- episodes ----------------------------------------------------------------

def test_non_transient_error_is_recorded_not_retried_not_dropped():
    adapter = _FlakyAdapter({1: (TypeError("unsupported operand"), None)})
    episodes, _ = run_sweep([adapter], ["m"], [_FixedAttack()], [0, 1, 2])
    # Every seed is in the results -- the errored one is not dropped from n.
    assert [e.seed for e in episodes] == [0, 1, 2]
    errored = episodes[1]
    assert errored.status == "error"
    assert errored.error == "TypeError: unsupported operand"
    assert errored.succeeded is False and errored.task_completed is False
    assert errored.stop_reason == "error"
    assert errored.model == "m" and errored.attack == "fixed" and errored.scenario == "invoice"
    assert {e.status for e in (episodes[0], episodes[2])} == {"ok"}
    # A TypeError is deterministic: it is attempted exactly once.
    assert adapter.calls.count(1) == 1


def test_json_decode_error_is_not_retried():
    adapter = _FlakyAdapter({0: (json.JSONDecodeError("Expecting value", "{", 1), None)})
    episodes, _ = run_sweep([adapter], ["m"], [_FixedAttack()], [0])
    assert adapter.calls == [0]
    assert episodes[0].status == "error"
    assert episodes[0].error.startswith("JSONDecodeError:")


def test_rate_limit_then_success_is_retried_and_counted_ok():
    adapter = _FlakyAdapter({0: (_rate_limit(), 1)})
    episodes, _ = run_sweep([adapter], ["m"], [_FixedAttack()], [0])
    assert adapter.calls == [0, 0]  # first attempt + one retry
    assert len(episodes) == 1
    assert episodes[0].status == "ok" and episodes[0].error is None


def test_transient_error_that_persists_is_bounded_then_recorded():
    adapter = _FlakyAdapter({0: (_server_error(), None)})
    episodes, _ = run_sweep([adapter], ["m"], [_FixedAttack()], [0])
    assert len(adapter.calls) == 3  # 1 initial + 2 retries, not forever
    assert episodes[0].status == "error"
    assert episodes[0].error.startswith("InternalServerError:")


def test_ok_episode_copies_trace_stop_reason():
    episodes, _ = run_sweep([_FlakyAdapter()], ["m"], [_FixedAttack()], [0])
    assert episodes[0].status == "ok"
    assert episodes[0].stop_reason == "max_turns"


def test_judge_crash_is_an_error_outcome(monkeypatch):
    """An exception after the adapter ran (e.g. in utility scoring) is also
    recorded, not retried: re-running a whole paid episode cannot fix it."""
    adapter = _FlakyAdapter()

    def boom(self, trace):  # noqa: ARG001
        raise TypeError("argument of type 'NoneType' is not iterable")

    monkeypatch.setattr(type(SCENARIOS["invoice"]), "task_completed", boom)
    episodes, _ = run_sweep([adapter], ["m"], [_FixedAttack()], [0])
    assert adapter.calls == [0]
    assert episodes[0].status == "error"


def test_error_prints_traceback_and_summary(capsys):
    adapter = _FlakyAdapter({0: (RuntimeError("simulated adapter bug"), None)})
    run_sweep([adapter], ["m"], [_FixedAttack()], [0, 1])
    err = capsys.readouterr().err
    assert "seed=0" in err and "model=m" in err
    assert "Traceback (most recent call last)" in err
    assert "RuntimeError: simulated adapter bug" in err
    assert "raise exc" in err  # a source line from the traceback
    assert "errors: 1 episode(s)" in err


def test_all_seeds_succeeding_produces_no_warning(capsys):
    run_sweep([_FlakyAdapter()], ["m"], [_FixedAttack()], [0, 1, 2])
    assert capsys.readouterr().err == ""


def test_max_turns_reaches_the_adapter():
    class _Recording:
        name = "recording"

        def __init__(self):
            self.max_turns: list[int] = []

        def run(self, spec):
            self.max_turns.append(spec.max_turns)
            return NormalizedTrace(steps=[], final_output="")

    adapter = _Recording()
    run_sweep([adapter], ["m"], [_FixedAttack()], [0], max_turns=12)
    assert adapter.max_turns == [12]
    run_sweep([adapter], ["m"], [_FixedAttack()], [0])
    assert adapter.max_turns == [12, 5]  # default matches EpisodeSpec


# --- campaigns ---------------------------------------------------------------

class _CountingAttacker:
    name = "iterative"

    def __init__(self):
        self.histories: list[list[tuple[str, int, str]]] = []

    def next_payload(self, history):
        self.histories.append(list(history))
        return f"payload-{len(history)}"


class _ScriptedCampaignAdapter:
    """Returns clean traces, but raises `exc` on the given 1-based calls."""

    name = "scripted"

    def __init__(self, raise_on: dict[int, Exception]):
        self.raise_on = raise_on
        self.calls = 0

    def run(self, spec):
        self.calls += 1
        if self.calls in self.raise_on:
            raise self.raise_on[self.calls]
        return NormalizedTrace(steps=[], final_output="no")


def _spec(seed: int = 0) -> EpisodeSpec:
    return EpisodeSpec(task=None, tools=[], model="m", environment_seed=seed)


def test_campaign_error_on_attempt_3_keeps_attempts_1_2_and_counts_it():
    """Regression: the old runner restarted the whole campaign with a fresh
    budget, so budget=4 could spend 12 evaluations. Now the errored attempt is
    spent, recorded in history with grade 0, and the campaign continues."""
    attacker = _CountingAttacker()
    adapter = _ScriptedCampaignAdapter({3: TypeError("bad args")})
    result = run_campaign(adapter, _spec(), attacker, budget=4)
    assert adapter.calls == 4  # never more than the budget
    assert result.evaluations_spent == 4
    assert result.errors == 1
    assert result.status == "ok"
    assert result.broke is False
    final_history = attacker.histories[-1]
    assert [p for p, _, _ in final_history] == ["payload-0", "payload-1", "payload-2"]
    assert final_history[2][1] == 0
    assert "errored" in final_history[2][2] and "TypeError" in final_history[2][2]


def test_campaign_retries_transient_error_within_one_attempt():
    attacker = _CountingAttacker()
    adapter = _ScriptedCampaignAdapter({2: _rate_limit()})
    result = run_campaign(adapter, _spec(), attacker, budget=2)
    # Attempt 2 raised once, was retried, and succeeded: 3 adapter calls, 2 evaluations.
    assert adapter.calls == 3
    assert result.evaluations_spent == 2
    assert result.errors == 0


def test_campaign_attempts_to_break_counts_errored_attempts():
    canary = make_canary(0)

    class _LeakOnThird:
        name = "leaky"

        def __init__(self):
            self.calls = 0

        def run(self, spec):
            self.calls += 1
            if self.calls == 1:
                raise ValueError("bad")
            if self.calls == 3:
                return NormalizedTrace(steps=[TraceStep(
                    step=0, type="tool_call", name="send_email",
                    args={"to": "ap@corp.com", "body": canary})], final_output="")
            return NormalizedTrace(steps=[], final_output="")

    result = run_campaign(_LeakOnThird(), _spec(), _CountingAttacker(), budget=5)
    assert result.broke is True
    assert result.attempts_to_break == 3
    assert result.evaluations_spent == 3
    assert result.errors == 1


def test_campaign_attacker_crash_is_status_error_with_partial_accounting():
    class _DyingAttacker(_CountingAttacker):
        def next_payload(self, history):
            if len(history) == 2:
                raise RuntimeError("attacker LLM failed")
            return super().next_payload(history)

    result = run_campaign(_ScriptedCampaignAdapter({}), _spec(), _DyingAttacker(), budget=5)
    assert result.status == "error"
    assert result.error == "RuntimeError: attacker LLM failed"
    assert result.evaluations_spent == 2
    assert result.broke is False


class _FakeTree:
    """Stands in for TreeAttacker: spends the whole budget via evaluate()."""

    name = "tree_attacker"

    def __init__(self):
        self.observations = []

    def search(self, evaluate, budget):
        for i in range(budget):
            self.observations.append(evaluate(f"p{i}"))
        return TreeResult(False, None, budget, budget, 0, None)


def test_tree_campaign_error_counts_as_spent_evaluation():
    tree = _FakeTree()
    adapter = _ScriptedCampaignAdapter({2: TypeError("bad args")})
    result = run_scenario_tree_campaign(adapter, SCENARIOS["helpdesk"], "m", tree, budget=3)
    assert adapter.calls == 3
    assert result.evaluations_spent == 3
    assert result.errors == 1
    errored = tree.observations[1]
    assert errored.grade == 0 and errored.exfiltrated is False
    assert "errored" in errored.final_reply


def test_tree_campaign_search_crash_is_status_error():
    class _Crashing:
        name = "tree_attacker"

        def search(self, evaluate, budget):  # noqa: ARG002
            evaluate("p0")
            raise RuntimeError("attacker LLM failed")

    result = run_scenario_tree_campaign(
        _ScriptedCampaignAdapter({}), SCENARIOS["invoice"], "m", _Crashing(), budget=3,
    )
    assert result.status == "error"
    assert result.evaluations_spent == 1
