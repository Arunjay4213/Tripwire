"""Per-episode cost accounting and the sweep's token cap.

A paid sweep needs two things the results did not carry: what each episode
cost (so a defense's cost can be reported, not guessed) and a hard stop on
spend. The provider's usage fields are the source; everything must tolerate
test doubles that carry none.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from tests.scripted_client import ScriptedClient, message, tool_call
from tripwire.adapters._common import Usage
from tripwire.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep
from tripwire.adapters.langgraph_adapter import LangGraphAdapter
from tripwire.adapters.multi_agent_adapter import MultiAgentAdapter
from tripwire.adapters.raw_loop import RawLoopAdapter
from tripwire.defenses.outbound_guard import OutboundGuard
from tripwire.defenses.stack import DefenseStack
from tripwire.defenses.spotlighting import Spotlighting
from tripwire.harness.runner import TOOL_SCHEMAS, run_episode, run_sweep
from tripwire.scenarios import SCENARIOS


class _UsageClient(ScriptedClient):
    """ScriptedClient whose responses carry usage and a served model id."""

    def _create(self, **kwargs):
        response = super()._create(**kwargs)
        response.usage = SimpleNamespace(prompt_tokens=100, completion_tokens=10)
        response.model = "m-served-2026"
        return response


def _read_then_send():
    return [
        message(None, [tool_call("c1", "read_inbox", "{}")]),
        message(None, [tool_call("c2", "send_email", '{"to": "accounting@corp.com", "body": "Total $2,480.00"}')]),
        message("Done."),
    ]


def _spec():
    return EpisodeSpec(
        task={"system_prompt": "p", "user_message": "Forward the total to accounting@corp.com.",
              "tool_impls": {"read_inbox": lambda **_: "Invoice total $2,480.00", "send_email": lambda **_: "sent"}},
        tools=[{"type": "function", "function": {"name": n, "parameters": {"type": "object", "properties": {}}}}
               for n in ("read_inbox", "send_email")],
        model="m", environment_seed=0,
    )


def test_usage_tolerates_responses_without_usage_or_model():
    u = Usage()
    u.record(SimpleNamespace(choices=[]))
    assert u.fields() == {"prompt_tokens": 0, "completion_tokens": 0, "model_calls": 1, "served_model": ""}


def test_single_agent_adapters_record_calls_tokens_and_the_served_model():
    for make in (lambda c: RawLoopAdapter(c), lambda c: LangGraphAdapter(client=c)):
        trace = make(_UsageClient(script=_read_then_send())).run(_spec())
        assert trace.model_calls == 3
        assert (trace.prompt_tokens, trace.completion_tokens) == (300, 30)
        assert trace.served_model == "m-served-2026"


def test_relay_records_both_agents_calls():
    script = [
        message(None, [tool_call("a1", "read_inbox", "{}")]),
        message("Summary: total $2,480.00, send to accounting@corp.com"),
        message(None, [tool_call("b1", "send_email", '{"to": "accounting@corp.com", "body": "$2,480.00"}')]),
        message("Done."),
    ]
    trace = MultiAgentAdapter(client=_UsageClient(script=script)).run(_spec())
    assert trace.model_calls == 4 and trace.prompt_tokens == 400


def test_run_episode_records_the_defenses_own_calls_and_tokens_per_episode():
    guard = OutboundGuard(detector=lambda _t: False)  # injected detector: a call, no model tokens
    guard.tokens = 7  # pretend an earlier episode spent these; only the delta may be charged here

    class _CallsGuard:
        name = "calls_guard"

        def run(self, spec):
            spec.tool_call_guard("send_email", {"to": "accounting@corp.com", "body": "x"})
            return NormalizedTrace(steps=[TraceStep(step=0, type="tool_call", name="send_email",
                                                    args={"to": "accounting@corp.com", "body": "x"})],
                                   final_output="", prompt_tokens=50, completion_tokens=5, model_calls=2,
                                   served_model="m-v1")

    class _Attack:
        name = "fixed"

        def render(self, canary, ctx=None):
            return "p"

    result = run_episode(_CallsGuard(), EpisodeSpec(task=None, tools=TOOL_SCHEMAS, model="m", environment_seed=0),
                         _Attack(), defense=guard, scenario=SCENARIOS["invoice"])
    assert (result.prompt_tokens, result.completion_tokens, result.model_calls) == (50, 5, 2)
    assert result.defense_calls == 1 and result.defense_tokens == 0
    assert result.served_model == "m-v1"


def test_a_stack_sums_its_members_calls_and_tokens():
    a, b = OutboundGuard(detector=lambda _t: False), OutboundGuard(detector=lambda _t: False)
    a.tokens, b.tokens = 3, 4
    stack = DefenseStack([Spotlighting(), a])
    assert stack.tokens == 3
    stack.check_tool_call("send_email", {"to": "x@corp.com", "body": "y"})
    assert stack.calls == 1


# --- the cap ------------------------------------------------------------------------

class _Costly:
    """Every episode reports 100 prompt tokens and takes a moment, so a
    parallel sweep has cells in flight when the cap trips."""

    name = "costly"

    def run(self, spec):
        time.sleep(0.1)
        return NormalizedTrace(steps=[], final_output="", prompt_tokens=100, model_calls=1)


class _Static:
    name = "static"

    def render(self, canary, ctx=None):
        return "p"


def _ten_cells(**kw):
    scenarios = list(SCENARIOS.values())
    return run_sweep([_Costly()], ["m"], [_Static()], [0], defenses=None,
                     scenarios=scenarios + scenarios[:1] * 6, **kw)  # 10 cells of 1 seed, 100 tokens each


def test_no_cap_runs_every_cell_and_results_carry_tokens(capsys):
    episodes, _ = _ten_cells()
    assert len(episodes) == 10 and all(e.prompt_tokens == 100 for e in episodes)
    assert "token cap" not in capsys.readouterr().err


def test_cap_stops_a_serial_sweep_exactly_at_the_cell_that_reaches_it(capsys):
    episodes, _ = _ten_cells(max_tokens=250)
    assert len(episodes) == 3  # 100, 200, 300 >= 250: the fourth cell is never started
    assert "token cap reached" in capsys.readouterr().err.replace("\n", " ")


def test_cap_stops_a_parallel_sweep_with_at_most_the_cells_in_flight_overshooting(capsys):
    """Two workers, ten slow cells, cap 150: the first two cells complete
    together and trip the cap; a worker may already have picked up the next
    queued cell, so at most two more run. Everything still queued is cancelled
    and reported."""
    episodes, _ = _ten_cells(max_tokens=150, concurrency=2)
    err = capsys.readouterr().err
    assert 2 <= len(episodes) <= 4, len(episodes)
    assert "token cap reached" in err and f"{10 - len(episodes)} of 10 cells were NOT run" in err
