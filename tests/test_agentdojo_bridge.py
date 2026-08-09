"""Offline tests for the AgentDojo bridge.

No LLM and no network: get_suite loads bundled benchmark data, environments are
plain pydantic objects, and the tools run locally against them. We drive the
bridge with a fake adapter and a scripted tool call to prove the wiring --
schema conversion, tool binding to a live env, defense hooks, and AgentDojo's
own scoring -- without any model in the loop.
"""

from __future__ import annotations

from src.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep
from src.defenses.base import NoDefense
from src.defenses.prompt_hardening import PromptHardening
from src.defenses.spotlighting import OPEN_DELIMITER, Spotlighting
from src.environments.agentdojo_bridge import (
    AGENTDOJO_SYSTEM_PROMPT,
    AgentDojoEpisode,
    run_agentdojo_episode,
)

# A fixed, known-present workspace pairing (see the suite's task ids).
USER_TASK = "user_task_0"
INJECTION_TASK = "injection_task_0"
MODEL = "test-model"


def _episode():
    return AgentDojoEpisode(USER_TASK, INJECTION_TASK, "direct", MODEL)


def test_build_spec_uses_real_task_prompt_and_tools():
    ep = _episode()
    spec = ep.build_spec(NoDefense(), seed=0)
    # The user message is the real AgentDojo task prompt, not a scripted one.
    assert spec.task["user_message"] == ep.user_task.PROMPT
    assert spec.task["user_message"]  # non-empty
    # The full AgentDojo workspace toolset is offered (2 dozen tools).
    names = [t["function"]["name"] for t in spec.tools]
    assert "send_email" in names
    assert len(names) > 10


def test_no_defense_system_prompt_is_base():
    spec = _episode().build_spec(NoDefense(), seed=0)
    assert spec.task["system_prompt"] == AGENTDOJO_SYSTEM_PROMPT


def test_prompt_hardening_wraps_system_prompt():
    spec = _episode().build_spec(PromptHardening(), seed=0)
    assert spec.task["system_prompt"].startswith(AGENTDOJO_SYSTEM_PROMPT)
    assert "UNTRUSTED" in spec.task["system_prompt"]


def test_spotlighting_wraps_tool_result_against_live_env():
    ep = _episode()
    spec = ep.build_spec(Spotlighting(), seed=0)
    # A read tool executes against the real environment and its output is
    # fenced by spotlighting before the (hypothetical) model would see it.
    name = next(n for n in spec.task["tool_impls"] if n.startswith(("get_", "search_", "read_")))
    raw = spec.task["tool_impls"][name]()  # no-arg-friendly read tool
    fenced = spec.tool_result_wrapper(name, raw)
    assert fenced.startswith(OPEN_DELIMITER)
    assert ep._calls, "the tool call should have been captured for scoring"


def test_tool_filter_offered_menu_can_be_restricted():
    from src.defenses.tool_filter import ToolFilter

    ep = _episode()
    # tool_filter allowlists by name; point it at real AgentDojo tool names.
    spec = ep.build_spec(ToolFilter(["get_day_calendar_events"]), seed=0)
    names = [t["function"]["name"] for t in spec.tools]
    assert names == ["get_day_calendar_events"]
    # And the mid-loop guard blocks a tool it never offered.
    allowed, msg = spec.tool_call_guard("send_email", {"recipients": ["x@evil.com"]})
    assert allowed is False


def test_score_returns_two_bools_on_empty_run():
    """A run that called no tools completes neither the task nor the attack."""
    ep = _episode()
    ep.build_spec(NoDefense(), seed=0)
    trace = NormalizedTrace(steps=[], final_output="I could not help with that.")
    succeeded, completed = ep.score(trace)
    assert succeeded is False
    assert completed is False


class _NoToolAdapter:
    """Adapter that calls nothing and returns a clean refusal trace."""

    name = "notool"

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        return NormalizedTrace(
            steps=[TraceStep(step=0, type="model_output", content="done")],
            final_output="done",
        )


def test_run_agentdojo_episode_end_to_end_offline():
    result = run_agentdojo_episode(
        _NoToolAdapter(), USER_TASK, INJECTION_TASK, "direct", MODEL,
        defense=NoDefense(), seed=1,
    )
    assert result.adapter == "notool"
    assert result.attack == "direct"
    assert result.defense == "no_defense"
    assert result.seed == 1
    # No tools called -> neither the injection nor the real task succeeded.
    assert result.succeeded is False
    assert result.task_completed is False
