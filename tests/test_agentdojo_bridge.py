"""Offline tests for the AgentDojo bridge.

No LLM and no network: get_suite loads bundled benchmark data, environments are
plain pydantic objects, and the tools run locally against them. We build the
episode spec directly and script a tool call to prove the wiring -- schema
conversion, tool binding to a live env, defense hooks, and AgentDojo's own
scoring -- without any model in the loop.
"""

from __future__ import annotations

import pytest
from agentdojo.attacks.base_attacks import MODEL_NAMES

from tripwire.adapters.base import NormalizedTrace
from tripwire.defenses.base import NoDefense
from tripwire.defenses.prompt_hardening import PromptHardening
from tripwire.defenses.spotlighting import OPEN_DELIMITER, Spotlighting
from tripwire.environments.agentdojo_bridge import (
    AGENTDOJO_SYSTEM_PROMPT,
    AgentDojoEpisode,
    _agentdojo_model_name,
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
    from tripwire.defenses.tool_filter import ToolFilter

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


# --- model-name mapping (so important_instructions never crashes) ------------
# AgentDojo's important_instructions attack resolves {model} by matching a
# MODEL_NAMES key as a substring of the pipeline name. A current id like
# "claude-haiku-4-5" contains no listed key, so the bridge maps every provider
# to a name that DOES contain a key. This regression-guards that mapping.

def _resolves(name: str) -> bool:
    return any(key in name for key in MODEL_NAMES)


@pytest.mark.parametrize("model_id, expected_friendly", [
    ("claude-haiku-4-5", "Claude"),
    ("claude-opus-4-8", "Claude"),
    ("gpt-4o-mini", "GPT-4"),
    ("gemini-2.0-flash", "AI model developed by Google"),
    ("llama-3.3-70b-versatile", "AI assistant"),
    ("some-unknown-model-xyz", "Local model"),
])
def test_agentdojo_model_name_resolves_for_every_provider(model_id, expected_friendly):
    name = _agentdojo_model_name(model_id)
    assert _resolves(name), f"{model_id!r} -> {name!r} matches no MODEL_NAMES key"
    friendly = next(MODEL_NAMES[k] for k in MODEL_NAMES if k in name)
    assert friendly == expected_friendly
