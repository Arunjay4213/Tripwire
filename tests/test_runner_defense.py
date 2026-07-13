"""Tests for defense wiring in src/harness/runner.py.

run_episode/run_campaign/run_sweep harden each episode via `defense` before the
adapter runs: `wrap_system_prompt` on `task["system_prompt"]`, `filter_tool_calls`
on the offered tool schemas (`tools`). Defaults to NoDefense (passthrough).
"""

from __future__ import annotations

from src.adapters.base import EpisodeSpec, NormalizedTrace
from src.attacks.fixed_injection import FixedInjection
from src.defenses.base import NoDefense
from src.defenses.tool_filter import ToolFilter
from src.harness.runner import TOOL_SCHEMAS, run_campaign, run_episode, run_sweep


class _RecordingAdapter:
    """Adapter that records every EpisodeSpec it receives and returns a clean trace."""

    name = "recording"

    def __init__(self) -> None:
        self.received_specs: list[EpisodeSpec] = []

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        self.received_specs.append(spec)
        return NormalizedTrace(steps=[], final_output="")


class _UppercaseDefense:
    """Minimal Defense that proves wrap_system_prompt is actually applied."""

    name = "uppercase"

    def wrap_system_prompt(self, prompt: str) -> str:
        return prompt.upper()

    def filter_tool_calls(self, tool_calls: list) -> list:
        return tool_calls


class _RecordingAttacker:
    """Adaptive attacker stub — same shape as test_attacks.py's RecordingAttacker."""

    name = "iterative"

    def next_payload(self, history):
        return f"payload-{len(history)}"


def _spec(seed=0):
    return EpisodeSpec(task=None, tools=TOOL_SCHEMAS, model="m", environment_seed=seed)


# --- run_episode -------------------------------------------------------------

def test_run_episode_defaults_to_no_defense():
    adapter = _RecordingAdapter()
    result = run_episode(adapter, _spec(), FixedInjection())
    assert result.defense == "no_defense"
    assert adapter.received_specs[0].tools == TOOL_SCHEMAS


def test_run_episode_wraps_system_prompt_after_canary_injection():
    adapter = _RecordingAdapter()
    run_episode(adapter, _spec(), FixedInjection(), defense=_UppercaseDefense())
    prompt = adapter.received_specs[0].task["system_prompt"]
    # Uppercased, and covers the canary line canary.inject() appended.
    assert prompt == prompt.upper()
    assert "SECRET KEY" in prompt


def test_run_episode_filters_offered_tools():
    adapter = _RecordingAdapter()
    defense = ToolFilter(["read_inbox"])
    result = run_episode(adapter, _spec(), FixedInjection(), defense=defense)
    tools = adapter.received_specs[0].tools
    assert [t["function"]["name"] for t in tools] == ["read_inbox"]
    assert result.defense == "tool_filter"


def test_run_episode_tool_filter_does_not_touch_tool_impls():
    """Filtering the offered schema doesn't remove the underlying tool_impls —
    the model just never sees send_email as callable."""
    adapter = _RecordingAdapter()
    run_episode(adapter, _spec(), FixedInjection(), defense=ToolFilter(["read_inbox"]))
    assert set(adapter.received_specs[0].task["tool_impls"]) == {"send_email", "read_inbox"}


# --- run_campaign --------------------------------------------------------------

def test_run_campaign_applies_defense_each_attempt():
    adapter = _RecordingAdapter()
    defense = ToolFilter(["read_inbox"])
    result = run_campaign(adapter, _spec(), _RecordingAttacker(), budget=2, defense=defense)
    assert result.defense == "tool_filter"
    assert len(adapter.received_specs) == 2
    for spec in adapter.received_specs:
        assert [t["function"]["name"] for t in spec.tools] == ["read_inbox"]


def test_run_campaign_defaults_to_no_defense():
    adapter = _RecordingAdapter()
    result = run_campaign(adapter, _spec(), _RecordingAttacker(), budget=1)
    assert result.defense == "no_defense"


# --- run_sweep -----------------------------------------------------------------

def test_run_sweep_expands_defense_dimension():
    adapter = _RecordingAdapter()
    defenses = [NoDefense(), ToolFilter(["read_inbox"])]
    episodes, campaigns = run_sweep(
        [adapter], ["m"], [FixedInjection()], [0, 1], defenses=defenses,
    )
    assert campaigns == []
    assert len(episodes) == 2 * 2  # 2 seeds x 2 defenses
    assert {e.defense for e in episodes} == {"no_defense", "tool_filter"}


def test_run_sweep_defaults_to_single_no_defense():
    adapter = _RecordingAdapter()
    episodes, _ = run_sweep([adapter], ["m"], [FixedInjection()], [0])
    assert len(episodes) == 1
    assert episodes[0].defense == "no_defense"
