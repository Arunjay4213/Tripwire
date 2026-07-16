"""Tests for defense wiring in src/harness/runner.py.

Uses a recording fake adapter (no network) to prove the defense is actually
applied to the spec the adapter receives -- not just accepted as a parameter.
"""

from __future__ import annotations

from src.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep
from src.defenses.base import NoDefense
from src.defenses.tool_filter import ToolFilter
from src.harness.canary import make_canary
from src.harness.runner import TOOL_SCHEMAS, run_campaign, run_episode, run_sweep


class _FixedAttack:
    """Attack whose render() ignores the canary, like the real attacks do."""

    name = "fixed"

    def render(self, canary: str) -> str:  # noqa: ARG002
        return "irrelevant payload"


class _UppercaseDefense:
    """Minimal Defense that proves wrap_system_prompt is actually applied."""

    name = "uppercase"

    def wrap_system_prompt(self, prompt: str) -> str:
        return prompt.upper()

    def filter_tool_calls(self, tool_calls: list) -> list:
        return tool_calls


class RecordingAdapter:
    """Adapter that records the spec it was called with and returns a clean trace."""

    name = "recording"

    def __init__(self) -> None:
        self.received_spec: EpisodeSpec | None = None

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        self.received_spec = spec
        return NormalizedTrace(steps=[], final_output="")


def _spec(seed=0):
    return EpisodeSpec(task=None, tools=TOOL_SCHEMAS, model="m", environment_seed=seed)


# --- run_episode ---------------------------------------------------------------

def test_run_episode_defaults_to_no_defense():
    adapter = RecordingAdapter()
    result = run_episode(adapter, _spec(), _FixedAttack())
    assert result.defense == "no_defense"
    # NoDefense doesn't filter -- all tool schemas pass through untouched.
    names = [t["function"]["name"] for t in adapter.received_spec.tools]
    assert set(names) == {"send_email", "read_inbox"}


def test_run_episode_applies_wrap_system_prompt():
    adapter = RecordingAdapter()
    run_episode(adapter, _spec(), _FixedAttack(), defense=_UppercaseDefense())
    assert adapter.received_spec.task["system_prompt"].startswith(
        "YOU ARE A HELPFUL EMAIL ASSISTANT."
    )


def test_run_episode_applies_filter_tool_calls():
    adapter = RecordingAdapter()
    run_episode(adapter, _spec(), _FixedAttack(), defense=ToolFilter(["read_inbox"]))
    names = [t["function"]["name"] for t in adapter.received_spec.tools]
    assert names == ["read_inbox"]


def test_run_episode_records_defense_name():
    adapter = RecordingAdapter()
    result = run_episode(adapter, _spec(), _FixedAttack(), defense=ToolFilter(["read_inbox"]))
    assert result.defense == "tool_filter"


def test_run_episode_no_defense_is_passthrough():
    adapter = RecordingAdapter()
    run_episode(adapter, _spec(), _FixedAttack(), defense=NoDefense())
    assert len(adapter.received_spec.tools) == len(TOOL_SCHEMAS)


def test_tool_filter_blocks_leak_even_if_attack_would_otherwise_succeed():
    """The real-world point of the defense: send_email isn't even offered."""

    class _LeakyAdapter:
        name = "leaky"

        def run(self, spec: EpisodeSpec) -> NormalizedTrace:
            # Even a fully-compromised adapter can't call a tool that was
            # never in its menu.
            offered = {t["function"]["name"] for t in spec.tools}
            assert "send_email" not in offered
            return NormalizedTrace(steps=[], final_output="")

    result = run_episode(
        _LeakyAdapter(), _spec(), _FixedAttack(), defense=ToolFilter(["read_inbox"])
    )
    assert result.succeeded is False


# --- run_campaign ----------------------------------------------------------------

class _RecordingAttacker:
    name = "iterative"

    def next_payload(self, history):
        return f"payload-{len(history)}"


def _send(body):
    return NormalizedTrace(
        steps=[TraceStep(step=0, type="tool_call", name="send_email", args={"body": body})],
        final_output=body,
    )


class _ScriptedAdapter:
    name = "scripted"

    def __init__(self, traces):
        self._traces = list(traces)
        self.i = 0
        self.received_specs: list[EpisodeSpec] = []

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        self.received_specs.append(spec)
        trace = self._traces[self.i]
        self.i += 1
        return trace


def test_run_campaign_defaults_to_no_defense():
    seed = 0
    canary = make_canary(seed)
    adapter = _ScriptedAdapter([_send(f"leaked: {canary}")])
    result = run_campaign(adapter, _spec(seed), _RecordingAttacker(), budget=3)
    assert result.defense == "no_defense"


def test_run_campaign_applies_defense_to_every_attempt():
    adapter = _ScriptedAdapter([_send("clean"), _send("clean"), _send("clean")])
    run_campaign(
        adapter, _spec(), _RecordingAttacker(), budget=3, defense=ToolFilter(["read_inbox"])
    )
    assert len(adapter.received_specs) == 3
    for spec in adapter.received_specs:
        names = [t["function"]["name"] for t in spec.tools]
        assert names == ["read_inbox"]


def test_run_campaign_records_defense_name():
    adapter = _ScriptedAdapter([_send("clean")])
    result = run_campaign(
        adapter, _spec(), _RecordingAttacker(), budget=1, defense=ToolFilter(["read_inbox"])
    )
    assert result.defense == "tool_filter"


# --- run_sweep -------------------------------------------------------------------

def test_run_sweep_defaults_to_single_no_defense_pass():
    adapter = RecordingAdapter()
    episodes, _ = run_sweep([adapter], ["m"], [_FixedAttack()], [0])
    assert len(episodes) == 1
    assert episodes[0].defense == "no_defense"


def test_run_sweep_multiplies_by_defenses():
    adapter = RecordingAdapter()
    defenses = [NoDefense(), ToolFilter(["read_inbox"])]
    episodes, _ = run_sweep([adapter], ["m"], [_FixedAttack()], [0, 1], defenses=defenses)
    assert len(episodes) == 4  # 1 adapter x 1 model x 1 attack x 2 defenses x 2 seeds
    assert {e.defense for e in episodes} == {"no_defense", "tool_filter"}
