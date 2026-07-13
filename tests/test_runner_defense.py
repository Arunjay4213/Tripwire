"""Tests for defense wiring in src/harness/runner.py."""

from __future__ import annotations

import pytest

from src.adapters.base import EpisodeSpec, NormalizedTrace
from src.defenses.base import NoDefense
from src.defenses.tool_filter import ToolFilter
from src.harness.runner import run_episode


class _FakeAdapter:
    name = "fake"

    def __init__(self) -> None:
        self.received_spec: EpisodeSpec | None = None

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        self.received_spec = spec
        return NormalizedTrace(steps=[], final_output="")


class _UppercaseDefense:
    """Minimal Defense that proves wrap_system_prompt is actually applied."""

    name = "uppercase"

    def wrap_system_prompt(self, prompt: str) -> str:
        return prompt.upper()

    def filter_tool_calls(self, tool_calls: list) -> list:
        return tool_calls


def _make_spec() -> EpisodeSpec:
    return EpisodeSpec(
        task="summarize my inbox",
        tools=[{"name": "read_email"}, {"name": "send_email"}],
        model="llama-3.3-70b-versatile",
        environment_seed=0,
    )


def test_run_episode_defaults_to_no_defense():
    adapter = _FakeAdapter()
    spec = _make_spec()
    with pytest.raises(NotImplementedError):
        run_episode(adapter, spec, "important_instructions")
    assert adapter.received_spec.task == spec.task
    assert adapter.received_spec.tools == spec.tools


def test_run_episode_applies_wrap_system_prompt():
    adapter = _FakeAdapter()
    spec = _make_spec()
    with pytest.raises(NotImplementedError):
        run_episode(adapter, spec, "important_instructions", defense=_UppercaseDefense())
    assert adapter.received_spec.task == "SUMMARIZE MY INBOX"


def test_run_episode_applies_filter_tool_calls():
    adapter = _FakeAdapter()
    spec = _make_spec()
    defense = ToolFilter(["read_email"])
    with pytest.raises(NotImplementedError):
        run_episode(adapter, spec, "important_instructions", defense=defense)
    assert adapter.received_spec.tools == [{"name": "read_email"}]


def test_run_episode_no_defense_is_passthrough():
    adapter = _FakeAdapter()
    spec = _make_spec()
    with pytest.raises(NotImplementedError):
        run_episode(adapter, spec, "important_instructions", defense=NoDefense())
    assert adapter.received_spec.tools == spec.tools
