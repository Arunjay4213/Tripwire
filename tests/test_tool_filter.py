"""Tests for src/defenses/tool_filter.py."""

from __future__ import annotations

from src.defenses.base import Defense
from src.defenses.tool_filter import ToolFilter


class _FakeFunction:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeToolCall:
    """Mimics an OpenAI-style ChatCompletionMessageToolCall."""

    def __init__(self, name: str) -> None:
        self.function = _FakeFunction(name)


class _FakeToolDef:
    """Mimics a plain tool-definition object with a bare `.name`."""

    def __init__(self, name: str) -> None:
        self.name = name


def test_tool_filter_satisfies_defense_protocol():
    assert isinstance(ToolFilter(["read_email"]), Defense)


def test_name_is_tool_filter():
    assert ToolFilter(["read_email"]).name == "tool_filter"


def test_wrap_system_prompt_is_passthrough():
    tf = ToolFilter(["read_email"])
    assert tf.wrap_system_prompt("You are a helpful assistant.") == "You are a helpful assistant."


def test_filter_tool_calls_drops_disallowed_openai_style_calls():
    tf = ToolFilter(["read_email"])
    calls = [_FakeToolCall("read_email"), _FakeToolCall("send_email")]
    out = tf.filter_tool_calls(calls)
    assert [c.function.name for c in out] == ["read_email"]


def test_filter_tool_calls_drops_disallowed_tool_definitions():
    tf = ToolFilter(["read_email"])
    tools = [_FakeToolDef("read_email"), _FakeToolDef("send_email")]
    out = tf.filter_tool_calls(tools)
    assert [t.name for t in out] == ["read_email"]


def test_filter_tool_calls_drops_disallowed_dict_schema():
    tf = ToolFilter(["read_email"])
    tools = [
        {"type": "function", "function": {"name": "read_email"}},
        {"type": "function", "function": {"name": "send_email"}},
    ]
    out = tf.filter_tool_calls(tools)
    assert [t["function"]["name"] for t in out] == ["read_email"]


def test_filter_tool_calls_empty_list():
    assert ToolFilter(["read_email"]).filter_tool_calls([]) == []
