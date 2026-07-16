"""Tests for the defense module — Defense protocol, NoDefense, ToolFilter,
and resolve_defenses() in src/config/loader.py.
"""

from __future__ import annotations

import pytest

from src.config.loader import load_config, resolve_defenses
from src.defenses.base import Defense, NoDefense
from src.defenses.tool_filter import ToolFilter

EXAMPLE_CONFIG_PATH = "src/config/threat_model.example.yaml"

READ_INBOX_SCHEMA = {"type": "function", "function": {"name": "read_inbox"}}
SEND_EMAIL_SCHEMA = {"type": "function", "function": {"name": "send_email"}}


# --- NoDefense ---------------------------------------------------------------

def test_no_defense_satisfies_protocol():
    assert isinstance(NoDefense(), Defense)


def test_no_defense_name():
    assert NoDefense().name == "no_defense"


def test_no_defense_wrap_system_prompt_is_passthrough():
    assert NoDefense().wrap_system_prompt("hello") == "hello"


def test_no_defense_filter_tool_calls_is_passthrough():
    tools = [READ_INBOX_SCHEMA, SEND_EMAIL_SCHEMA]
    assert NoDefense().filter_tool_calls(tools) == tools


# --- ToolFilter ----------------------------------------------------------------

def test_tool_filter_satisfies_protocol():
    assert isinstance(ToolFilter(["read_inbox"]), Defense)


def test_tool_filter_name():
    assert ToolFilter(["read_inbox"]).name == "tool_filter"


def test_tool_filter_wrap_system_prompt_is_passthrough():
    assert ToolFilter(["read_inbox"]).wrap_system_prompt("hello") == "hello"


def test_tool_filter_drops_disallowed_dict_schema():
    tf = ToolFilter(["read_inbox"])
    out = tf.filter_tool_calls([READ_INBOX_SCHEMA, SEND_EMAIL_SCHEMA])
    assert [t["function"]["name"] for t in out] == ["read_inbox"]


def test_tool_filter_allows_multiple():
    tf = ToolFilter(["read_inbox", "send_email"])
    out = tf.filter_tool_calls([READ_INBOX_SCHEMA, SEND_EMAIL_SCHEMA])
    assert len(out) == 2


def test_tool_filter_empty_input():
    assert ToolFilter(["read_inbox"]).filter_tool_calls([]) == []


def test_tool_filter_drops_disallowed_runtime_tool_call():
    """Also works on OpenAI-style runtime tool-call objects (.function.name)."""
    call = type("Call", (), {"function": type("F", (), {"name": "send_email"})()})()
    assert ToolFilter(["read_inbox"]).filter_tool_calls([call]) == []


# --- resolve_defenses ---------------------------------------------------------

def test_resolve_none_is_no_defense():
    defenses = resolve_defenses([None], allowed_tools=[])
    assert len(defenses) == 1
    assert isinstance(defenses[0], NoDefense)


def test_resolve_tool_filter():
    defenses = resolve_defenses(["tool_filter"], allowed_tools=["read_inbox"])
    assert len(defenses) == 1
    assert isinstance(defenses[0], ToolFilter)
    assert defenses[0].allowed_tools == ["read_inbox"]


def test_resolve_mixed_list_preserves_order():
    defenses = resolve_defenses([None, "tool_filter"], allowed_tools=["read_inbox"])
    assert isinstance(defenses[0], NoDefense)
    assert isinstance(defenses[1], ToolFilter)


def test_resolve_tool_filter_without_allowed_tools_raises():
    with pytest.raises(ValueError, match="allowed_tools"):
        resolve_defenses(["tool_filter"], allowed_tools=[])


def test_resolve_unknown_name_raises():
    with pytest.raises(ValueError, match="not_a_real_defense"):
        resolve_defenses(["not_a_real_defense"], allowed_tools=[])


# --- load_config() end-to-end on the real example yaml ------------------------

def test_load_config_resolves_defenses_from_example_yaml():
    config = load_config(EXAMPLE_CONFIG_PATH)
    assert [d.name for d in config.defenses] == ["no_defense", "tool_filter"]
    assert config.allowed_tools == ["read_inbox"]


def test_load_config_tool_filter_has_allowed_tools():
    config = load_config(EXAMPLE_CONFIG_PATH)
    tool_filter = next(d for d in config.defenses if d.name == "tool_filter")
    assert tool_filter.allowed_tools == ["read_inbox"]
