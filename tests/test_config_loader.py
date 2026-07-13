"""Tests for the defense registry in src/config/loader.py — resolve_defenses().

Mirrors test_adapter_registry.py: a name -> class registry, looked up by name,
raising a clear error on an unknown name. "tool_filter" additionally needs an
`allowed_tools` list, unlike the zero-arg adapter/attack registries.
"""

from __future__ import annotations

import pytest

from src.config.loader import load_config, resolve_defenses
from src.defenses.base import Defense, NoDefense
from src.defenses.tool_filter import ToolFilter

EXAMPLE_CONFIG_PATH = "src/config/threat_model.example.yaml"


def test_resolves_none_to_no_defense():
    defenses = resolve_defenses([None])
    assert len(defenses) == 1
    assert isinstance(defenses[0], NoDefense)
    assert isinstance(defenses[0], Defense)


def test_resolves_tool_filter_with_allowed_tools():
    defenses = resolve_defenses(["tool_filter"], allowed_tools=["read_inbox"])
    assert len(defenses) == 1
    assert isinstance(defenses[0], ToolFilter)
    assert defenses[0].allowed_tools == ["read_inbox"]


def test_resolves_multiple_names_in_order():
    defenses = resolve_defenses([None, "tool_filter"], allowed_tools=["read_inbox"])
    assert [type(d) for d in defenses] == [NoDefense, ToolFilter]


def test_resolves_empty_list():
    assert resolve_defenses([]) == []


def test_tool_filter_without_allowed_tools_raises():
    with pytest.raises(ValueError, match="allowed_tools"):
        resolve_defenses(["tool_filter"])


def test_tool_filter_with_empty_allowed_tools_raises():
    with pytest.raises(ValueError, match="allowed_tools"):
        resolve_defenses(["tool_filter"], allowed_tools=[])


def test_raises_on_unknown_name():
    with pytest.raises(ValueError, match="Unknown defense 'nonexistent'"):
        resolve_defenses(["nonexistent"])


def test_known_name_after_unknown_name_not_silently_dropped():
    """A bad name anywhere in the list should fail loudly, not just skip it."""
    with pytest.raises(ValueError):
        resolve_defenses(["tool_filter", "nonexistent"], allowed_tools=["read_inbox"])


def test_load_config_parses_allowed_tools_from_example_yaml():
    config = load_config(EXAMPLE_CONFIG_PATH)
    assert config.defenses == ["tool_filter"]
    assert config.allowed_tools == ["read_inbox"]


def test_resolve_defenses_on_example_config():
    config = load_config(EXAMPLE_CONFIG_PATH)
    defenses = resolve_defenses(config.defenses, config.allowed_tools)
    assert len(defenses) == 1
    assert isinstance(defenses[0], ToolFilter)
    assert defenses[0].allowed_tools == ["read_inbox"]
