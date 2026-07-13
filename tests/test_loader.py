"""Tests for src/harness/loader.py."""

from __future__ import annotations

import pytest

from src.defenses.base import NoDefense
from src.defenses.tool_filter import ToolFilter
from src.harness.loader import TripwireConfig, load_config, resolve_defenses

EXAMPLE_CONFIG_PATH = "src/config/threat_model.example.yaml"


def test_load_config_parses_example_yaml():
    config = load_config(EXAMPLE_CONFIG_PATH)
    assert config.models == ["llama-3.3-70b-versatile"]
    assert config.suites == ["workspace"]
    assert config.attacks == ["important_instructions"]
    assert config.defenses == ["tool_filter"]
    assert config.allowed_tools == ["read_email", "search_calendar"]
    assert config.seeds == [0, 1, 2]
    assert config.max_tokens_per_run is None
    assert config.smoke is False


def test_resolve_defenses_on_example_config():
    config = load_config(EXAMPLE_CONFIG_PATH)
    defenses = resolve_defenses(config)
    assert len(defenses) == 1
    assert isinstance(defenses[0], ToolFilter)
    assert defenses[0].allowed_tools == ["read_email", "search_calendar"]


def _base_config(**overrides) -> TripwireConfig:
    defaults = dict(
        models=["m"],
        suites=["workspace"],
        attacks=["important_instructions"],
        defenses=[None],
        seeds=[0],
    )
    defaults.update(overrides)
    return TripwireConfig(**defaults)


def test_resolve_defenses_none_entry_is_no_defense():
    config = _base_config(defenses=[None])
    defenses = resolve_defenses(config)
    assert len(defenses) == 1
    assert isinstance(defenses[0], NoDefense)


def test_resolve_defenses_unknown_name_raises_value_error():
    config = _base_config(defenses=["not_a_real_defense"])
    with pytest.raises(ValueError, match="not_a_real_defense"):
        resolve_defenses(config)


def test_resolve_defenses_tool_filter_without_allowed_tools_raises():
    config = _base_config(defenses=["tool_filter"], allowed_tools=[])
    with pytest.raises(ValueError, match="allowed_tools"):
        resolve_defenses(config)
