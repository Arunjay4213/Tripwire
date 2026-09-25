"""Tests for the adapter registry — resolve_adapters().

Mirrors resolve_attacks() in tripwire/config/loader.py: a name -> class registry,
looked up by name, raising a clear error on an unknown name.
"""

from __future__ import annotations

import pytest

from tripwire.adapters.base import Adapter
from tripwire.adapters.langgraph_adapter import LangGraphAdapter
from tripwire.adapters.loader import ADAPTER_REGISTRY, resolve_adapters
from tripwire.adapters.multi_agent_adapter import MultiAgentAdapter
from tripwire.adapters.raw_loop import RawLoopAdapter


def test_registry_contains_known_adapters():
    assert set(ADAPTER_REGISTRY) == {"raw_loop", "langgraph", "multi_agent"}


def test_resolves_raw_loop():
    adapters = resolve_adapters(["raw_loop"])
    assert len(adapters) == 1
    assert isinstance(adapters[0], RawLoopAdapter)
    assert isinstance(adapters[0], Adapter)
    assert adapters[0].name == "raw_loop"


def test_resolves_langgraph():
    adapters = resolve_adapters(["langgraph"])
    assert len(adapters) == 1
    assert isinstance(adapters[0], LangGraphAdapter)
    assert isinstance(adapters[0], Adapter)
    assert adapters[0].name == "langgraph"


def test_resolves_multi_agent():
    adapters = resolve_adapters(["multi_agent"])
    assert len(adapters) == 1
    assert isinstance(adapters[0], MultiAgentAdapter)
    assert isinstance(adapters[0], Adapter)
    assert adapters[0].name == "multi_agent"


def test_resolves_multiple_names_in_order():
    adapters = resolve_adapters(["raw_loop", "langgraph"])
    assert [type(a) for a in adapters] == [RawLoopAdapter, LangGraphAdapter]


def test_resolves_empty_list():
    assert resolve_adapters([]) == []


def test_raises_on_unknown_name():
    with pytest.raises(ValueError, match="Unknown adapter 'nonexistent'"):
        resolve_adapters(["nonexistent"])


def test_unknown_name_error_lists_known_adapters():
    with pytest.raises(ValueError, match="raw_loop"):
        resolve_adapters(["bogus"])


def test_known_name_after_unknown_name_not_silently_dropped():
    """A bad name anywhere in the list should fail loudly, not just skip it."""
    with pytest.raises(ValueError):
        resolve_adapters(["raw_loop", "nonexistent"])


def test_unknown_name_suggests_closest_adapter():
    with pytest.raises(ValueError, match="Did you mean 'langgraph'"):
        resolve_adapters(["langgrph"])
