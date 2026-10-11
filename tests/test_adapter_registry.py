"""Tests for the adapter registry — resolve_adapters().

Mirrors resolve_attacks() in tripwire/config/loader.py: a name -> class registry,
looked up by name, raising a clear error on an unknown name.
"""

from __future__ import annotations

import pytest

from tripwire.adapters.base import Adapter
from tripwire.adapters.langgraph_adapter import LangGraphAdapter
from tripwire.adapters.loader import resolve_adapters
from tripwire.adapters.raw_loop import RawLoopAdapter


def test_resolves_raw_loop():
    adapters = resolve_adapters(["raw_loop"])
    assert len(adapters) == 1
    assert isinstance(adapters[0], RawLoopAdapter)
    assert isinstance(adapters[0], Adapter)
    assert adapters[0].name == "raw_loop"


def test_resolves_multiple_names_in_order():
    adapters = resolve_adapters(["raw_loop", "langgraph"])
    assert [type(a) for a in adapters] == [RawLoopAdapter, LangGraphAdapter]


def test_known_name_after_unknown_name_not_silently_dropped():
    """A bad name anywhere in the list should fail loudly, not just skip it."""
    with pytest.raises(ValueError):
        resolve_adapters(["raw_loop", "nonexistent"])


def test_unknown_name_suggests_closest_adapter():
    with pytest.raises(ValueError, match="Did you mean 'langgraph'"):
        resolve_adapters(["langgrph"])
