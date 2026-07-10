"""Tests for the adapter registry — resolve_adapters().

Mirrors resolve_attacks() in src/config/loader.py: a name -> class registry,
looked up by name, raising a clear error on an unknown name.
"""

from __future__ import annotations

import pytest

from src.adapters.base import Adapter
from src.adapters.langgraph_adapter import LangGraphAdapter
from src.adapters.loader import ADAPTER_REGISTRY, resolve_adapters
from src.adapters.raw_loop import RawLoopAdapter


@pytest.fixture(autouse=True)
def _fake_groq_env(monkeypatch):
    """resolve_adapters() constructs a real (but unused) OpenAI client for
    adapters that take one -- that doesn't hit the network, but does need
    *some* api_key/base_url set. Stub them so these tests don't depend on a
    real .env file being present."""
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("GROQ_BASE_URL", "https://example.invalid/v1")


def test_registry_contains_known_adapters():
    assert set(ADAPTER_REGISTRY) == {"raw_loop", "langgraph"}


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
