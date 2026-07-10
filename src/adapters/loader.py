"""Adapter registry — map adapter name strings to instantiated Adapter objects.

Mirrors src/config/loader.py's resolve_attacks(): a name -> class registry,
looked up by name, raising a clear error on an unknown name.
"""

from __future__ import annotations

import inspect
import os

from openai import OpenAI

from .base import Adapter
from .langgraph_adapter import LangGraphAdapter
from .raw_loop import RawLoopAdapter

ADAPTER_REGISTRY: dict[str, type] = {
    "raw_loop": RawLoopAdapter,
    "langgraph": LangGraphAdapter,
}


def _default_client() -> OpenAI:
    """Shared Groq/OpenAI-compatible client for adapters that take one as a
    constructor arg (currently just RawLoopAdapter -- LangGraphAdapter builds
    its own internally). Built lazily so resolving adapters that don't need
    it doesn't construct one for nothing.
    """
    return OpenAI(
        api_key=os.getenv("GROQ_API_KEY"),
        base_url=os.getenv("GROQ_BASE_URL"),
    )


def resolve_adapters(names: list[str]) -> list[Adapter]:
    """Map adapter name strings to instantiated Adapter objects. Raise on unknown."""
    client: OpenAI | None = None
    adapters: list[Adapter] = []
    for name in names:
        cls = ADAPTER_REGISTRY.get(name)
        if cls is None:
            known = ", ".join(sorted(ADAPTER_REGISTRY))
            raise ValueError(f"Unknown adapter {name!r}. Known: {known}")
        if "client" in inspect.signature(cls.__init__).parameters:
            client = client or _default_client()
            adapters.append(cls(client))
        else:
            adapters.append(cls())
    return adapters
