"""Adapter registry — map adapter name strings to instantiated Adapter objects.

Mirrors tripwire/config/loader.py's resolve_attacks(): a name -> class registry,
looked up by name, raising a clear error on an unknown name.
"""

from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path

from openai import OpenAI

from tripwire.harness.llm import make_client

from .base import Adapter, EpisodeSpec, NormalizedTrace
from .crewai_adapter import CrewAIAdapter
from .langgraph_adapter import LangGraphAdapter
from .multi_agent_adapter import MultiAgentAdapter
from .raw_loop import RawLoopAdapter

# `crewai` needs an optional dependency, but importing and constructing it does
# not (see crewai_adapter.py) -- CrewAI is imported lazily inside run(), so this
# registry stays importable on a core install and a user who lists an adapter
# they haven't installed gets a clear message at run time, not an import error.
ADAPTER_REGISTRY: dict[str, type] = {
    "raw_loop": RawLoopAdapter,
    "langgraph": LangGraphAdapter,
    "multi_agent": MultiAgentAdapter,
    "crewai": CrewAIAdapter,
}


def _default_client() -> OpenAI:
    """Shared OpenAI-compatible client for adapters that take one as a
    constructor arg (currently just RawLoopAdapter -- LangGraphAdapter builds
    its own internally). Provider is chosen by env (see harness.llm.make_client).
    Built lazily so resolving adapters that don't need it doesn't construct one
    for nothing.
    """
    return make_client()


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


def load_agent_module(path: str) -> Adapter:
    """Load a user-supplied "bring your own agent" Python file as an Adapter.

    Runs the same attack suite, environment, judge, and reporting as the
    built-in adapters -- BYO just swaps out what actually executes the tool
    loop, via the same EpisodeSpec/NormalizedTrace contract every adapter in
    this codebase already implements (see tripwire/adapters/base.py). No second,
    simplified interface to document or drift out of sync with the real one.

    The file at `path` must define exactly one of:
      - `adapter`: an object satisfying the Adapter protocol, i.e. it has a
        `.name` and a `.run(spec: EpisodeSpec) -> NormalizedTrace` method.
      - `run(spec: EpisodeSpec) -> NormalizedTrace`: a bare module-level
        function. Wrapped into an ad-hoc adapter named after the file
        (its stem), since a bare function has no natural `.name`.

    Example (examples/byo_agent_example.py) shows the `run()` form.
    """
    module_path = Path(path)
    if not module_path.is_file():
        raise ValueError(f"Agent module not found: {path!r}")

    spec = importlib.util.spec_from_file_location(module_path.stem, module_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Could not load {path!r} as a Python module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if hasattr(module, "adapter"):
        candidate = module.adapter
        if not isinstance(candidate, Adapter):
            raise ValueError(
                f"{path}: `adapter` does not satisfy the Adapter protocol -- "
                f"needs a `.name` (str) and `.run(spec) -> NormalizedTrace`"
            )
        return candidate

    if hasattr(module, "run"):
        run_fn = module.run

        class _BYOAdapter:
            name = module_path.stem

            def run(self, spec: EpisodeSpec) -> NormalizedTrace:
                return run_fn(spec)

        return _BYOAdapter()

    raise ValueError(
        f"{path}: must define either `adapter` (an Adapter-protocol object) "
        f"or `run(spec: EpisodeSpec) -> NormalizedTrace` (a bare function)"
    )
