"""Adapter registry — map adapter name strings to instantiated Adapter objects.

Mirrors tripwire/config/loader.py's resolve_attacks(): a name -> class registry,
looked up by name, raising a clear error on an unknown name.
"""

from __future__ import annotations

import dataclasses
import difflib
import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Any

from openai import OpenAI

from tripwire.harness.llm import make_client

from .base import Adapter, EpisodeSpec, NormalizedTrace, ToolCallGuard, ToolResultWrapper
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
            close = difflib.get_close_matches(name, list(ADAPTER_REGISTRY), n=1) if isinstance(name, str) else []
            hint = f" Did you mean {close[0]!r}?" if close else ""
            raise ValueError(f"Unknown adapter {name!r}.{hint} Known: {known}")
        if "client" in inspect.signature(cls.__init__).parameters:
            client = client or _default_client()
            adapters.append(cls(client))
        else:
            adapters.append(cls())
    return adapters


def _defense_name(guard: ToolCallGuard) -> str | None:
    """The name of the defense a guard belongs to, when it is a bound method
    of a Defense (which is how Scenario.build_spec passes it)."""
    owner = getattr(guard, "__self__", None)
    name = getattr(owner, "name", None)
    return name if isinstance(name, str) else None


class HookAuditingAdapter:
    """Wraps a bring-your-own adapter and records whether it used the defense hooks.

    Defenses reach an adapter only through spec.tools, spec.tool_call_guard
    and spec.tool_result_wrapper. The built-in adapters honor all three, but a
    BYO agent can ignore the hooks, and then an "outbound_guard" row is really
    an undefended run. The judge reads only the trace, so it cannot see this.
    This wrapper passes counting closures in place of the two hooks, records
    which ones were called in `last_hooks_called` after every run, and prints
    a warning (once per defense) when the trace has tool calls but the guard
    was never consulted. It satisfies the same Adapter protocol as the agent.
    """

    def __init__(self, inner: Adapter) -> None:
        self.inner = inner
        self.name: str = inner.name
        self.last_hooks_called: dict[str, bool] = {"guard": False, "wrapper": False}
        self._warned_defenses: set[str | None] = set()

    def __getattr__(self, attr: str) -> Any:
        # Only reached for attributes not set in __init__: expose the agent's
        # own. Guard `inner` itself so copy/pickle cannot recurse forever.
        if attr == "inner":
            raise AttributeError(attr)
        return getattr(self.inner, attr)

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        called = {"guard": False, "wrapper": False}
        guard = spec.tool_call_guard
        wrapper = spec.tool_result_wrapper

        counting_guard: ToolCallGuard | None = None
        if guard is not None:
            def counting_guard(name: str, args: dict[str, Any]) -> tuple[bool, str]:
                called["guard"] = True
                return guard(name, args)

        counting_wrapper: ToolResultWrapper | None = None
        if wrapper is not None:
            def counting_wrapper(name: str, result: str) -> str:
                called["wrapper"] = True
                return wrapper(name, result)

        audited = dataclasses.replace(
            spec, tool_call_guard=counting_guard, tool_result_wrapper=counting_wrapper
        )
        trace = self.inner.run(audited)
        self.last_hooks_called = called

        if guard is not None and not called["guard"]:
            steps = getattr(trace, "steps", None) or []
            has_tool_calls = any(getattr(s, "type", None) == "tool_call" for s in steps)
            defense = _defense_name(guard)
            # Under no_defense the guard always allows, so skipping it changes
            # nothing; only warn where it would change the measurement.
            if has_tool_calls and defense != "no_defense" and defense not in self._warned_defenses:
                self._warned_defenses.add(defense)
                label = defense or "the configured defense"
                print(
                    f"Warning: agent {self.name!r} made tool calls but never called "
                    f"spec.tool_call_guard, so {label} was not enforced; its results for "
                    f"this agent are not meaningful. Call spec.tool_call_guard(name, args) "
                    f"before running each tool (see examples/byo_agent_example.py).",
                    file=sys.stderr,
                )
        return trace


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

    The result is wrapped in a HookAuditingAdapter, which keeps the agent's
    name and records whether it honored the defense hooks.

    Example (examples/byo_agent_example.py) shows the `run()` form.
    """
    module_path = Path(path)
    if not module_path.is_file():
        raise ValueError(f"Agent module not found: {path!r}")

    # The module must be in sys.modules while it executes: dataclasses (and
    # typing.get_type_hints, pydantic) look up sys.modules[cls.__module__] to
    # resolve string annotations, so `from __future__ import annotations` plus
    # an @dataclass would otherwise crash. The prefix keeps the name from
    # shadowing a real module such as `agent` or `run`.
    module_name = f"tripwire_byo_{module_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Could not load {path!r} as a Python module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise

    if hasattr(module, "adapter"):
        candidate = module.adapter
        if inspect.isclass(candidate):
            raise ValueError(
                f"{path}: `adapter` is a class; instantiate it, e.g. "
                f"`adapter = {candidate.__name__}()`"
            )
        if not isinstance(candidate, Adapter):
            raise ValueError(
                f"{path}: `adapter` does not satisfy the Adapter protocol -- "
                f"needs a `.name` (str) and `.run(spec) -> NormalizedTrace`"
            )
        return HookAuditingAdapter(candidate)

    if hasattr(module, "run"):
        run_fn = module.run
        if not callable(run_fn):
            raise ValueError(f"{path}: `run` must be a function `run(spec) -> NormalizedTrace`")

        class _BYOAdapter:
            name = module_path.stem

            def run(self, spec: EpisodeSpec) -> NormalizedTrace:
                return run_fn(spec)

        return HookAuditingAdapter(_BYOAdapter())

    raise ValueError(
        f"{path}: must define either `adapter` (an Adapter-protocol object) "
        f"or `run(spec: EpisodeSpec) -> NormalizedTrace` (a bare function)"
    )
