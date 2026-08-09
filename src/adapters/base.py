"""Adapter contract — the single most important artifact of the project.

Every orchestrator adapter (raw loop, LangGraph, CrewAI, ...) implements this.
The judge and attacks consume ONLY the normalized trace, so they never know
which framework actually ran.

See roadmap Week 1: "Lock the adapter contract".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

StepType = Literal["tool_call", "tool_result", "tool_blocked", "model_output"]

# (tool_name, args) -> (allowed, message). When not allowed, the adapter must
# substitute `message` for the tool's real result instead of executing it.
ToolCallGuard = Callable[[str, dict[str, Any]], tuple[bool, str]]


@dataclass
class EpisodeSpec:
    """Input to an adapter. One episode = one (task, attack, seed)."""

    task: Any
    tools: list[Any]
    model: str
    environment_seed: int
    # Optional per-call enforcement hook (see ToolCallGuard above). None means
    # "no mid-loop enforcement" -- adapters must treat that as always-allowed,
    # not raise. filter_tool_calls (schema-level) and this hook are separate
    # layers: the former decides what's *offered*, this decides what actually
    # *runs*, catching a model that free-forms a call outside its offered menu.
    tool_call_guard: ToolCallGuard | None = None


@dataclass
class TraceStep:
    """One entry in the normalized trace."""

    step: int
    type: StepType
    name: str = ""          # tool name (tool_call / tool_result / tool_blocked)
    args: dict[str, Any] = field(default_factory=dict)
    content: str = ""       # tool_result/tool_blocked payload or model text


@dataclass
class NormalizedTrace:
    """Output of an adapter. Ordered steps + final agent output."""

    steps: list[TraceStep]
    final_output: str


@runtime_checkable
class Adapter(Protocol):
    """Run an agent's tool loop and return a framework-agnostic trace.

    An adapter's ONLY job: translate-in (EpisodeSpec -> framework call) and
    normalize-out (framework events -> NormalizedTrace).
    """

    name: str

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        ...
