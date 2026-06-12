"""Adapter contract — the single most important artifact of the project.

Every orchestrator adapter (raw loop, LangGraph, CrewAI, ...) implements this.
The judge and attacks consume ONLY the normalized trace, so they never know
which framework actually ran.

See roadmap Week 1: "Lock the adapter contract".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

StepType = Literal["tool_call", "tool_result", "model_output"]


@dataclass
class EpisodeSpec:
    """Input to an adapter. One episode = one (task, attack, seed)."""

    task: Any
    tools: list[Any]
    model: str
    environment_seed: int


@dataclass
class TraceStep:
    """One entry in the normalized trace."""

    step: int
    type: StepType
    name: str = ""          # tool name (tool_call / tool_result)
    args: dict[str, Any] = field(default_factory=dict)
    content: str = ""       # tool_result payload or model text


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
