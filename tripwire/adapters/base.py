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
StopReason = Literal["done", "max_turns", "error"]

# (tool_name, args) -> (allowed, message). When not allowed, the adapter must
# substitute `message` for the tool's real result instead of executing it.
ToolCallGuard = Callable[[str, dict[str, Any]], tuple[bool, str]]

# (tool_name, result) -> transformed result. Applied to a tool's real output
# *after* it executes and *before* the model sees it. Used by content-marking
# defenses (e.g. spotlighting fences untrusted tool output in delimiters so
# the model treats it as data, not instructions). Identity when unset.
ToolResultWrapper = Callable[[str, str], str]


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
    # Optional transform applied to a tool's real result before the model sees
    # it (see ToolResultWrapper above). None means "no transform" -- adapters
    # must treat that as identity, not raise. Runs only on results of tools
    # that actually executed, never on a guard's block message.
    tool_result_wrapper: ToolResultWrapper | None = None
    # Optional transform for a system prompt the adapter writes itself. The
    # task's system_prompt is already wrapped by the defense; an adapter that
    # runs a second agent with its own persona (multi_agent's sender) applies
    # this to that persona, so a prompt-level defense reaches every agent and
    # not only the first. None means identity.
    system_prompt_wrapper: Callable[[str], str] | None = None
    # Shared turn budget: the maximum number of model calls an adapter may make
    # in one episode. Every adapter must honor the same number so the
    # orchestration layer is the only thing that varies between adapters. When
    # the budget runs out the adapter returns the partial trace with
    # stop_reason="max_turns" instead of raising.
    max_turns: int = 5


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
    # Why the episode ended: "done" (model produced a final answer),
    # "max_turns" (turn budget exhausted), or "error" (adapter caught an
    # exception after some steps ran; the partial trace is still scored).
    stop_reason: StopReason = "done"


@runtime_checkable
class Adapter(Protocol):
    """Run an agent's tool loop and return a framework-agnostic trace.

    An adapter's ONLY job: translate-in (EpisodeSpec -> framework call) and
    normalize-out (framework events -> NormalizedTrace).
    """

    name: str

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        ...
