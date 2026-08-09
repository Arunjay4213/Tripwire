"""Defense interface — wrap mitigations behind one contract.

Defenses sit between the harness and the adapter, at two enforcement points:

- wrap_system_prompt / filter_tool_calls run once, before the agent's tool
  loop starts -- they decide what's offered (the system prompt, the tool
  menu).
- check_tool_call runs mid-loop, once per tool call the model actually makes
  -- it decides what's allowed to *run*. This is what catches a model that
  free-forms a call outside its offered menu (a real, observed failure mode),
  and what a content-inspecting defense (e.g. "block outputs that look like a
  secret") would need -- filtering the menu upfront can't do that.

The judge still scores only the normalized trace; defenses affect what the
agent does, not how we measure success.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Defense(Protocol):
    """Mitigation applied during an episode before/during the agent tool loop."""

    @property
    def name(self) -> str:
        """Stable identifier for configs, results, and ASR tables."""
        ...

    def wrap_system_prompt(self, prompt: str) -> str:
        """Modify the system prompt before the agent runs."""
        ...

    def filter_tool_calls(self, tool_calls: list[Any]) -> list[Any]:
        """Filter or modify tool definitions before the agent runs."""
        ...

    def check_tool_call(self, name: str, args: dict[str, Any]) -> tuple[bool, str]:
        """Approve or block one actual tool call, mid-loop.

        Returns (allowed, message). When not allowed, `message` replaces the
        tool's real result -- the adapter must not execute the tool.
        """
        ...


class NoDefense:
    """Default defense — passthrough when no mitigation is configured."""

    @property
    def name(self) -> str:
        return "no_defense"

    def wrap_system_prompt(self, prompt: str) -> str:
        return prompt

    def filter_tool_calls(self, tool_calls: list[Any]) -> list[Any]:
        return tool_calls

    def check_tool_call(self, name: str, args: dict[str, Any]) -> tuple[bool, str]:
        return True, ""
