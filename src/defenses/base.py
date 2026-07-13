"""Defense interface — wrap mitigations behind one contract.

Defenses sit between the harness and the adapter: they can harden the system
prompt before the agent runs and filter tool calls before execution. The judge
still scores only the normalized trace; defenses affect what the agent does, not
how we measure success.
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
        """Filter or modify tool calls before execution."""
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
