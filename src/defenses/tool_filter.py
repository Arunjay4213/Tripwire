"""Tool filter defense — restrict the agent to an allowlist of tool names."""

from __future__ import annotations

from typing import Any


def _tool_name(entry: Any) -> str:
    """Extract a name from either a generated tool call or a tool definition.

    `filter_tool_calls` is applied both to runtime tool-call objects (OpenAI-style,
    name at `entry.function.name`) and to `EpisodeSpec.tools` definitions (plain
    `.name`, or OpenAI tool-schema dicts `{"function": {"name": ...}}`), so both
    shapes need to resolve to the same string.
    """
    function = getattr(entry, "function", None)
    if function is not None:
        return function.name
    if isinstance(entry, dict):
        return entry["function"]["name"] if "function" in entry else entry["name"]
    return entry.name


class ToolFilter:
    """Drops tool calls/definitions whose name is not on the configured allowlist."""

    def __init__(self, allowed_tools: list[str]) -> None:
        self.allowed_tools = allowed_tools

    @property
    def name(self) -> str:
        return "tool_filter"

    def wrap_system_prompt(self, prompt: str) -> str:
        return prompt

    def filter_tool_calls(self, tool_calls: list[Any]) -> list[Any]:
        return [call for call in tool_calls if _tool_name(call) in self.allowed_tools]
