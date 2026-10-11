"""Tool-call policy shared by every built-in adapter.

The project's claim is that only the orchestration layer differs between
adapters. That only holds if every adapter handles the same model output the
same way, including the messy cases where the model goes off-script. Those
cases are exactly the ones prompt injection produces, so they must never crash
an adapter (the runner would retry or drop the episode) and must never be
silently rewritten (the judge would lose the evidence). This module is the one
place that policy lives:

- Arguments that are not valid JSON, or valid JSON that is not an object, are
  kept verbatim as ``{"__raw__": <raw string>}``. The tool does not run; the
  call is recorded as a ``tool_call`` step with those args (so the judge can
  still find a canary in them), followed by a ``tool_blocked`` step whose text
  is sent back to the model as the tool result. The loop continues.
- A tool name the agent was not given is not run: ``tool_blocked`` with
  "Tool 'X' is not available to this agent."
- The defense's ``tool_call_guard`` is consulted next; a denial is
  ``tool_blocked`` with the guard's message.
- A tool that raises produces a ``tool_result`` whose content is
  ``"tool error: <ExceptionType>: <message>"``. The loop continues.

Empty arguments ("", None) and the literal JSON ``null`` mean "no arguments"
and parse to ``{}``: providers send all three for no-arg tools.

Bring-your-own adapters can import ``parse_tool_args`` and
``execute_tool_call`` to get identical behavior.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .base import ToolCallGuard, ToolResultWrapper

# Key under which unparseable tool-call arguments are preserved verbatim.
RAW_ARGS_KEY = "__raw__"


def parse_tool_args(raw_arguments: str | None) -> dict[str, Any]:
    """Parse a tool call's raw argument string into a dict, never raising.

    Returns ``{}`` for "", None or "null" (no-arg tools), the parsed object
    when the string is a JSON object, and ``{"__raw__": raw_arguments}`` for
    anything else (malformed JSON, or JSON that is not an object). The raw
    form keeps a canary inside a truncated call visible to the judge instead
    of quietly turning the call into ``{}``.
    """
    if not raw_arguments:
        return {}
    try:
        parsed = json.loads(raw_arguments)
    except (json.JSONDecodeError, TypeError):
        return {RAW_ARGS_KEY: raw_arguments}
    if parsed is None:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {RAW_ARGS_KEY: raw_arguments}


def has_invalid_args(args: dict[str, Any]) -> bool:
    """True when ``args`` is the ``{"__raw__": ...}`` form from parse_tool_args."""
    return set(args) == {RAW_ARGS_KEY} and isinstance(args[RAW_ARGS_KEY], str)


def message_text(content: Any) -> str:
    """Plain text of a message's content: a string, None, or a list of
    content blocks (``[{"type": "text", "text": ...}, ...]``), which some
    OpenAI-compatible providers send. Never a Python repr of the list."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "".join(parts)
    return "" if content is None else str(content)


def assistant_text(message: Any) -> str:
    """The text of an assistant turn: its content, or, for a refusal
    (``content`` None and the text in ``message.refusal``), the refusal, so
    the trace and the adaptive attackers see what the model actually said."""
    return message_text(getattr(message, "content", None)) or message_text(getattr(message, "refusal", None))


def assistant_message_to_dict(message: Any) -> dict[str, Any]:
    """Convert an OpenAI SDK ChatCompletionMessage into a plain OpenAI-format
    assistant dict, the form every adapter feeds back into the conversation.

    Normalizes the shapes real providers send: content as a block list
    becomes text, a refusal becomes the content, and a tool call with no id
    (some endpoints omit it) gets one, since the tool message that answers it
    must name it. Arguments are re-serialized from parse_tool_args, so the
    history always carries a valid JSON object (some OpenAI-compatible
    endpoints reject a request whose earlier tool call has malformed
    arguments). Malformed arguments appear there as
    ``{"__raw__": "<what the model sent>"}``, so the model still sees what it
    actually produced rather than a rewritten ``{}``.
    """
    message_dict: dict[str, Any] = {"role": "assistant", "content": assistant_text(message)}
    if message.tool_calls:
        message_dict["tool_calls"] = [
            {
                "id": call.id or f"call_{index}",
                "type": "function",
                "function": {
                    "name": call.function.name,
                    "arguments": json.dumps(parse_tool_args(call.function.arguments)),
                },
            }
            for index, call in enumerate(message.tool_calls)
        ]
    return message_dict


def offered_tool_map(tools: list[Any] | None, impls: dict[str, Any]) -> dict[str, Any]:
    """The tools an agent may actually run: the implementations of the tools
    it was OFFERED. ``spec.tools`` is the menu; an implementation that exists
    but was filtered off the menu (tool_filter removing send_email) must not
    run just because the model free-forms a call to it."""
    offered = {_tool_schema_name(t) for t in tools or []}
    return {name: impl for name, impl in impls.items() if name in offered}


def _tool_schema_name(tool: Any) -> str:
    if isinstance(tool, dict):
        function = tool.get("function", tool)
        return str(function.get("name", ""))
    return str(getattr(tool, "name", ""))


@dataclass(frozen=True)
class ToolOutcome:
    """What one tool call produced.

    ``content`` is what the model sees as the tool result. ``blocked`` is True
    when the tool did not run (bad arguments, unknown tool, or a guard
    denial); adapters record that as a ``tool_blocked`` step so the judge
    never scores a non-executed attempt as a real leak.
    """

    content: str
    blocked: bool


def invalid_args_message(name: str) -> str:
    return f"invalid JSON arguments: the call to '{name}' was not run because its arguments are not a JSON object."


def unavailable_tool_message(name: str) -> str:
    return f"Tool '{name}' is not available to this agent."


def execute_tool_call(
    name: str,
    args: dict[str, Any],
    tool_map: dict[str, Any],
    tool_call_guard: ToolCallGuard | None = None,
    tool_result_wrapper: ToolResultWrapper | None = None,
) -> ToolOutcome:
    """Apply the shared policy (see module docstring) to one parsed tool call.

    ``args`` must come from parse_tool_args. The result wrapper (a defense's
    content marking, e.g. spotlighting) runs only on output of a tool that
    actually returned; never on block messages or tool errors, which are
    harness text rather than untrusted tool content.
    """
    if has_invalid_args(args):
        return ToolOutcome(invalid_args_message(name), blocked=True)
    if name not in tool_map:
        # Topology, not a defense decision: this agent was never given this
        # tool (a defense filtered it out, or the model made the name up).
        return ToolOutcome(unavailable_tool_message(name), blocked=True)
    if tool_call_guard is not None:
        allowed, message = tool_call_guard(name, args)
        if not allowed:
            return ToolOutcome(message, blocked=True)
    try:
        result = str(tool_map[name](**args))
    except Exception as exc:  # noqa: BLE001 - any tool failure is fed back to the model
        return ToolOutcome(f"tool error: {type(exc).__name__}: {exc}", blocked=False)
    if tool_result_wrapper is not None:
        result = tool_result_wrapper(name, result)
    return ToolOutcome(result, blocked=False)
