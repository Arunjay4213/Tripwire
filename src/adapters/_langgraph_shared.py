"""Shared helpers for LangGraph-based adapters.

LangGraphAdapter and MultiAgentAdapter both talk to a raw OpenAI/Groq client
while using LangGraph's add_messages reducer for state -- the OpenAI SDK
message <-> langchain_core BaseMessage coercion quirks this works around
were debugged once (see langgraph_adapter.py's AgentState docstring for the
full explanation) and must stay identical across both adapters, not drift
apart via copy-paste.
"""

from __future__ import annotations

import json
from typing import Any

from .base import TraceStep


def run_tool(tool_map: dict, name: str, args: dict, tool_result_wrapper: Any = None) -> str:
    """Execute a tool and pass its output through the defense's result wrapper.

    The wrapper (spotlighting's delimiter fencing, say) runs only on results of
    tools that actually executed -- never on a guard's block message -- and is
    identity when unset. Shared so both LangGraph adapters apply it identically.
    """
    result = str(tool_map[name](**args))
    if tool_result_wrapper is not None:
        result = tool_result_wrapper(name, result)
    return result


def parse_tool_args(raw_arguments: str | None) -> dict[str, Any]:
    """Normalize a tool call's raw arguments into a dict.

    Providers are inconsistent for no-arg tools: they may send "", "{}",
    or literally "null" (which json.loads()'s to None, not {}). langchain's
    AIMessage.tool_calls requires args to be a dict, so we always land on one.
    """
    if not raw_arguments:
        return {}
    try:
        parsed = json.loads(raw_arguments)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def openai_message_to_dict(message: Any) -> dict[str, Any]:
    """Convert an OpenAI SDK ChatCompletionMessage into a plain OpenAI-format
    dict -- add_messages only knows how to coerce BaseMessage / dict / (role,
    content) tuples, not raw SDK objects.
    """
    message_dict: dict[str, Any] = {"role": "assistant", "content": message.content or ""}
    if message.tool_calls:
        message_dict["tool_calls"] = [
            {
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.function.name,
                    "arguments": json.dumps(parse_tool_args(call.function.arguments)),
                },
            }
            for call in message.tool_calls
        ]
    return message_dict


def messages_to_trace_steps(messages: list[Any], step_offset: int = 0) -> tuple[list[TraceStep], str]:
    """Convert a run of coerced langchain_core BaseMessages (AIMessage /
    ToolMessage) into TraceSteps, continuing step numbering from step_offset.

    Returns (steps, final_output) where final_output is the last AIMessage
    with no tool_calls seen (empty string if none). Shared because
    MultiAgentAdapter needs to run this exact conversion twice, once per
    agent, into one combined trace.
    """
    steps: list[TraceStep] = []
    final_output = ""

    for msg in messages:
        if msg.type == "ai":
            if msg.tool_calls:
                for call in msg.tool_calls:
                    steps.append(TraceStep(
                        step=step_offset + len(steps),
                        type="tool_call",
                        name=call["name"],
                        args=call["args"],
                    ))
            else:
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                final_output = content
                steps.append(TraceStep(step=step_offset + len(steps), type="model_output", content=content))
        elif msg.type == "tool":
            content = msg.content if isinstance(msg.content, str) else str(msg.content)
            # status="error" is how _run_tools marks a tool_call_guard denial
            # (see langgraph_adapter.py) -- the judge must not score a
            # blocked attempt as a real leak just because the model
            # requested it with the canary in its args.
            step_type = "tool_blocked" if getattr(msg, "status", None) == "error" else "tool_result"
            steps.append(TraceStep(
                step=step_offset + len(steps), type=step_type, name=msg.name or "", content=content,
            ))

    return steps, final_output
