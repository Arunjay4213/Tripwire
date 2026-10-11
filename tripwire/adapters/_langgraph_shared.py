"""Shared helpers for LangGraph-based adapters.

LangGraphAdapter and MultiAgentAdapter both talk to a raw OpenAI/Groq client
while using LangGraph's add_messages reducer for state -- the OpenAI SDK
message <-> langchain_core BaseMessage coercion quirks this works around
were debugged once (see langgraph_adapter.py's AgentState docstring for the
full explanation) and must stay identical across both adapters, not drift
apart via copy-paste.
"""

from __future__ import annotations

from typing import Any

# The tool-call policy (argument parsing, unknown tools, guard, tool errors)
# is framework-neutral and lives in _common.py so raw_loop shares it too.
# Re-exported here under the names the LangGraph adapters already import.
from ._common import (
    ToolOutcome,
    assistant_message_to_dict,
    execute_tool_call,
    message_text,
    offered_tool_map,
    parse_tool_args,
)
from .base import StepType, TraceStep

# Historical name, still imported by multi_agent_adapter.py.
openai_message_to_dict = assistant_message_to_dict

__all__ = [
    "ToolOutcome",
    "assistant_message_to_dict",
    "execute_tool_call",
    "message_text",
    "messages_to_trace_steps",
    "offered_tool_map",
    "openai_message_to_dict",
    "parse_tool_args",
]


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
                # Text the model wrote alongside its tool calls is still model
                # output (it may carry the canary); keep it, as raw_loop does.
                text = message_text(msg.content)
                if text:
                    steps.append(TraceStep(step=step_offset + len(steps), type="model_output", content=text))
                for call in msg.tool_calls:
                    steps.append(TraceStep(
                        step=step_offset + len(steps),
                        type="tool_call",
                        name=call["name"],
                        args=call["args"],
                    ))
            else:
                content = message_text(msg.content)
                final_output = content
                steps.append(TraceStep(step=step_offset + len(steps), type="model_output", content=content))
        elif msg.type == "tool":
            content = message_text(msg.content)
            # status="error" is how _run_tools marks a call that did not run
            # (guard denial, unknown tool, invalid arguments; see
            # langgraph_adapter.py) -- the judge must not score a blocked
            # attempt as a real leak just because the model requested it
            # with the canary in its args.
            step_type: StepType = "tool_blocked" if getattr(msg, "status", None) == "error" else "tool_result"
            steps.append(TraceStep(
                step=step_offset + len(steps), type=step_type, name=msg.name or "", content=content,
            ))

    return steps, final_output
