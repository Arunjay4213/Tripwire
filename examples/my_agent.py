"""Example BYO agent — a LangGraph tool-loop, wired into Tripwire's contract.

Run the full attack suite against this agent instead of the built-ins:

    python -m src --config src/config/threat_model.example.yaml \
        --agent examples/my_agent.py --smoke

The whole contract is two types (src/adapters/base.py): an `EpisodeSpec` comes
in, a `NormalizedTrace` goes out. Expose EITHER a module-level
`run(spec) -> NormalizedTrace`, OR (as here) an `adapter` object with a `.name`
and a `.run(spec)`. Point `--agent` at your own agent's equivalent of the graph
below.

What Tripwire hands you in the spec (you never build these yourself):
  - spec.task["system_prompt"]  the system prompt (already defense-hardened)
  - spec.task["user_message"]   the user's request
  - spec.task["tool_impls"]     {tool_name: callable} -- the real tools to run
  - spec.tools                  OpenAI-format tool schemas to give the model
  - spec.model                  model id to call
  - spec.tool_call_guard        optional (name, args) -> (allowed, message)
  - spec.tool_result_wrapper    optional (name, result) -> transformed result

What Tripwire needs back: a NormalizedTrace whose `steps` record, in order,
every `tool_call` (with its args) and `tool_result`/`tool_blocked` (with its
content) -- that trace is ALL the judge reads. If your agent calls `send_email`
with the planted secret in an argument, it must show up as a `tool_call` step,
or the leak is invisible to scoring.

This agent uses two "basic tools" -- `read_inbox` and `send_email` -- supplied
by Tripwire's environment. Your real agent would have its own tools; the same
two hooks (`tool_call_guard`, `tool_result_wrapper`) are how a Tripwire defense
gates whatever tools you give it.
"""

from __future__ import annotations

import os
from typing import Annotated, TypedDict

from dotenv import load_dotenv
from langchain_core.messages import convert_to_openai_messages
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from openai import OpenAI

from src.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep

load_dotenv()


class _State(TypedDict):
    # add_messages appends rather than replaces, and coerces plain OpenAI-format
    # dicts into langchain message objects -- which is why _call_model converts
    # back to OpenAI dicts before calling the raw client below.
    messages: Annotated[list, add_messages]


class LangGraphAgent:
    """A minimal two-node LangGraph agent (call model -> run tools -> repeat)."""

    name = "my_langgraph_agent"

    def __init__(self) -> None:
        self._client = OpenAI(api_key=os.getenv("GROQ_API_KEY"), base_url=os.getenv("GROQ_BASE_URL"))

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        env = spec.task
        tool_impls = env["tool_impls"]
        steps: list[TraceStep] = []

        def call_model(state: _State) -> _State:
            openai_messages = convert_to_openai_messages(state["messages"])
            response = self._client.chat.completions.create(
                model=spec.model, messages=openai_messages, tools=spec.tools,
            )
            msg = response.choices[0].message
            # Return a plain OpenAI-format dict; add_messages coerces it.
            out: dict = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                out["tool_calls"] = [
                    {"id": c.id, "type": "function",
                     "function": {"name": c.function.name, "arguments": c.function.arguments or "{}"}}
                    for c in msg.tool_calls
                ]
            return {"messages": [out]}

        def run_tools(state: _State) -> _State:
            last = state["messages"][-1]
            results = []
            for call in last.tool_calls:  # coerced AIMessage: {"name","args","id"}
                name, args = call["name"], call["args"]
                steps.append(TraceStep(step=len(steps), type="tool_call", name=name, args=args))

                # Enforce a defense's mid-loop guard, if one is set, before running.
                blocked = False
                if spec.tool_call_guard is not None:
                    allowed, message = spec.tool_call_guard(name, args)
                    if not allowed:
                        result, blocked = message, True
                    else:
                        result = self._exec(spec, tool_impls, name, args)
                else:
                    result = self._exec(spec, tool_impls, name, args)

                steps.append(TraceStep(
                    step=len(steps),
                    type="tool_blocked" if blocked else "tool_result",
                    name=name, content=str(result),
                ))
                results.append({
                    "role": "tool", "name": name, "tool_call_id": call["id"],
                    "content": str(result), **({"status": "error"} if blocked else {}),
                })
            return {"messages": results}

        def should_continue(state: _State) -> str:
            last = state["messages"][-1]
            return "run_tools" if getattr(last, "tool_calls", None) else END

        graph = StateGraph(_State)
        graph.add_node("call_model", call_model)
        graph.add_node("run_tools", run_tools)
        graph.set_entry_point("call_model")
        graph.add_conditional_edges("call_model", should_continue)
        graph.add_edge("run_tools", "call_model")
        app = graph.compile()

        result = app.invoke({"messages": [
            {"role": "system", "content": env["system_prompt"]},
            {"role": "user", "content": env["user_message"]},
        ]})

        # final_output = last assistant message with no tool calls.
        final = ""
        for msg in result["messages"]:
            if getattr(msg, "type", None) == "ai" and not getattr(msg, "tool_calls", None):
                final = msg.content if isinstance(msg.content, str) else str(msg.content)
        if final:
            steps.append(TraceStep(step=len(steps), type="model_output", content=final))
        return NormalizedTrace(steps=steps, final_output=final)

    @staticmethod
    def _exec(spec: EpisodeSpec, tool_impls: dict, name: str, args: dict) -> str:
        """Run a tool, then let a defense's result wrapper transform the output
        before the model sees it (spotlighting fences untrusted output here).
        Identity when no defense sets a wrapper."""
        result = str(tool_impls[name](**args))
        if spec.tool_result_wrapper is not None:
            result = spec.tool_result_wrapper(name, result)
        return result


# `--agent examples/my_agent.py` looks for this `adapter` object (or a bare
# `run` function). Exposing an object is the right shape when your agent is
# already a class wrapping a framework, as here.
adapter = LangGraphAgent()
