"""Single-agent LangGraph adapter: a call_model <-> run_tools graph.

Same EpisodeSpec/NormalizedTrace contract as raw_loop.py, same turn budget
(spec.max_turns) and the same tool-call policy (_common.py), so the only
thing that differs from raw_loop is that LangGraph drives the loop.

No load_dotenv() here: importing a library module must not write a .env into
os.environ. The CLI loads .env; scripts that build adapters directly do too.
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langchain_core.messages import convert_to_openai_messages
from langgraph.errors import GraphRecursionError
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from openai import OpenAI

from tripwire.harness.llm import make_client

from ._langgraph_shared import (
    execute_tool_call,
    messages_to_trace_steps,
    openai_message_to_dict,
)
from .base import EpisodeSpec, NormalizedTrace, StopReason


def recursion_limit_for(max_turns: int) -> int:
    """LangGraph recursion_limit that allows exactly ``max_turns`` model calls.

    Each loop iteration is two LangGraph super-steps: call_model, then
    run_tools. ``max_turns`` model calls plus the tool round after each one is
    therefore ``2 * max_turns`` super-steps, which is what raw_loop does in
    ``max_turns`` iterations (it also runs the tools requested by its last
    model call). The next call_model would be super-step ``2 * max_turns + 1``,
    so LangGraph raises GraphRecursionError there and the adapter returns the
    partial trace with stop_reason="max_turns".
    """
    return 2 * max_turns


class AgentState(TypedDict):
    """
    The conversation so far.
    add_messages means new messages get appended not replaced.

    NOTE: the add_messages reducer coerces every message we hand it (plain
    OpenAI-format dicts included) into langchain_core BaseMessage objects
    (SystemMessage/HumanMessage/AIMessage/ToolMessage). That's why
    _call_model converts state["messages"] back to OpenAI dicts before
    calling the (raw, non-langchain) Groq/OpenAI client -- the client
    doesn't know how to serialize BaseMessage objects.
    """
    messages: Annotated[list, add_messages]


class LangGraphAdapter:
    name = "langgraph"

    def __init__(self, client: OpenAI | None = None):
        """``client`` is any OpenAI-compatible client; built from env when
        omitted. resolve_adapters passes the sweep's shared client."""
        self.client = client if client is not None else make_client()

    def _call_model(self, state: AgentState, model: str, tools_json: list[dict]) -> AgentState:
        """
        Node 1: send current messages to the LLM, get a response.
        The response gets added to state.messages automatically.
        """
        openai_messages = convert_to_openai_messages(state["messages"])
        # Omit `tools` entirely when the list is empty -- a defense (tool_filter)
        # can strip every tool, and most OpenAI-compatible endpoints reject an
        # empty `tools=[]` with a 400. No tools -> the model can only reply text.
        kwargs = {"model": model, "messages": openai_messages}
        if tools_json:
            kwargs["tools"] = tools_json
        response = self.client.chat.completions.create(**kwargs)
        # Return a plain OpenAI-format dict, not the raw SDK object -- the
        # add_messages reducer only knows how to coerce BaseMessage / dict /
        # (role, content) tuples (see AgentState docstring above).
        return {"messages": [openai_message_to_dict(response.choices[0].message)]}

    def _run_tools(self, state: AgentState, tool_map: dict, tool_call_guard, tool_result_wrapper) -> AgentState:
        """
        Node 2: look at the last message, run whatever tools it asked for,
        add the results back to state.
        """
        last_message = state["messages"][-1]
        tool_results = []

        for call in last_message.tool_calls:
            # last_message is a coerced AIMessage here, so tool_calls are
            # langchain ToolCall dicts: {"name", "args" (already parsed by
            # parse_tool_args, so malformed args are {"__raw__": ...}), "id"}.
            name = call["name"]
            outcome = execute_tool_call(name, call["args"], tool_map, tool_call_guard, tool_result_wrapper)

            tool_result: dict = {
                "role": "tool",
                "name": name,
                "tool_call_id": call["id"],
                "content": outcome.content,
            }
            if outcome.blocked:
                # ToolMessage.status="error" is how messages_to_trace_steps
                # tells a call that did not run apart from a real
                # tool_result -- the judge must not score it as a real leak
                # just because the model requested it with the canary in args.
                tool_result["status"] = "error"
            tool_results.append(tool_result)

        return {"messages": tool_results}

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        # Step 1: unpack spec per the shared adapter contract (matches
        # raw_loop.py so both adapters plug into the same runner.py
        # unchanged). spec.task is a dict: system_prompt, user_message,
        # tool_impls (name -> callable). spec.tools is a plain OpenAI
        # function-calling JSON schema list -- no callables embedded, since
        # that list goes straight to the LLM client.
        env = spec.task
        initial_messages = [
            {"role": "system", "content": env["system_prompt"]},
            {"role": "user", "content": env["user_message"]},
        ]
        tools_json = spec.tools
        tool_map = env["tool_impls"]

        # Step 2: build the graph
        def call_model(state):
            return self._call_model(state, spec.model, tools_json)

        def run_tools(state):
            return self._run_tools(state, tool_map, spec.tool_call_guard, spec.tool_result_wrapper)

        def should_continue(state) -> str:
            """
            The edge decision: after calling the model,
            did it ask for tools? If yes run them. If no we're done.
            """
            last = state["messages"][-1]
            if getattr(last, "tool_calls", None):
                return "run_tools"
            return END

        # Build the flowchart
        graph = StateGraph(AgentState)

        # Add the two nodes
        graph.add_node("call_model", call_model)
        graph.add_node("run_tools", run_tools)

        # Add the edges
        graph.set_entry_point("call_model")
        graph.add_conditional_edges("call_model", should_continue)
        graph.add_edge("run_tools", "call_model")  # after tools, call model again

        # Compile -- turns the flowchart into a runnable object
        app = graph.compile()

        # Step 3: run the graph under the shared turn budget. stream() with
        # stream_mode="values" yields the full state after every super-step,
        # so when the budget runs out (GraphRecursionError) the last yielded
        # state is the partial trace -- invoke() would discard it.
        config: Any = {"recursion_limit": recursion_limit_for(spec.max_turns)}
        state: dict[str, Any] = {"messages": []}
        stop_reason: StopReason = "done"
        try:
            for state in app.stream({"messages": initial_messages}, config=config, stream_mode="values"):
                pass
        except GraphRecursionError:
            stop_reason = "max_turns"

        # Step 4: record TraceSteps -- only what the run produced, not the
        # initial system/user messages we fed in.
        new_messages = state["messages"][len(initial_messages):]
        steps, final_output = messages_to_trace_steps(new_messages)
        if stop_reason == "max_turns":
            final_output = ""

        # Step 5: return NormalizedTrace
        return NormalizedTrace(steps=steps, final_output=final_output, stop_reason=stop_reason)
