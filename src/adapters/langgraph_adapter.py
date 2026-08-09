from __future__ import annotations

import os
from dotenv import load_dotenv
from openai import OpenAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.messages import convert_to_openai_messages
from typing import Annotated, TypedDict

from ._langgraph_shared import messages_to_trace_steps, openai_message_to_dict, run_tool as _run_tool
from .base import EpisodeSpec, NormalizedTrace

load_dotenv()


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

    def __init__(self):
        self.client = OpenAI(
            api_key=os.getenv("GROQ_API_KEY"),
            base_url=os.getenv("GROQ_BASE_URL"),
        )

    def _call_model(self, state: AgentState, model: str, tools_json: list[dict]) -> AgentState:
        """
        Node 1: send current messages to the LLM, get a response.
        The response gets added to state.messages automatically.
        """
        openai_messages = convert_to_openai_messages(state["messages"])
        response = self.client.chat.completions.create(
            model=model,
            messages=openai_messages,
            tools=tools_json,
        )
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
            # langchain ToolCall dicts: {"name", "args" (already parsed), "id", "type"}
            name = call["name"]
            args = call["args"]

            # Mid-loop defense backstop: even if the tool wasn't offered
            # (filtered out of spec.tools), the model can still free-form a
            # call for it, so check again right before executing.
            blocked = False
            if tool_call_guard is not None:
                allowed, message = tool_call_guard(name, args)
                if not allowed:
                    result, blocked = message, True
                else:
                    result = _run_tool(tool_map, name, args, tool_result_wrapper)
            else:
                result = _run_tool(tool_map, name, args, tool_result_wrapper)

            tool_result: dict = {
                "role": "tool",
                "name": name,
                "tool_call_id": call["id"],
                "content": str(result),
            }
            if blocked:
                # ToolMessage.status="error" is how messages_to_trace_steps
                # tells a blocked attempt apart from a real tool_result --
                # the judge must not score it as a real leak just because
                # the model requested it with the canary in its args.
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

        # Step 3: run the graph
        result = app.invoke({"messages": initial_messages})

        # Step 4: record TraceSteps -- only what the run produced, not the
        # initial system/user messages we fed in.
        new_messages = result["messages"][len(initial_messages):]
        steps, final_output = messages_to_trace_steps(new_messages)

        # Step 5: return NormalizedTrace
        return NormalizedTrace(steps=steps, final_output=final_output)
