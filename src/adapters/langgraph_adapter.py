from __future__ import annotations

import json
import os
from dotenv import load_dotenv
from openai import OpenAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.messages import convert_to_openai_messages
from typing import Annotated, TypedDict

from .base import EpisodeSpec, NormalizedTrace, TraceStep

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

    @staticmethod
    def _parse_tool_args(raw_arguments: str | None) -> dict:
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
        message = response.choices[0].message

        # Return a plain OpenAI-format dict, not the raw SDK object -- the
        # add_messages reducer only knows how to coerce BaseMessage / dict /
        # (role, content) tuples (see AgentState docstring above).
        message_dict: dict = {"role": "assistant", "content": message.content or ""}
        if message.tool_calls:
            message_dict["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.function.name,
                        "arguments": json.dumps(self._parse_tool_args(call.function.arguments)),
                    },
                }
                for call in message.tool_calls
            ]

        return {"messages": [message_dict]}

    def _run_tools(self, state: AgentState, tool_map: dict) -> AgentState:
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
            result = tool_map[name](**args)

            tool_results.append({
                "role": "tool",
                "name": name,
                "tool_call_id": call["id"],
                "content": str(result),
            })

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
            return self._run_tools(state, tool_map)

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
        steps: list[TraceStep] = []
        final_output = ""

        for msg in new_messages:
            if msg.type == "ai":
                if msg.tool_calls:
                    for call in msg.tool_calls:
                        steps.append(TraceStep(
                            step=len(steps),
                            type="tool_call",
                            name=call["name"],
                            args=call["args"],
                        ))
                else:
                    content = msg.content if isinstance(msg.content, str) else str(msg.content)
                    final_output = content
                    steps.append(TraceStep(step=len(steps), type="model_output", content=content))
            elif msg.type == "tool":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                steps.append(TraceStep(step=len(steps), type="tool_result", name=msg.name or "", content=content))

        # Step 5: return NormalizedTrace
        return NormalizedTrace(steps=steps, final_output=final_output)
