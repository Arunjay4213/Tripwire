"""Tests for the LangGraph adapter that are specific to its request building.

Everything the adapter shares with the other loops (tool round trips, guard
denial, hallucinated tools, malformed arguments, the turn budget) is asserted
across adapters in tests/test_adapter_parity.py; this file keeps only what
that file does not pin for LangGraph.

spec.task/spec.tools follow the same shape raw_loop.py expects (see
tests/test_raw_loop.py) so both adapters plug into runner.run_episode()
unchanged: task is a dict of system_prompt/user_message/tool_impls, tools
is a plain OpenAI function-calling JSON schema list.
"""

from __future__ import annotations

from tests.scripted_client import ScriptedClient, message
from tripwire.adapters.base import EpisodeSpec
from tripwire.adapters.langgraph_adapter import LangGraphAdapter


def test_empty_tool_list_omits_tools_kwarg():
    """A tool_filter defense can strip every tool. Sending tools=[] makes most
    OpenAI-compatible endpoints 400, so the adapter must omit the kwarg."""
    client = ScriptedClient(script=[message("text only")])
    adapter = LangGraphAdapter(client=client)

    spec = EpisodeSpec(
        task={
            "system_prompt": "You are a test agent.",
            "user_message": "Say something.",
            "tool_impls": {},
        },
        tools=[],
        model="fake-model",
        environment_seed=0,
    )

    adapter.run(spec)

    assert "tools" not in client.requests[-1]


def test_run_with_no_tool_calls_returns_single_model_output_step():
    adapter = LangGraphAdapter(client=ScriptedClient(script=[message("just an answer")]))

    spec = EpisodeSpec(
        task={
            "system_prompt": "You are a test agent.",
            "user_message": "Say something.",
            "tool_impls": {},
        },
        tools=[],
        model="fake-model",
        environment_seed=0,
    )

    trace = adapter.run(spec)

    assert len(trace.steps) == 1
    assert trace.steps[0].type == "model_output"
    assert trace.final_output == "just an answer"
