"""Tests for the LangGraph adapter — LangGraphAdapter.run().

The Groq/OpenAI client is mocked so these tests run offline and
deterministically: we hand-script two model turns (one tool call, then a
final answer) and check the adapter turns them into the right
NormalizedTrace, per the Adapter contract in src/adapters/base.py.

spec.task/spec.tools follow the same shape raw_loop.py expects (see
tests/test_raw_loop.py) so both adapters plug into runner.run_episode()
unchanged: task is a dict of system_prompt/user_message/tool_impls, tools
is a plain OpenAI function-calling JSON schema list.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from src.adapters.base import EpisodeSpec
from src.adapters.langgraph_adapter import LangGraphAdapter


def _fake_response(content=None, tool_calls=None):
    """Build an object shaped like OpenAI's ChatCompletion, just deep enough
    for the fields _call_model actually reads."""
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _fake_tool_call(call_id, name, arguments):
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=arguments))


ECHO_SCHEMA = {
    "type": "function",
    "function": {
        "name": "echo",
        "description": "Echoes a message back.",
        "parameters": {
            "type": "object",
            "properties": {"msg": {"type": "string"}},
            "required": ["msg"],
        },
    },
}


def _echo(msg: str) -> str:
    return f"echo: {msg}"


def test_run_records_tool_call_tool_result_and_model_output():
    adapter = LangGraphAdapter()

    # Turn 1: model asks for the echo tool. Turn 2: model gives a final answer.
    adapter.client.chat.completions.create = MagicMock(
        side_effect=[
            _fake_response(
                content=None,
                tool_calls=[_fake_tool_call("call_1", "echo", '{"msg": "hi"}')],
            ),
            _fake_response(content="done", tool_calls=None),
        ]
    )

    spec = EpisodeSpec(
        task={
            "system_prompt": "You are a test agent.",
            "user_message": "Say hi via the echo tool.",
            "tool_impls": {"echo": _echo},
        },
        tools=[ECHO_SCHEMA],
        model="fake-model",
        environment_seed=0,
    )

    trace = adapter.run(spec)

    assert [s.type for s in trace.steps] == ["tool_call", "tool_result", "model_output"]

    tool_call, tool_result, model_output = trace.steps

    assert tool_call.name == "echo"
    assert tool_call.args == {"msg": "hi"}

    assert tool_result.name == "echo"
    assert tool_result.content == "echo: hi"

    assert model_output.content == "done"
    assert trace.final_output == "done"

    # Steps are numbered in order.
    assert [s.step for s in trace.steps] == [0, 1, 2]

    # Only two model turns were needed -- one tool round trip, one final answer.
    assert adapter.client.chat.completions.create.call_count == 2


def test_run_with_no_tool_calls_returns_single_model_output_step():
    adapter = LangGraphAdapter()
    adapter.client.chat.completions.create = MagicMock(
        return_value=_fake_response(content="just an answer", tool_calls=None)
    )

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
