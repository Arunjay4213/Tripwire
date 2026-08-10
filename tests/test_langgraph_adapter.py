"""Tests for the LangGraph adapter — LangGraphAdapter.run().

The Groq/OpenAI client is mocked so these tests run offline and
deterministically: we hand-script two model turns (one tool call, then a
final answer) and check the adapter turns them into the right
NormalizedTrace, per the Adapter contract in tripwire/adapters/base.py.

spec.task/spec.tools follow the same shape raw_loop.py expects (see
tests/test_raw_loop.py) so both adapters plug into runner.run_episode()
unchanged: task is a dict of system_prompt/user_message/tool_impls, tools
is a plain OpenAI function-calling JSON schema list.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from tripwire.adapters.base import EpisodeSpec
from tripwire.adapters.langgraph_adapter import LangGraphAdapter


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


def test_blocked_call_never_executes_real_tool():
    """Mid-loop enforcement: spec.tool_call_guard is checked before execution."""
    adapter = LangGraphAdapter()
    adapter.client.chat.completions.create = MagicMock(
        side_effect=[
            _fake_response(
                content=None,
                tool_calls=[_fake_tool_call("call_1", "echo", '{"msg": "hi"}')],
            ),
            _fake_response(content="done", tool_calls=None),
        ]
    )

    executed = []

    def echo(msg: str) -> str:
        executed.append(msg)  # would prove a real leak if this ran
        return f"echo: {msg}"

    def guard(name, args):
        return False, f"blocked: {name}"

    spec = EpisodeSpec(
        task={
            "system_prompt": "You are a test agent.",
            "user_message": "Say hi via the echo tool.",
            "tool_impls": {"echo": echo},
        },
        tools=[ECHO_SCHEMA],
        model="fake-model",
        environment_seed=0,
        tool_call_guard=guard,
    )

    trace = adapter.run(spec)

    assert executed == []  # the real tool never ran
    tool_result = trace.steps[1]
    assert tool_result.type == "tool_blocked"
    assert tool_result.content == "blocked: echo"


def test_allowed_call_executes_normally_with_guard_present():
    adapter = LangGraphAdapter()
    adapter.client.chat.completions.create = MagicMock(
        side_effect=[
            _fake_response(
                content=None,
                tool_calls=[_fake_tool_call("call_1", "echo", '{"msg": "hi"}')],
            ),
            _fake_response(content="done", tool_calls=None),
        ]
    )

    def guard(name, args):
        return True, ""

    spec = EpisodeSpec(
        task={
            "system_prompt": "You are a test agent.",
            "user_message": "Say hi via the echo tool.",
            "tool_impls": {"echo": _echo},
        },
        tools=[ECHO_SCHEMA],
        model="fake-model",
        environment_seed=0,
        tool_call_guard=guard,
    )

    trace = adapter.run(spec)

    assert trace.steps[1].content == "echo: hi"


def test_hallucinated_tool_is_blocked_not_crashed():
    """A model can free-form a tool name the agent was never given (e.g. a
    defense filtered it out). That must produce a tool_blocked step, not a
    KeyError -- matching MultiAgentAdapter's handling."""
    adapter = LangGraphAdapter()
    adapter.client.chat.completions.create = MagicMock(
        side_effect=[
            _fake_response(
                content=None,
                tool_calls=[_fake_tool_call("call_1", "ghost_tool", '{"msg": "hi"}')],
            ),
            _fake_response(content="done", tool_calls=None),
        ]
    )

    spec = EpisodeSpec(
        task={
            "system_prompt": "You are a test agent.",
            "user_message": "Do something.",
            "tool_impls": {"echo": _echo},  # ghost_tool is NOT here
        },
        tools=[ECHO_SCHEMA],
        model="fake-model",
        environment_seed=0,
    )

    trace = adapter.run(spec)  # must not raise

    blocked = trace.steps[1]
    assert blocked.type == "tool_blocked"
    assert "not available" in blocked.content


def test_empty_tool_list_omits_tools_kwarg():
    """A tool_filter defense can strip every tool. Sending tools=[] makes most
    OpenAI-compatible endpoints 400, so the adapter must omit the kwarg."""
    adapter = LangGraphAdapter()
    create = MagicMock(return_value=_fake_response(content="text only", tool_calls=None))
    adapter.client.chat.completions.create = create

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

    assert "tools" not in create.call_args.kwargs


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
