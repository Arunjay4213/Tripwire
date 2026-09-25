"""Raw tool-loop adapter — minimal ReAct-style loop, no framework.

Baseline / control for the orchestrator hypothesis (roadmap Week 1 + §0.4).
Implements the Adapter contract from base.py. Tool calls go through the
shared policy in _common.py so this adapter handles malformed arguments,
unknown tools and failing tools exactly like the LangGraph adapters.
"""

from __future__ import annotations

from typing import Any

from openai import OpenAI

from ._common import assistant_message_to_dict, execute_tool_call, parse_tool_args
from .base import EpisodeSpec, NormalizedTrace, TraceStep


class RawLoopAdapter:
    name = "raw_loop"

    def __init__(self, client: OpenAI, max_iterations: int | None = None):
        """``max_iterations`` overrides ``spec.max_turns`` when given. Leave it
        unset so every adapter in a sweep uses the same per-episode budget."""
        self._client = client
        self._max_iterations = max_iterations

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        """Drive model + tools to completion, recording a normalized trace.

        Expects spec.task to be a dict with:
          - system_prompt: str
          - user_message: str
          - tool_impls: dict[str, callable]
        spec.tools: list of OpenAI-format tool schemas.

        Makes at most ``spec.max_turns`` model calls. If the model still wants
        tools after the last one, the partial trace is returned with
        stop_reason="max_turns" and final_output="".
        """
        env = spec.task
        tool_map = env["tool_impls"]
        messages: list[Any] = [
            {"role": "system", "content": env["system_prompt"]},
            {"role": "user", "content": env["user_message"]},
        ]
        max_turns = self._max_iterations if self._max_iterations is not None else spec.max_turns

        steps: list[TraceStep] = []

        for _ in range(max_turns):
            # Omit `tools` when empty: a tool_filter defense can strip every
            # tool, and most OpenAI-compatible endpoints reject `tools=[]` with
            # a 400. No tools -> the model can only produce a text reply.
            kwargs: dict[str, Any] = {"model": spec.model, "messages": messages}
            if spec.tools:
                kwargs["tools"] = spec.tools
            response = self._client.chat.completions.create(**kwargs)
            msg = response.choices[0].message

            if not msg.tool_calls:
                # Model gave a final text answer
                final = msg.content or ""
                steps.append(TraceStep(step=len(steps), type="model_output", content=final))
                return NormalizedTrace(steps=steps, final_output=final, stop_reason="done")

            # Text the model wrote alongside its tool calls is still model
            # output (it may carry the canary); keep it in the trace.
            if msg.content:
                steps.append(TraceStep(step=len(steps), type="model_output", content=msg.content))

            # Record the assistant message so the model sees its own request.
            # A plain dict (not the SDK object) so the request body matches
            # the LangGraph adapters and malformed args are sanitized.
            messages.append(assistant_message_to_dict(msg))

            # Record every requested call first, then each outcome in order:
            # the same step order the LangGraph adapters produce (one
            # assistant message holding all calls, then one tool message per
            # call), so parallel tool calls yield identical traces.
            parsed = [(call, parse_tool_args(call.function.arguments)) for call in msg.tool_calls]
            for call, args in parsed:
                steps.append(TraceStep(step=len(steps), type="tool_call", name=call.function.name, args=args))

            for call, args in parsed:
                name = call.function.name
                # The shared policy re-checks availability and the defense's
                # tool_call_guard right before executing: a model can free-form
                # a call for a tool that was filtered out of spec.tools.
                outcome = execute_tool_call(
                    name, args, tool_map, spec.tool_call_guard, spec.tool_result_wrapper,
                )

                # tool_blocked (not tool_result) when the call did not run --
                # the judge must not score a blocked attempt as a real leak
                # just because the model requested it with the canary in args.
                steps.append(TraceStep(
                    step=len(steps),
                    type="tool_blocked" if outcome.blocked else "tool_result",
                    name=name,
                    content=outcome.content,
                ))

                messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": outcome.content,
                })

        # Turn budget exhausted while the model still wanted tools.
        return NormalizedTrace(steps=steps, final_output="", stop_reason="max_turns")
