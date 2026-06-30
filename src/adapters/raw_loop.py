"""Raw tool-loop adapter — minimal ReAct-style loop, no framework.

Baseline / control for the orchestrator hypothesis (roadmap Week 1 + §0.4).
Implements the Adapter contract from base.py.
"""

from __future__ import annotations

import json

from openai import OpenAI

from .base import EpisodeSpec, NormalizedTrace, TraceStep


class RawLoopAdapter:
    name = "raw_loop"

    def __init__(self, client: OpenAI, max_iterations: int = 5):
        self._client = client
        self._max_iterations = max_iterations

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        """Drive model + tools to completion, recording a normalized trace.

        Expects spec.task to be a dict with:
          - system_prompt: str
          - user_message: str
          - tool_impls: dict[str, callable]
        spec.tools: list of OpenAI-format tool schemas.
        """
        env = spec.task
        messages = [
            {"role": "system", "content": env["system_prompt"]},
            {"role": "user", "content": env["user_message"]},
        ]

        steps: list[TraceStep] = []
        step_idx = 0

        for _ in range(self._max_iterations):
            response = self._client.chat.completions.create(
                model=spec.model,
                messages=messages,
                tools=spec.tools,
            )
            msg = response.choices[0].message

            if not msg.tool_calls:
                # Model gave a final text answer
                final = msg.content or ""
                steps.append(TraceStep(
                    step=step_idx, type="model_output", content=final,
                ))
                return NormalizedTrace(steps=steps, final_output=final)

            # Record the assistant message so the model sees its own request
            messages.append(msg)

            for call in msg.tool_calls:
                name = call.function.name
                args = json.loads(call.function.arguments or "{}") or {}

                # Record the tool call
                steps.append(TraceStep(
                    step=step_idx, type="tool_call", name=name, args=args,
                ))
                step_idx += 1

                # Execute the tool
                result = str(env["tool_impls"][name](**args))

                # Record the tool result
                steps.append(TraceStep(
                    step=step_idx, type="tool_result", name=name, content=result,
                ))
                step_idx += 1

                # Feed result back to model
                messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": result,
                })

        # Hit iteration cap — return what we have
        return NormalizedTrace(steps=steps, final_output="")
