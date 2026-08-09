"""Example "bring your own agent" file for `python -m tripwire --agent`.

Tripwire's whole adapter contract is two things (src/adapters/base.py):
`EpisodeSpec` in, `NormalizedTrace` out. A BYO agent file just needs to
satisfy that same contract -- there's no second, simplified interface to
learn. Define ONE of:

  - `run(spec: EpisodeSpec) -> NormalizedTrace`   (this file's approach)
  - `adapter = SomeObject()` with `.name` and `.run(spec) -> NormalizedTrace`
    (use this if your agent is already a class/object, e.g. you're wrapping
    an existing framework integration the way src/adapters/langgraph_adapter.py
    does)

This example is intentionally the simplest possible tool loop -- a trimmed
raw_loop.py -- not a template to copy wholesale. Point --agent at your own
agent's equivalent of the run() function below; the goal is showing the
minimum surface area required, not a reference implementation.

Run it:
    python -m tripwire --config src/config/threat_model.example.yaml \
        --agent examples/byo_agent_example.py --smoke
"""

from __future__ import annotations

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from src.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep

load_dotenv()

_client = OpenAI(api_key=os.getenv("GROQ_API_KEY"), base_url=os.getenv("GROQ_BASE_URL"))

_MAX_ITERATIONS = 5


def run(spec: EpisodeSpec) -> NormalizedTrace:
    """spec.task is {"system_prompt", "user_message", "tool_impls"}; spec.tools
    is a plain OpenAI function-calling JSON schema list -- same shape every
    built-in adapter reads. Tripwire supplies both; you never construct them.
    """
    env = spec.task
    messages = [
        {"role": "system", "content": env["system_prompt"]},
        {"role": "user", "content": env["user_message"]},
    ]

    steps: list[TraceStep] = []
    for _ in range(_MAX_ITERATIONS):
        response = _client.chat.completions.create(
            model=spec.model, messages=messages, tools=spec.tools,
        )
        message = response.choices[0].message

        if not message.tool_calls:
            final = message.content or ""
            steps.append(TraceStep(step=len(steps), type="model_output", content=final))
            return NormalizedTrace(steps=steps, final_output=final)

        messages.append(message)
        for call in message.tool_calls:
            name = call.function.name
            args = json.loads(call.function.arguments or "{}") or {}
            steps.append(TraceStep(step=len(steps), type="tool_call", name=name, args=args))

            # Defense enforcement is opt-in per adapter: check tool_call_guard
            # (if the active defense set one) before running the real tool.
            # Skipping this line still works -- it just means your agent
            # can't be gated by a mid-loop defense like tool_filter.
            if spec.tool_call_guard is not None:
                allowed, guard_message = spec.tool_call_guard(name, args)
                result = guard_message if not allowed else str(env["tool_impls"][name](**args))
            else:
                result = str(env["tool_impls"][name](**args))

            steps.append(TraceStep(step=len(steps), type="tool_result", name=name, content=result))
            messages.append({"role": "tool", "tool_call_id": call.id, "content": result})

    return NormalizedTrace(steps=steps, final_output="")
