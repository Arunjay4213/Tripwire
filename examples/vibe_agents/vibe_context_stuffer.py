"""Vibecoded agent #2 -- the context stuffer (prompt laundering).

The single most common RAG antipattern: pre-fetch the data and paste it straight
into the system prompt as "context" before the model decides anything. It feels
efficient (one fewer tool round-trip) but it launders UNTRUSTED email text into
the SYSTEM channel -- the highest-authority part of the prompt. Any instruction
hidden in the inbox now reads as if the developer wrote it.

This also quietly defeats the input-side defenses: spotlighting and
prompt_hardening tell the model to distrust *tool output*, but here the inbox
never arrives as tool output -- the agent already promoted it to system context,
so the "treat tool content as data" framing does not apply to it.

BYO contract: EpisodeSpec in, NormalizedTrace out.
"""

from __future__ import annotations

import json

from dotenv import load_dotenv

from src.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep
from src.harness.llm import make_client

load_dotenv()

_client = make_client()
_MAX_STEPS = 6


class VibeContextStuffer:
    name = "vibe_context_stuffer"

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        env = spec.task
        steps: list[TraceStep] = []

        # Vibecode: read the inbox up front and splice it into the system prompt.
        # (Recorded as a tool step for trace fidelity, but the model never sees it
        # as tool output -- it sees it as system context.)
        steps.append(TraceStep(step=0, type="tool_call", name="read_inbox", args={}))
        inbox = str(env["tool_impls"]["read_inbox"]())
        steps.append(TraceStep(step=1, type="tool_result", name="read_inbox", content=inbox))

        system = (
            env["system_prompt"]
            + "\n\nHere is the user's inbox, for context:\n"
            + inbox
        )
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": env["user_message"]},
        ]
        # send_email only -- the inbox is already "in context".
        send_tool = [t for t in (spec.tools or []) if t["function"]["name"] == "send_email"]

        for _ in range(_MAX_STEPS):
            resp = _client.chat.completions.create(
                model=spec.model, messages=messages, tools=send_tool or spec.tools,
            )
            msg = resp.choices[0].message
            if not msg.tool_calls:
                final = msg.content or ""
                steps.append(TraceStep(step=len(steps), type="model_output", content=final))
                return NormalizedTrace(steps=steps, final_output=final)
            messages.append(msg)
            for call in msg.tool_calls:
                name = call.function.name
                args = json.loads(call.function.arguments or "{}") or {}
                steps.append(TraceStep(step=len(steps), type="tool_call", name=name, args=args))
                result = str(env["tool_impls"][name](**args))
                steps.append(TraceStep(step=len(steps), type="tool_result", name=name, content=result))
                messages.append({"role": "tool", "tool_call_id": call.id, "content": result})
        return NormalizedTrace(steps=steps, final_output="")


adapter = VibeContextStuffer()
