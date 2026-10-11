"""CrewAI adapter — a third orchestration layer behind the same contract.

The point of this adapter is the project's core hypothesis: hold the model,
task, attack, and defense constant, vary ONLY the orchestration framework, and
see whether hijackability moves. raw_loop is the no-framework control,
langgraph/multi_agent are graph-based, and CrewAI is the role/goal/crew style --
a genuinely different way of composing an agent, not another graph.

Same contract as every other adapter (see base.py): EpisodeSpec in,
NormalizedTrace out. The judge, attacks, and defenses read only that trace, so
they never learn CrewAI ran.

Two fidelity notes, because CrewAI's model differs from the others:

- **No raw system-prompt slot.** CrewAI composes an agent's system message from
  role/goal/backstory rather than taking one verbatim. The harness's system
  prompt (which is where canary.inject plants the secret, and where a defense's
  wrap_system_prompt lands) goes into `backstory`, the free-form persona field,
  so the planted id and any hardening instruction are both in the agent's
  context exactly as they are for the other adapters.
- **The trace is recorded at the tool boundary, not from framework events.**
  CrewAI wraps tool execution in its own machinery, so rather than
  reverse-engineering its event stream we wrap each tool impl itself (see
  _ToolRecorder). That records the model's *requested* args, honors
  spec.tool_call_guard before anything executes, and applies
  spec.tool_result_wrapper to real output -- the three things scoring and the
  defense ladder depend on. It also keeps the scoring-critical logic testable
  offline, with no crew run and no network.

CrewAI is an optional dependency (`pip install 'tripwire-eval[crewai]'`),
imported lazily so that merely importing the adapter registry -- which every
CLI run does -- never requires it.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from .base import EpisodeSpec, NormalizedTrace, TraceStep

_INSTALL_HINT = (
    "The 'crewai' adapter needs the optional CrewAI dependency, which is not "
    "installed. Install it with:\n"
    "    pip install 'tripwire-eval[crewai]'\n"
    "or, from a checkout:\n"
    "    pip install crewai"
)

# Matches RawLoopAdapter's cap: bound the agent loop so a model that never
# stops calling tools cannot hang a sweep.
DEFAULT_MAX_ITERATIONS = 5

# JSON-schema type -> Python annotation for the generated args model. Anything
# unlisted falls back to Any, which accepts whatever the model emits rather than
# failing validation and losing the episode.
_JSON_TO_PY: dict[str, type] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "object": dict,
    "array": list,
}


def _import_crewai():
    """Import CrewAI on first real use, with an actionable message if absent."""
    try:
        import crewai
    except ImportError as e:
        raise ImportError(_INSTALL_HINT) from e
    return crewai


class _ToolRecorder:
    """Executes a tool and records it into the normalized trace.

    One recorder per episode, shared by every wrapped tool, so the steps land in
    a single ordered list. This is the whole scoring contract for this adapter:

    1. record a `tool_call` step carrying the model's full requested args --
       always, even when the call is about to be blocked, since otherwise we
       could not see what it tried;
    2. consult spec.tool_call_guard and, on denial, record `tool_blocked` and
       return the guard's message WITHOUT executing the tool;
    3. otherwise execute, pass the real output through spec.tool_result_wrapper
       (spotlighting's fence lives here), and record `tool_result`.

    A tool the agent asks for but that this episode has no impl for is recorded
    as `tool_blocked` too -- topology, not a defense decision, matching
    LangGraphAdapter and MultiAgentAdapter.
    """

    def __init__(
        self,
        tool_impls: dict[str, Any],
        steps: list[TraceStep],
        tool_call_guard: Any = None,
        tool_result_wrapper: Any = None,
    ) -> None:
        self._tool_impls = tool_impls
        self.steps = steps
        self._guard = tool_call_guard
        self._wrapper = tool_result_wrapper

    def invoke(self, name: str, args: dict[str, Any]) -> str:
        """Run one tool call end to end, returning what the agent should see."""
        args = dict(args or {})
        self.steps.append(
            TraceStep(step=len(self.steps), type="tool_call", name=name, args=args)
        )

        impl = self._tool_impls.get(name)
        if impl is None:
            return self._blocked(name, f"Tool {name!r} is not available to this agent.")

        if self._guard is not None:
            allowed, message = self._guard(name, args)
            if not allowed:
                return self._blocked(name, message)

        result = str(impl(**args))
        if self._wrapper is not None:
            result = self._wrapper(name, result)
        self.steps.append(
            TraceStep(step=len(self.steps), type="tool_result", name=name, content=result)
        )
        return result

    def _blocked(self, name: str, message: str) -> str:
        self.steps.append(
            TraceStep(step=len(self.steps), type="tool_blocked", name=name, content=message)
        )
        return message


def build_args_model(tool_name: str, parameters: dict[str, Any] | None):
    """Build a pydantic model for a tool's arguments from its OpenAI schema.

    CrewAI validates tool input against an `args_schema`, while Tripwire carries
    tool definitions as OpenAI function-calling JSON (the same list every other
    adapter hands straight to the model). This converts one to the other.

    Unknown JSON types map to Any and non-required fields default to None, so a
    model that emits a slightly-off argument set still reaches the tool instead
    of erroring out and silently costing the episode.
    """
    from pydantic import create_model

    parameters = parameters or {}
    properties: dict[str, Any] = parameters.get("properties") or {}
    required = set(parameters.get("required") or [])

    fields: dict[str, Any] = {}
    for prop, meta in properties.items():
        annotation = _JSON_TO_PY.get((meta or {}).get("type", ""), Any)
        if prop in required:
            fields[prop] = (annotation, ...)
        else:
            fields[prop] = (Optional[annotation], None)

    return create_model(f"{tool_name.title().replace('_', '')}Args", **fields)


def _build_tool(schema: dict[str, Any], recorder: _ToolRecorder):
    """Turn one OpenAI tool schema into a CrewAI tool that records through
    `recorder`. Built per episode, since the recorder is per episode."""
    _import_crewai()  # surface the install hint before touching crewai.tools
    from crewai.tools import BaseTool

    function = schema.get("function", schema)
    # Local aliases: a class body cannot read an enclosing function's local of
    # the same name it also assigns (`name: str = name` would raise NameError).
    tool_name = function["name"]
    tool_description = function.get("description", "") or tool_name
    schema_model = build_args_model(tool_name, function.get("parameters"))

    class _TripwireTool(BaseTool):
        name: str = tool_name
        description: str = tool_description
        args_schema: type = schema_model

        def _run(self, **kwargs: Any) -> str:
            return recorder.invoke(tool_name, kwargs)

    return _TripwireTool()


class CrewAIAdapter:
    """Runs an episode as a single-agent CrewAI crew."""

    name = "crewai"

    def __init__(self, max_iterations: int = DEFAULT_MAX_ITERATIONS) -> None:
        # No CrewAI import here on purpose: resolve_adapters() constructs every
        # registered adapter, and constructing this one must not require the
        # optional dependency. The import happens in run().
        self._max_iterations = max_iterations

    def _llm(self, model: str):
        """Build a CrewAI LLM pointed at whichever OpenAI-compatible provider is
        configured, mirroring harness.llm.make_client's precedence (OPENAI_* wins,
        else GROQ_*). LiteLLM's `openai/` prefix is what routes a custom base_url
        through its OpenAI-compatible path.
        """
        crewai = _import_crewai()
        if os.getenv("OPENAI_API_KEY"):
            api_key = os.getenv("OPENAI_API_KEY")
            base_url = os.getenv("OPENAI_BASE_URL") or None
        else:
            api_key = os.getenv("GROQ_API_KEY")
            base_url = os.getenv("GROQ_BASE_URL") or None
        return crewai.LLM(model=f"openai/{model}", api_key=api_key, base_url=base_url)

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        """Drive a CrewAI crew to completion, recording a normalized trace.

        Expects spec.task to be the standard environment dict (system_prompt,
        user_message, tool_impls) and spec.tools to be OpenAI tool schemas --
        identical to what raw_loop.py and the LangGraph adapters consume.
        """
        crewai = _import_crewai()
        env = spec.task

        steps: list[TraceStep] = []
        recorder = _ToolRecorder(
            env["tool_impls"], steps, spec.tool_call_guard, spec.tool_result_wrapper
        )
        # An empty list is expected, not an error: a tool_filter defense can
        # strip every tool, leaving an agent that can only produce text.
        tools = [_build_tool(schema, recorder) for schema in (spec.tools or [])]

        agent = crewai.Agent(
            role="Email assistant",
            goal=env["user_message"],
            backstory=env["system_prompt"],  # see module docstring: no raw system slot
            tools=tools,
            llm=self._llm(spec.model),
            allow_delegation=False,
            verbose=False,
            max_iter=self._max_iterations,
        )
        task = crewai.Task(
            description=env["user_message"],
            expected_output="A short confirmation of what you did.",
            agent=agent,
        )
        crew = crewai.Crew(agents=[agent], tasks=[task], verbose=False)

        output = crew.kickoff()
        final = str(getattr(output, "raw", output) or "")
        steps.append(TraceStep(step=len(steps), type="model_output", content=final))
        return NormalizedTrace(steps=steps, final_output=final)
