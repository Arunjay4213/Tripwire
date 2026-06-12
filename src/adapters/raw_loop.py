"""Raw tool-loop adapter — minimal ReAct-style loop, no framework.

Baseline / control for the orchestrator hypothesis (roadmap Week 1 + §0.4).
Implements the Adapter contract from base.py.
"""

from __future__ import annotations

from .base import EpisodeSpec, NormalizedTrace


class RawLoopAdapter:
    name = "raw_loop"

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        # TODO Week 1: drive model + tools to completion (or step cap),
        # recording each tool_call / tool_result / model_output as a TraceStep.
        raise NotImplementedError
