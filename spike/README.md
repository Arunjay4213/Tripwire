# spike/ — Week-0 throwaway experiments

Goal (roadmap §0.4): test the orchestrator hypothesis cheaply BEFORE committing
six weeks. Same model + same task + same attack, different agent loop ->
different attack-success rate?

- **Run A (native):** AgentDojo's own pipeline -> record ASR.
- **Run B (alternate loop):** one minimal ReAct-style loop (ideally LangGraph)
  calling the SAME AgentDojo tools over the SAME environment, same model, same
  tasks -> record ASR.
- Compare across a few seeds to gauge noise.

Write the §0.5 decision-gate outcome here before continuing:
- ASR differs meaningfully + stably -> orchestrator finding is real.
- ASR basically the same -> pivot headline to evaluation rigor itself.

This dir is throwaway. Nothing here is imported by `src/`.
