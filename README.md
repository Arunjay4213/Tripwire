# tripwire

**An evaluation harness for tool-using AI agents.** Point it at an agent, hit it
with prompt-injection attacks, and get a deterministic pass/fail on whether the
agent can be hijacked into leaking a planted secret (a "canary") or taking a
forbidden action. Designed to run in CI, against *your own* agent.

The focus is **evaluation rigor**: a no-human-judgment scoring path, fixed seeds,
and reproducible runs. Prompt injection is just the domain that makes the
scoring clean.

## The bet

Does the **orchestration layer** — LangGraph vs. CrewAI vs. a raw tool loop —
change how vulnerable an agent is to injection, with the model and task held
fixed? That's the open question this project is built to answer.

## How it works

```
agent + task  ──>  adapter  ──>  normalized trace  ──>  judge  ──>  pass / fail
                (per framework)   (framework-agnostic)  (pure Python,
                                                          no LLM)
```

Every orchestrator plugs in behind one contract (`src/adapters/base.py`): it
takes an episode spec and returns a normalized trace. The judge and attacks read
*only* that trace, so they never know which framework ran — that's what makes the
comparison fair.

## Layout

| Path | What |
|------|------|
| `src/harness/` | runner, canary injection, deterministic judge, reporter |
| `src/adapters/` | the contract + one adapter per orchestrator (raw loop, LangGraph, …) |
| `src/attacks/` | injection strategies (wraps AgentDojo's, plus an iterative attacker) |
| `src/config/` | threat model / run config |
| `spike/` | week-0 experiment to validate the bet before the full build |
| `docs/` | provider ToS notes |

## Status

🚧 **Skeleton.** Contracts and module structure are in place; behavior is stubbed
with `TODO`s and lands incrementally. See `roadmap tripwire.pdf` for the plan.

## Credits

Builds on [AgentDojo](https://github.com/ethz-spylab/agentdojo) (attack suites,
environments) and known attack methods (e.g. PAIR). tripwire's contribution is
the harness, the measurement methodology, and — if it holds — the orchestrator
finding.
