# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Tripwire is an evaluation harness that measures AI agent vulnerability to prompt injection attacks. It tests whether orchestration layers (LangGraph, CrewAI, raw tool loop) affect agent hijackability when model and task are held constant.

**Pipeline**: `agent + task → adapter (per-framework) → normalized trace → deterministic judge → pass/fail`

## Commands

```bash
# Install dependencies (into direnv-managed Python 3.13)
pip install -r requirements.txt

# Run all tests (26 tests, ~0.03s)
python -m pytest tests/ -v

# Run single test file
python -m pytest tests/test_judge.py -v

# Run single test
python -m pytest tests/test_judge.py::test_canary_in_body -v

# Run spike experiments (require GROQ_API_KEY in .env)
python spike/hello_groq.py          # verify Groq connectivity
python spike/tool_calling.py        # tiny attack demo
python spike/run_agentdojo.py       # AgentDojo benchmark (6 episodes smoke, 180 full)
```

No Makefile, no build step, no linter configured yet. Just pip + pytest.

## Architecture

**Core contract** (`src/adapters/base.py`): Every framework adapter takes an `EpisodeSpec` and returns a `NormalizedTrace` (list of `TraceStep` dataclasses). Judge and attacks read ONLY the trace — never framework internals. This is what makes cross-framework comparison fair.

**Implemented modules:**
- `src/harness/judge.py` — `attack_succeeded()`: pure Python, no LLM. Returns True if canary string appears in any arg of a `send_email` tool call in the trace.
- `src/harness/stats.py` — `wilson_ci()`: Wilson score confidence interval for honest error bounds at small sample sizes.

**Stubs (TODO):** `src/harness/canary.py`, `src/harness/runner.py`, `src/harness/reporter.py`, `src/adapters/raw_loop.py`, `src/attacks/base.py`

**spike/** — Throwaway week-0 experiments. NOT imported by `src/`. Used to validate approach before full build.

## Key Design Decisions

- **Deterministic judge** — no LLM in scoring path. Reproducible, CI-friendly.
- **Fixed seeds** — `environment_seed` on `EpisodeSpec` enables exact reproducibility.
- **Adapter protocol** — `runtime_checkable` Protocol class. Add new frameworks by implementing one class.
- **Groq as provider** — OpenAI-compatible API, free tier, fast inference. Configured via `.env` (see `.env.example`).
- **agentdojo** dependency — provides benchmark suites, attack strategies, and tool environments.

## Conventions

- Type hints throughout, `from __future__ import annotations` in all modules.
- Dataclasses for data flow (`EpisodeSpec`, `NormalizedTrace`, `TraceStep`, `EpisodeResult`). No mutable defaults; use `field(default_factory=...)`.
- Tests use hand-built `NormalizedTrace` objects — no mocking, no LLM calls.
- When pairing, add to existing files rather than creating parallel solution files.
