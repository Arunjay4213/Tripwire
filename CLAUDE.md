# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Tripwire is an evaluation harness that measures AI agent vulnerability to prompt injection attacks. It tests whether orchestration layers (raw tool loop, LangGraph single-agent, LangGraph multi-agent relay) affect agent hijackability when model and task are held constant.

**Pipeline**: `agent + scenario → adapter (per-framework) → normalized trace → deterministic judge → pass/fail + security feedback`

## Commands

```bash
# Install for development (editable, with test + optional extras)
pip install -e ".[dev]"        # or: uv pip install -e ".[dev]"

# Run all tests (293 tests, fully offline, ~4s)
python -m pytest tests/ -q

# Run a single test file / test
python -m pytest tests/test_judge.py -q
python -m pytest tests/test_scenarios.py::test_resolve_scenarios_known_and_unknown -q

# Create a starter config to edit (what a fresh `pip install` user runs first)
python -m tripwire init

# Run a sweep against the built-in adapters (needs a provider key in .env)
python -m tripwire --config tripwire/config/threat_model.example.yaml --smoke

# Point it at your own agent (same attacks, scenarios, judge, and security report)
python -m tripwire --config <cfg> --agent path/to/your_agent.py

# Build the distributable package
uv build
```

Published on PyPI as `tripwire-eval` (the import package and CLI stay `tripwire`, like scikit-learn -> import sklearn). Packaging lives in `pyproject.toml` (hatchling); `uv publish` on a `vX.Y.Z` tag via `.github/workflows/release.yml`. No linter configured.

## Architecture

**Core contract** (`tripwire/adapters/base.py`): Every framework adapter takes an `EpisodeSpec` and returns a `NormalizedTrace` (list of `TraceStep` dataclasses). Judge and attacks read ONLY the trace — never framework internals. This is what makes cross-framework comparison fair.

**Harness** (`tripwire/harness/`):
- `judge.py` - pure Python, no LLM. `attack_succeeded()`/`attack_exfiltrated()`: True only if the canary reaches a `send_email` recipient OUTSIDE the scenario's authorized set (destination-aware exfiltration, NOT canary-in-any-arg). `attack_grade` is the recipient-blind 0/1/2 signal; `task_completed_for` checks the benign task.
- `canary.py` - `make_canary(seed)`: deterministic canary from seed (MD5-based). `inject()`: plants canary into the system prompt.
- `runner.py` - `run_episode()`: wires scenario + canary + attack + adapter + judge for one episode. `run_sweep()`: loops adapters × models × scenarios × attacks × defenses × seeds. Adaptive campaigns via `run_campaign`/`run_scenario_tree_campaign`.
- `reporter.py` - `print_asr_table()` (grouped by adapter/scenario/attack/defense, Wilson CI), `print_campaign_table()`, and `print_security_report()` - the actionable "which attacks got through and how to fix" feedback.
- `advice.py` - per-attack remediation knowledge base backing the security report.
- `stats.py` - `wilson_ci()`: Wilson score CI for honest error bounds at small n.

**Adapters** (`tripwire/adapters/`): `raw_loop.py` (minimal ReAct baseline), `langgraph_adapter.py` (single-agent LangGraph), `multi_agent_adapter.py` (LangGraph relay: agent A summarizes the inbox for agent B). `loader.py` also loads a bring-your-own agent file (`--agent`).

**Scenarios** (`tripwire/scenarios.py`): the tasks the agent is attacked on - `invoice` (default), `helpdesk`, `calendar`, `expense`. Each plants the secret, defines a legitimate task + AUTHORIZED recipient, and builds a full `EpisodeSpec`. Selected via `scenarios:` in the config.

**Defenses** (`tripwire/defenses/`): the ladder - `prompt_hardening` (L1), `spotlighting` (L2), `tool_filter`, `outbound_guard` (L3). Four hooks: `wrap_system_prompt`, `filter_tool_calls`, `check_tool_call`, `wrap_tool_result`.

**Attacks** (`tripwire/attacks/`): `base.py` is the `Attack` protocol (`name` + `render(canary) -> str`; attacks never embed the canary). The suite (see `docs/attacks.md`): templated baselines (`agentdojo_wrappers.py`), hand-crafted attacks (`fixed_injection.py`: metadata_exfil, public_identifier, forged_boundary, prerequisite_mirror, mundane_redirect), and adaptive attackers (`iterative.py` PAIR, `tree_attacker.py` TAP). Registered in `config/loader.py`.

## Key Design Decisions

- **Deterministic judge** — no LLM in scoring path. Reproducible, CI-friendly.
- **Destination-aware success** - success = exfiltration to an UNAUTHORIZED recipient (the secret leaving its intended channel), NOT the canary appearing in any email. The canary appended to the legitimate email is not a leak. See `docs/methodology.md`.
- **Actionable output** - a sweep ends with `print_security_report`: which attacks got through, per (agent, defense), and the concrete fix for each.
- **Fixed seeds** — `environment_seed` on `EpisodeSpec` enables exact reproducibility (the deterministic canary; the model still samples at temperature).
- **Adapter protocol** — `runtime_checkable` Protocol class. Add new frameworks by implementing one class.
- **Attack protocol** — `render(canary)` returns injection payload. Attack receives canary but good attacks (like `FixedInjection`) don't embed it — they trick the agent into volunteering it.
- **Provider-agnostic** - any OpenAI-compatible endpoint, chosen by env (see `tripwire/harness/llm.py`). Default is Anthropic's compat endpoint (`claude-haiku-4-5`); Groq/OpenAI also work. `ATTACKER_MODEL` sets a separate strong model for the adaptive attackers.
- **agentdojo** dependency — provides benchmark suites, attack strategies, and tool environments.
- **Provider ToS** — see `docs/provider-policy.md`. Do not run at volume against closed-model APIs without authorization.

## Conventions

- Type hints throughout, `from __future__ import annotations` in all modules.
- Dataclasses for data flow (`EpisodeSpec`, `NormalizedTrace`, `TraceStep`, `EpisodeResult`). No mutable defaults; use `field(default_factory=...)`.
- Tests use hand-built `NormalizedTrace` objects — no mocking, no LLM calls.
- When pairing, add to existing files rather than creating parallel solution files.
