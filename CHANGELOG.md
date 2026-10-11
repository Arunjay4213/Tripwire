# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A **CrewAI adapter** (`adapters: [crewai]`), a third orchestration style behind the same `EpisodeSpec` -> `NormalizedTrace` contract, so the framework comparison covers a non-graph composition model.
  CrewAI is an optional extra (`pip install 'tripwire-eval[crewai]'`) imported lazily, so a core install is unaffected and listing an uninstalled adapter gives a clear message instead of an import error.
- `tests/conftest.py`, which plants a dummy provider key when the environment has none, so `pytest` runs out of the box.
  The suite is offline; the key only satisfies the OpenAI client constructor. A real key already in the environment is left alone.
- **Cross-adapter contract tests** (`tests/test_adapter_equivalence.py`): the same scripted agent behavior is run through every adapter and asserted to reach the same judge verdict.
  This is what makes a cross-framework ASR comparison meaningful — it rules out the possibility that a difference between adapters is an artifact of how each one writes its trace rather than a real difference in hijackability.
  In particular, a guard-denied call must be typed `tool_blocked` in every framework; if one adapter recorded it as a `tool_result`, that adapter's defended ASR would be silently inflated.

## [0.2.0] - 2026-08-10

Hardening pass for the open-source release.

### Fixed

- Bad configs now print a single clear `Error: ...` line and exit non-zero instead of a Python traceback.
  This covers a missing file, an empty or comment-only file, a non-mapping top level, a missing required key, an unknown adapter/attack/scenario/defense name, and a scalar where a list is required (e.g. `seeds: 5`).
- The adaptive attackers (`iterative`, `tree_attacker`) no longer silently skip a whole campaign when no attacker model is set in the environment.
  They fall back to the model under test; `ATTACKER_MODEL` still overrides it for a separate, stronger attacker.
- The LangGraph adapter no longer crashes when the model requests a tool it was never given (a hallucinated or defense-filtered tool); it reports the call as unavailable, matching the multi-agent adapter.
- All adapters omit the `tools` argument when the tool list is empty, instead of sending `tools=[]` and getting a 400 from most OpenAI-compatible endpoints (this happened when a `tool_filter` defense removed every tool).
- The benign-task utility check now parses `to`/`recipients`/`cc`/`bcc` (string or list), the same as the leak check, so task completion is not under-counted when a model emits `recipients=[...]`.
- When the sweep gives up on an episode after retries, it now prints the full traceback, so a bug in a bring-your-own `--agent` adapter is debuggable instead of showing as a vague provider error.
- The adaptive-attacker effort-to-break table and the security report now group by scenario, so a multi-scenario sweep no longer merges distinct tasks into one row.

### Changed

- Removed the required `suites` config key, which nothing in the run path used.
  Existing configs that still carry a stray `suites:` key keep loading; the key is ignored.
- Bounded the `langgraph` and `langchain-core` dependencies to `<2` to avoid a future major release breaking a fresh install.
- The starter, example, and CI configs now lead with a strong attack, so a `--smoke` run demonstrates a real leak instead of running only the near-zero `direct` baseline.
- Renamed the GitHub Actions workflow to `CI` so the README status badge label matches.

### Removed

- The throwaway `spike/` experiment directory, which was imported by nothing and had been shipping in the source distribution.

### Added

- `SECURITY.md` describing how to report a vulnerability and what is in scope for a red-team eval harness.
- `CONTRIBUTING.md` with dev setup, the adapter/attack/defense/scenario extension points, and conventions.
- This changelog.

## [0.1.0] - 2026-08-10

Initial release.

### Added

- Cross-framework prompt-injection evaluation harness with a single adapter contract (`EpisodeSpec` in, `NormalizedTrace` out), so the judge and attacks read only the normalized trace.
- Built-in adapters: raw tool loop, single-agent LangGraph, and a multi-agent LangGraph relay.
- Bring-your-own-agent support via `tripwire --agent path/to/agent.py`, running the same attacks, scenarios, judge, and report against your own agent.
- Scenarios (`invoice`, `helpdesk`, `calendar`, `expense`), each with its own task and authorized recipient.
- An attack suite: templated baselines, hand-crafted injections, and the adaptive PAIR and TAP attackers.
- A defense ladder: prompt hardening, spotlighting, tool filtering, and an outbound guard.
- A deterministic, LLM-free judge with destination-aware exfiltration scoring, plus Wilson confidence intervals for honest error bounds at small sample sizes.
- An actionable security report at the end of a sweep: which attacks got through, per agent and defense, and how to close each gap.
- A CI gate (`scripts/ci/check_asr_threshold.py`) that fails the build when attack success rate exceeds a threshold.
- Provider-agnostic client for any OpenAI-compatible endpoint, and an optional AgentDojo bridge.

[Unreleased]: https://github.com/Arunjay4213/Tripwire/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Arunjay4213/Tripwire/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Arunjay4213/Tripwire/releases/tag/v0.1.0
