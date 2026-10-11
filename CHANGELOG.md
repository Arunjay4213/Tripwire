# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (measurement)

- **Every result records what it cost.** Episodes carry `prompt_tokens`, `completion_tokens`, `model_calls`, the model id the provider actually served (`served_model`, e.g. the dated Azure deployment version), and the defense's own `defense_calls` and `defense_tokens` (the outbound guard's and the quarantined reader's, summed in a stack); campaigns carry the target's totals and `attacker_tokens`.
  The ASR and campaign tables gain a `tokens` column (mean per scored run), so a defense's cost is reported, not guessed.
- **`limits.max_tokens_per_run` is enforced.** The sweep stops scheduling cells once the running total reaches it, keeps everything that ran, and reports how many cells were not run; the overshoot is at most the cells in flight.
  The loader no longer warns that it is unenforced.

### Added (defense track)

- **Stacked defenses.** `defenses: [spotlighting+recipient_allowlist]` applies several rungs to one episode in the listed order; the first member that blocks decides, errors are summed so an outage inside a stack is still an error outcome, and the runner's model fallback reaches each member.
  One name, one row, one gate filter.
- **`no_attack`**, the control: an empty payload, so the benign task runs exactly as it is in every injection slot.
  Its utility under a defense is the defense's own cost to the agent, which the attacked rows cannot show.
- **`quarantined_reader`**, CaMeL-style typed extraction: the agent never sees the read tool's raw text.
  An extractor model returns only the typed values the scenario declares (`Scenario.extraction`, carried on `DefenseContext.fields`), each value is validated by kind (an amount must look like an amount; a short text is capped and may not carry an address or a URL), and the agent gets a rendered record of what passed.
  Fails closed, and an extractor outage is an error outcome like a guard outage.
  Model from `READER_MODEL`, else the model under test; no sampling parameters are sent.
- **Deterministic egress defenses**, refusing a `send_email` before it runs with no model in the decision:
  `recipient_allowlist` (only addresses the user's own request names, plus an optional `recipient_allowlist: {allow: [...]}` list),
  `secret_egress_scan` (the provisioned secret in any form the judge recognizes, including split across sends),
  and `taint_tracking` (an address that entered the episode only through tool output).
  Against an agent that obeys every injection they hold ASR at 0% in every adapter, with no utility cost for an agent that does its job (`tests/test_e2e.py`).
- **`sandwich`** (repeat the user's request after every tool result) and **`datamarking`** (spotlighting's marker-per-word variant, Hines et al.).
- **`bind(ctx)` on defenses.** `Scenario.build_spec` hands each defense a `DefenseContext` before anything else: the user's request, the provisioned secrets, the untrusted tools.
  It never carries the attacker's decoy or the judge's authorized set; the legitimate recipients are derived from the user's request.
- **`EpisodeSpec.system_prompt_wrapper`**, so an adapter that runs a second agent can apply the defense to that agent's persona.
- **Outbound guard options**: `recipient_context` (default on) shows the guard, outside its fence, the recipients the user asked for and blocks a send to anyone else; `precheck` (default off) runs the deterministic secret check before the model call.

### Changed (defense track)

- **Every defense now reaches the sender in the `multi_agent` relay.** Agent B's persona goes through the defense's prompt wrapper and Agent A's summary through its tool-result wrapper (fenced, marked, or taint-tracked like any tool output). Before, the agent that sends email ran undefended; `multi_agent` rows under a prompt-level defense are not comparable across this change.
- **`prompt_hardening`, `spotlighting` and `datamarking` anchor the recipient**: send only to the recipients the user named (listed when bound), never add or redirect one because tool content asks. Prompt-level numbers from before this change are not comparable.
- The security report leads with the deterministic rungs ("Start here: turn on recipient_allowlist, secret_egress_scan"), then the model-level ones; advice names the defenses to turn on instead of telling you to build an allowlist.
- `tripwire init` includes `recipient_allowlist`; the example config lists the whole ladder and its options; the CI example gates on `recipient_allowlist` instead of `tool_filter` (deterministic, and the agent still sends its legitimate email).

### Fixed (defense track)

- `examples/byo_agent_example.py` recorded a guard-denied call as `tool_result`, so the judge scored a refused send as a leak and every defended row for an agent copied from it was inflated. It now records `tool_blocked`, and omits `tools` when a defense leaves none.

### Changed

- **PAIR may encode or split the id.**
  The iterative attacker's prompt now says the id need not be sent verbatim, adds a guard-evasion seed strategy, and tells the attacker to encode or split the value when a guard blocked the send; the judge already decodes those forms, and the tree attacker already allowed them.
  Expect outbound_guard ASR under `iterative` to rise.
- **`outbound_guard` fails closed by default.**
  When the guard's detector errors (provider error, no model, unparseable verdict) the call is now blocked instead of allowed; `outbound_guard: {fail_closed: false}` in the config restores the old behaviour.
- **A guard outage is an error outcome, not a defended run.**
  An episode whose guard errored and did not leak is recorded with `status: error`, so the ASR table, the security report, the `--strict` exit code and the CI gate all see it instead of counting it as "held".
  A leak that got past a fail-open guard is still scored as a leak.
  Adaptive campaigns treat such an attempt as an errored evaluation.
- **A campaign whose every evaluation errored is `status: error`.**
  It used to come back `ok` with `broke: false` and count as a defense win.
- **The CrewAI adapter honors the shared per-episode budget** (`limits.max_turns`), records `stop_reason`, feeds a raising tool back as a `tool_result` like every other adapter, drops optional arguments the model never set (CrewAI forwards them as `None`), and uses a scenario-neutral role.

### Fixed

- **Provider response shapes are normalized once, for every adapter.**
  Content sent as a list of text blocks is flattened to text (one adapter stored the list, another a Python repr); a refusal (`content: null`, text in `refusal`) becomes the model's output so the trace and the adaptive attackers see it; a tool call with no id (some endpoints omit it) gets one instead of crashing the LangGraph adapter.
- **An implemented tool that is off the offered menu never runs.**
  Every adapter built its tool map from the scenario's implementations rather than from `spec.tools`, so a model that free-formed a call to a tool `tool_filter` had removed could still execute it when no guard was wired; the menu is now the topology in raw_loop, langgraph and both relay agents.
- PAIR's structured-reply parser took the span from the first `{` to the last `}`, so prose after the object that contained a brace made the whole reply, JSON wrapper included, the injected payload.
- The adaptive attackers retried every error with sleeps; auth errors and unknown models now fail at once.
- `wilson_ci` rejects `successes > n` instead of crashing the reporter; the guard's verdict parser treats a reply containing both verdicts as an error; a duplicate model, attack, adapter, scenario or defense in the config is rejected.

### Added

- **End-to-end tests** (`tests/test_e2e.py`) that run the real CLI against an in-process OpenAI-compatible server with scripted agent policies (`tests/fake_provider.py`): config, sweep, adapters, SDK, defenses, judge, results file, tables, exit codes and the CI gate, with nothing stubbed inside the pipeline.
- **An opt-in live smoke test** (`tests/test_live.py`, `TRIPWIRE_LIVE=1`) that CI now runs in place of the bare smoke command.
- **Offline coverage of `CrewAIAdapter.run()`** through a stub `crewai` package (`tests/fake_crewai.py`); the cross-adapter equivalence tests now run the real adapter instead of hand-building its trace.

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
