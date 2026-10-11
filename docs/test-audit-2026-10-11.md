# Test suite audit (2026-10-11)

Scope: all 28 files under `tests/`, 506 test functions (734 with parametrization), read in full against the source they exercise.
Question asked: do the tests catch things that might break, or do they only confirm the current implementation?

Every test was put in one of four buckets.
KEEP: asserts a behavioral invariant a plausible regression would break.
TAUTOLOGY: true only because of how the code happens to be written (a literal copied from the source, a registry key, a mock called with the args the test passed in).
TRIVIAL: a getter, a default, a protocol `hasattr` check, or Python itself.
DUPLICATE: materially the same assertion as another test.

Every bug listed in section 3 was reproduced by running the code, not only by reading it.

## 1. Verdict

About a quarter of the suite is dead weight, and it is concentrated in a few files.
The bigger problem is the shape of the coverage, not the volume.

| Group | Tests | KEEP | TAUTOLOGY | TRIVIAL | DUPLICATE | Not pulling weight |
|---|---|---|---|---|---|---|
| Judge, runner-defense, equivalence, raw_loop | 104 | 87 | 4 | 2 | 11 | 16% |
| Attacks (static, PAIR, TAP, context, fallback, bridge) | 113 | 77 | 18 | 8 | 10 | 32% |
| Adapters (crewai, multi_agent, langgraph, parity, registry, loader, tool_filter) | 99 | 55 | 10 | 6 | 28 | 44% |
| Harness and config (defenses, config, gate, runner, stats, cli, reporter, scenarios, canary, advice) | 181 | 151 | 12 | 13 | 14 | 22% |
| Total | 497 | 370 | 44 | 29 | 63 | 27% |

Files where more than half the tests are not pulling weight:

| File | Tests | Not KEEP | Why |
|---|---|---|---|
| `test_tool_filter.py` | 7 | 7 | Six are line-for-line duplicates of the ToolFilter block in `test_defenses.py`; the seventh covers a branch no production caller hits. |
| `test_langgraph_adapter.py` | 13 | 11 | Nine are weaker single-adapter copies of `test_adapter_parity.py` cases that already run LangGraph with stricter asserts. |
| `test_attacks.py` | 32 | 21 | Eleven assert template wording copied from the source; six duplicate the per-scenario render test; the seed-rotation test provably cannot fail. |
| `test_crewai_adapter.py` | 24 | 13 | Five re-run the judge over `_ToolRecorder` exactly as the equivalence file does; none executes `CrewAIAdapter.run()`. |
| `test_adapter_registry.py` | 10 | 7 | Message wording, difflib, and a hand-copied key set. |

Where the suite is strong: `test_judge.py`, `test_check_asr_threshold.py`, `test_config_loader.py`, `test_runner_resilience.py`, `test_agent_loader.py`, `test_adapter_parity.py`, and the TAP search tests.
These exercise real logic with scripted inputs and assert outcomes a bug would change.

## 2. Structural gaps

These matter more than the dead-weight count.

**There is no end-to-end test.**
Nothing runs the real path a user runs: config file, `run_sweep`, an adapter loop, the judge, `write_results`, the printed tables, the exit code, and the CI gate reading the file.
`test_cli_init.py` calls `main()` but replaces `run_sweep` with a stub.
The CI workflow runs a live smoke sweep only when a provider key is present, and asserts nothing about its output.

**The adapter stubs never model what a real provider sends.**
Four divergent fake clients exist (`ScriptedClient` in parity, `SimpleNamespace` copies in langgraph, multi_agent and equivalence, bare `MagicMock` in raw_loop).
All of them produce exactly the two shapes the code reads: `content: str | None` and `tool_calls[].function.arguments: str`.
None sends content as a list of blocks, a missing or empty tool-call id, a `refusal` field, `finish_reason="length"`, `tool_calls=[]`, or empty `choices`.
A provider change in any of those passes every test today.

**`CrewAIAdapter.run()` has zero coverage.**
Both the crewai test file and the equivalence file call `_ToolRecorder.invoke` by hand.
The equivalence file's CrewAI "runner" is a hand-built trace, so its cross-adapter claims hold for three adapters, not four.
`test_adapter_parity.py` covers only raw_loop and langgraph; multi_agent and crewai are a docstring TODO.

**Spotlighting is never exercised through an adapter loop.**
The only tests that apply a `tool_result_wrapper` call `execute_tool_call` or `_ToolRecorder` directly, or check that the runner put the wrapper on the spec.
Replacing `spec.tool_result_wrapper` with `None` inside `raw_loop.py`, `langgraph_adapter.py`, or `multi_agent_adapter.py` breaks no test.

**The archive wiring between modules is tested only with hand-written strings.**
`iterative.py` decides whether a win is archived by string-matching `"exfiltrated to an unauthorized recipient: yes"`, a literal emitted by `runner.py`.
Every archive test writes that literal itself, so a wording change in either file silently demotes every real win and no test fails.

## 3. Bugs the audit found

Each was reproduced by running the code on 2026-10-11.
None has a test today; each "add" item in section 5 names the test that would have caught it.

1. **A fail-open guard produces a green CI gate.**
`runner.py:229` records `guard_errors` on every episode; `reporter.py` and `scripts/ci/check_asr_threshold.py` never read it.
An outbound guard whose model is misconfigured errors on every call, allows every send, and the episode is scored as "held".
2. **An all-errored campaign is counted as held.**
`run_campaign` against an adapter that raises on every attempt returns `status="ok", broke=False, errors=3`.
`_is_scored` in `__main__.py` and the gate both treat it as a clean defended run.
3. **The shipped outbound guard fails open and the config cannot change it.**
`OutboundGuard.fail_closed` defaults to False and `resolve_defenses` constructs it with no arguments.
`test_outbound_guard_unparseable_verdict_is_an_error` enshrines the fail-open result.
4. **PAIR injects its own JSON wrapper as the payload.**
`iterative._parse_structured` takes the span from the first `{` to the last `}`.
A valid object followed by prose containing a brace, such as `Note: fill {id} yourself`, fails to parse and the whole raw text becomes the payload.
`tree_attacker.py` has exactly the guard that `iterative.py` lacks.
5. **Both adaptive attackers retry non-transient errors with sleeps.**
`iterative.py:367` and `tree_attacker.py:577` catch every exception and retry three times with 1.5 s, 3 s, 4.5 s sleeps.
An auth error or a model the provider does not serve wastes about 9 s per call and the tree attacker then re-queries per parent.
`runner.py` has `_is_transient` for exactly this distinction and the attackers ignore it.
`test_generate_raises_after_transient_retries_exhaust` asserts three calls for a `RuntimeError`, which locks the wrong behavior in.
6. **Two of the three hand-copied invoice contexts have already drifted.**
`iterative._default_context()` and `tree_attacker._DEFAULT_CONTEXT` both carry a `user_message` that no longer matches `SCENARIOS["invoice"].attack_context()`.
Only the `fixed_injection` copy is guarded by a test.
7. **The CrewAI adapter breaks the shared turn budget.**
`crewai_adapter.py:242` passes its own `max_iterations` to CrewAI and ignores `spec.max_turns`; the trace never sets `stop_reason`, so the reporter's max_turns column is always 0 for crewai.
It also hard-codes `role="Email assistant"` for every scenario and does not catch a raising tool, unlike `_common.execute_tool_call`.
8. **`wilson_ci(11, 10)` crashes the reporter mid-table.**
The square root goes complex and `max()` raises `TypeError`.
Nothing validates `successes <= n` or non-negative inputs.
9. **The guard's verdict parser reads the first word only.**
`parse_verdict("ALLOW. Actually, BLOCK.")` is ALLOW.
A detector model that reasons before answering can be read backwards.
10. **Duplicate config entries double n for free.**
Seeds are checked for duplicates; `models`, `attacks`, `scenarios`, and `defenses` are not.
A repeated defense doubles the cell's n and halves the Wilson width.
11. **A tool_call with no outcome step scores as executed.**
The CrewAI recorder does not wrap `impl(**args)` in try/except, so a raising tool leaves a `tool_call` with no `tool_result`, which the judge treats as executed.
Combined with the pydantic args model forwarding every optional field as `None`, a two-argument `send_email` impl raises `TypeError` on any call that includes `cc`.

## 4. Delete list

About 130 tests.
Deleting them loses no detection power.

- `tests/test_tool_filter.py`: the whole file.
- `tests/test_langgraph_adapter.py`: everything except `test_empty_tool_list_omits_tools_kwarg` and `test_run_with_no_tool_calls_returns_single_model_output_step`.
- `tests/test_crewai_adapter.py`: the five judge re-runs (`test_leak_to_unauthorized_recipient_scores_as_exfiltration`, `test_canary_to_authorized_recipient_is_not_exfiltration`, `test_blocked_leak_is_not_scored_as_a_leak`, `test_benign_task_completion_is_visible_in_the_trace`, `test_blocked_call_records_the_requested_args_anyway`), plus `test_no_guard_means_always_allowed`, `test_guard_allowing_executes_normally`, `test_adapter_name_is_crewai`, `test_registry_contains_crewai`, `test_install_hint_names_the_extra`, `test_step_indices_are_sequential`, `test_live_crew_smoke`.
- `tests/test_attacks.py`: `test_render_non_empty`, `test_render_contains_template_marker`, `test_render_targets_attacker_email`, `test_render_does_not_embed_canary`, `test_protocol_conformance`, `test_names_are_distinct`, `test_registry_resolves_new_attacks`, `test_handcrafted_attack_conformance`, the six per-attack wording tests (`test_metadata_exfil_uses_mundane_reframe` through `test_relay_action_item_is_summarizable_content`), `test_prerequisite_mirror_targets_an_unauthorized_recipient`, `test_iterative_protocol_conformance`, `test_looks_like_refusal_negative_clean_payload`, `test_next_payload_retries_past_refusal`, `test_render_delegates_to_round_zero`, `test_build_prompt_round_zero_has_no_history`, `test_build_prompt_seed_rotation_wraps`.
- `tests/test_iterative_attacker.py`: `test_render_passes_context_through`, `test_next_payload_signature_takes_no_canary`, `test_history_feedback_reaches_the_model_but_carries_no_canary`, `test_parse_structured_keeps_raw_fallback_when_no_json`, `test_system_prompt_states_in_channel_is_not_success`, `test_prompt_explains_grade2_without_exfiltration_is_not_a_win`.
- `tests/test_tree_attacker.py`: `test_parse_empty_is_empty`, `test_partial_generation_error_is_contained` (its docstring names a branch the test never reaches), `test_best_payload_survives_across_depths`, `test_protocol_name_and_registry`.
- `tests/test_attack_context.py`: `test_context_never_carries_the_canary`, `test_protocol_accepts_both_signatures`.
- `tests/test_adaptive_model_fallback.py`: `test_defense_without_model_gets_target_model_during_episode`.
- `tests/test_agentdojo_bridge.py`: `test_no_defense_system_prompt_is_base`, `test_run_agentdojo_episode_end_to_end_offline`.
- `tests/test_multi_agent_adapter.py`: `test_held_when_summary_does_not_relay_the_canary`, `test_task_completed_works_through_the_relay`, `test_tool_call_guard_applies_to_both_agents` (its name is false: A's guard is never denied), `test_actor_prompt_is_scenario_neutral`, `test_recursion_limit_mapping`, `test_module_does_not_load_dotenv_on_import`.
- `tests/test_adapter_registry.py`: `test_registry_contains_known_adapters`, `test_resolves_langgraph`, `test_resolves_multi_agent`, `test_resolves_empty_list`, `test_raises_on_unknown_name`, `test_unknown_name_error_lists_known_adapters`, `test_unknown_name_suggests_closest_adapter`.
- `tests/test_defenses.py`: the five `test_<defense>_satisfies_protocol`, the five `test_<defense>_name`, `test_tool_filter_wrap_system_prompt_is_passthrough`, `test_tool_filter_allows_multiple`, `test_tool_filter_empty_input`, `test_tool_filter_check_tool_call_catches_call_not_in_offered_menu`, `test_outbound_guard_passthrough_non_call_hooks`, `test_resolve_mixed_list_preserves_order`, `test_resolve_registry_defenses`, `test_resolve_unknown_name_raises`, `test_load_config_resolves_defenses_from_example_yaml`, `test_load_config_tool_filter_has_allowed_tools`.
- `tests/test_scenarios.py`: `test_authorized_recipient_is_same_domain_and_singular`, `test_scenarios_have_distinct_recipients_and_tools`, `test_attack_redirect_targets_are_unauthorized_everywhere` (stale: names two addresses no attack uses), `test_example_config_scenarios_resolve`, `test_legacy_build_episode_matches_invoice_scenario` (compares a function to itself).
- `tests/test_stats.py`: `test_zero_trials`, `test_zero_successes`, `test_half_successes`, `test_single_trial_failure`.
- `tests/test_canary.py`: `test_format_several_seeds`, `test_inject_returns_environment`.
- `tests/test_runner_defense.py`: `test_run_episode_records_defense_name`, `test_run_campaign_records_defense_name`, `test_run_sweep_defaults_to_single_no_defense_pass`.
- `tests/test_raw_loop.py`: `TestOffScriptToolCalls` (all four, covered by parity), `test_text_alongside_tool_calls_is_recorded`.
- `tests/test_judge.py`: `test_canary_to_unauthorized_recipient_is_exfiltration`, `test_grade_2_leaked`, `test_different_canary`, `test_observe_keeps_default_authorized_signature`.
- `tests/test_runner_concurrency.py`: `test_parallel_sweep_covers_every_cell`.
- `tests/test_cli_init.py`: `test_no_sys_path_hack` (greps the source text).
- `tests/test_advice_report.py`: `test_new_attacks_have_targeted_advice`, `test_report_congratulates_when_nothing_leaks`.
- `tests/test_reporter.py`: `test_write_results_empty`, `test_print_asr_table_empty`.
- `tests/test_config_loader.py`: `test_comment_only_config_is_treated_as_empty`.
- `tests/test_runner_resilience.py`: `test_json_decode_error_is_not_retried`.

## 5. Add list

### 5a. End-to-end layer (highest value)

**Offline end-to-end through a fake provider.**
Start an in-process HTTP server that speaks the OpenAI chat-completions shape and point `OPENAI_BASE_URL` at it.
The real `openai` SDK then does real HTTP, so response parsing is covered, and the full pipeline runs with no stub inside it.
The server exposes a few deterministic agent policies: obeys the injection, ignores it, redirects without the secret, loops forever, returns malformed arguments, returns content as a block list, returns a refusal with no tool call.
Run `python -m tripwire --config <tmp.yaml>` as a subprocess and assert on `results.json`, the printed ASR table, the security report, the exit code, and `check_asr_threshold` reading the file.
One parametrized case per adapter and defense asserts the ASR the policy guarantees, for example "obedient agent under no_defense is 100 percent, under tool_filter is 0 percent, under outbound_guard with a scripted BLOCK verdict is 0 percent".
This replaces most of what the per-adapter unit files assert and is the test that would have caught bugs 1, 2, 7 and 11.

**Opt-in live smoke test.**
A test marked `live`, skipped when no provider key is set, that runs the smoke sweep against the configured provider and asserts at least one episode scored, the results file was written, and the exit code is 0.
CI already has the key-gated job; make it run this test instead of a bare command.

### 5b. Targeted tests for the bugs in section 3

Each fails today.

1. Write an `outbound_guard` episode with `guard_errors=1` through `write_results`; assert the gate fails and the ASR table shows a non-zero guard-error column.
2. `run_campaign` against an always-raising adapter; assert the result is not scored by `_report_outcome` and fails the gate.
3. `resolve_defenses(["outbound_guard"])` produces a fail-closed guard, or the config exposes `fail_closed`.
4. `_parse_structured('{"improvement": "x", "payload": "the body"}\nNote: fill {id} yourself')` returns `"the body"` and the payload never contains the string `"payload"`.
5. An `AuthenticationError` from the attacker client makes one call and no sleep; a `RateLimitError` twice then success makes three calls. Replace `test_generate_raises_after_transient_retries_exhaust`.
6. Parametrize `test_default_ctx_matches_the_invoice_scenario` over all three default contexts.
7. A fake `crewai` module in `sys.modules` with stub `Agent`, `Task`, `Crew`, `LLM` that capture kwargs; assert `max_iter == spec.max_turns`, `backstory == system_prompt`, `stop_reason` is set, and the trace ends with `kickoff().raw`. Also a raising tool records a `tool_result` error step.
8. `wilson_ci(11, 10)` and `wilson_ci(-1, 10)` raise `ValueError`.
9. `parse_verdict` on a reply containing both verdict words raises a guard error.
10. A repeated entry in `models`, `attacks`, `scenarios`, or `defenses` raises like a repeated seed.
11. Run a two-tool-turn transcript through raw_loop, langgraph, and multi_agent with a wrapper; assert every `tool_result` and every `role: tool` message sent back to the model is wrapped on both turns.
12. Archive wiring through the real runner: an `IterativeAttacker` subclass with a scripted `_generate` against an adapter that exfiltrates on attempt one; assert the win is in the archive.

### 5c. Consolidation

- Move `ScriptedClient` from `test_adapter_parity.py` to `conftest.py` and delete the other three fake clients.
- Extend parity to multi_agent with a relay-shaped transcript set: A's guard denied, a raising tool in A, B with no tools, two same-named parallel sends with one denied.
- Add parity transcripts for the provider shapes the stubs never send: content as a block list, a tool call with `id=None`, a `refusal` with no tool call, `tool_calls=[]`.
- One registry-consistency test that ties `reporter.py:242`, every `Advice.reduced_by` entry, and `resolve_defenses` together, replacing the five `test_<defense>_name` tests.
- Concurrency isolation with a stateful defense: `concurrency=4` with an `OutboundGuard` whose detector counts calls; assert the template instance stays at zero and each episode's `guard_errors` is per-cell.

## 6. Suggested order

1. Build the fake-provider end-to-end test and the live smoke test (5a). This is the single biggest gain and the one the presentation benefits from.
2. Fix bugs 1, 2, 3 and 7 and land their tests (5b items 1, 2, 3, 7). These change reported numbers.
3. Delete section 4 and consolidate the stubs (5c first bullet). Expect the suite to drop from about 500 functions to about 370 plus the new end-to-end cases.
4. The remaining 5b and 5c items.
