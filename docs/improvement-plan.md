# Improvement plan: attackers and defenders

Written 2026-09-25; status column updated 2026-10-11.
This follows the audit in `audit-2026-09-25.md`.
Part 1 of that audit (measurement bugs) is fixed and committed.
This document records the remaining attack-side and defense-side changes, with a confidence and expected-effect estimate for each.
The Status column says what is on `main` as of 2026-10-11.

None of the estimates below have been measured.
The Part 1 fixes changed the baseline: multi_agent now sees the payload in every scenario, the outbound guard now runs a real model, and errored episodes are no longer dropped.
Before judging any change here, run a fresh sweep at 30 or more seeds per cell so the Wilson intervals are narrow enough to detect it.
Then measure each change against that baseline, one at a time.
Note for that sweep: since 2026-10-11 the outbound guard fails closed by default and a guard outage is recorded as an error outcome rather than a defended run, so defense numbers from before that date are not comparable to numbers from after it.

Confidence scale: very high, high, medium, low.
"Enabler" means the change has no effect on its own but is required by later items.

## Attack side

| Change | Status | Confidence it helps | Expected effect | Why |
|---|---|---|---|---|
| AttackContext through `render(canary, ctx)` | Done | High | Large on helpdesk, calendar, expense. None on invoice. | Payloads are invoice-specific and get pasted into a VPN ticket or a meeting request. The mismatch is what an aligned model notices. Enabler for everything that follows. |
| Fix the objective: retarget `public_identifier` and `forged_boundary`, rewrite the PAIR prompt | Done | High that numbers change, medium on magnitude | Two attacks go from structural 0% to something measurable. PAIR improves moderately. | PAIR optimizes a grade the judge does not count. Fixing a wrong target reliably helps. The attacker model's ceiling is unknown. |
| TAP scoring and search fixes | Done | Medium-high | Moderate. Bounded by the small evaluation budget. | The scorer ranks a benign run above a defense-blocked attack, so it prunes the best branch. Dedup and memory save wasted evaluations rather than find new wins. |
| Lift the verbatim-only constraint | Not done. The attacker prompts still ask for the id verbatim. | High against outbound_guard, near zero elsewhere | Guard ASR could rise substantially. | Encoding is the canonical classifier bypass. The judge now detects normalized, base64, hex, reversed and split leaks, so the constraint is no longer needed. Prompt-level defenses do not care how the id is written. |
| Injection slots: position, bounce message, tool description | Not done | Medium | Uncertain. Plausibly large for the bounce message. | Injection while the agent is mid-action is well documented as stronger. Position effects are real but smaller. Highest implementation cost on this list. |
| Relay-aware attack | Done (`relay_action_item`) | Medium | multi_agent rows only. | The summarizer is told to list recipients and action items. That instruction is targetable, but the id must survive two hops. |
| Guard-directed attack | Done (`guard_injection`) | Medium-high against the guard only | Guard ASR up. | The guard reads the attacker-influenced body. Once the guard fences its input, this attack weakens. |
| AgentDojo `tool_knowledge` port | Not done | Medium | Moderate. | Among the strongest templated attacks in the AgentDojo paper. The named-user gap remains. |
| Replay library | Not done | Does not raise ASR | Changes honesty, not strength. | Tells you whether a tree win at temperature was luck. Expect reported adaptive ASR to fall. |
| Remove oracle knowledge of the secret label | Not done. Every attack still names the "instance id". | High that it lowers ASR | Numbers go down. | Attacks currently know the deployment's variable name. Realism, not strength. |

## Defense side

| Change | Status | Confidence it helps | Expected effect | Why |
|---|---|---|---|---|
| `bind(ctx)` hook on Defense | Not done | Enabler | None on its own. | Required by the allowlist, the egress scan, guard hardening, Agent B coverage and taint tracking. |
| `recipient_allowlist` and `secret_egress_scan` | Not done | Very high | Destination-aware ASR to about 0% with full utility. | Deterministic and by construction. Caveat: the allowlist comes from the same authorized set the judge uses. In a real deployment it must come from the user's message, which is the hard part. This sets the ceiling and pushes attackers toward integrity goals the judge does not score yet. |
| Stacked defenses | Not done | High for measurement, medium for ASR | L1+L2 modest. L1+L3 or L2+allowlist larger. | Prompt-level rungs share one failure mode, so they add little to each other. Different mechanisms add more. |
| L1/L2 wording, recipient anchoring, datamarking, sandwich | Not done | Medium-high | Spotlighting should drop from its documented 50% to at most hardening's 15% on mundane_redirect. Datamarking has large reported gains over delimiting. | The recipient-anchoring rule targets exactly what mundane_redirect exploits. Wording effects are model-dependent and can vanish on the next model version. |
| Guard hardening: fenced input, authorized recipients, deterministic pre-check | Fenced input done. Fail-closed default and error accounting done (2026-10-11). Authorized recipients and the pre-check not done. | High against prerequisite_mirror | Guard ASR down a lot. | Given the recipient, the guard can see the send is unauthorized. This converges toward the deterministic allowlist. |
| Agent B coverage in multi_agent | Not done. Pinned by a strict expected failure in `tests/test_e2e.py`. | High for multi_agent rows | Brings multi_agent L1/L2 to roughly single-agent levels. | The agent that sends email currently has no defense at all. |
| Taint tracking | Not done | High for redirect attacks, with false-positive risk | Blocks any decoy address that first appeared in tool output. | Every current redirect address appears only in tool results. Legitimate recipients appear in the user message, so utility should hold in the four scenarios. |
| Quarantined reader (CaMeL-style typed extraction) | Not done | Medium | Strong in the literature. Utility cost unknown here. | Highest implementation cost. Needs typed extraction per scenario. |
| No-attack control run | Not done | Measurement only | Separates a defense's utility cost from attack disruption. | Needed to say anything about cost. |

## Order of work

Attack side first.

1. AttackContext contract and scenario fields (enabler). Done.
2. Templated hand-crafted attacks, retargeted `public_identifier` and `forged_boundary`, guard-directed and relay-aware classes. Done.
3. PAIR rewrite around the destination-aware objective with the redacted observation feedback. Done.
4. TAP scorer, critic as tiebreaker, dedup, technique memory, partial-JSON salvage, keep `best_payload`, lift the verbatim constraint. Done except the verbatim constraint.
5. Fresh baseline sweep, then measure. Not done. The only results newer than the attack rewrite are three errored episodes from a retired Groq model.
6. Injection slots and `tool_knowledge` port as a second wave. Not started.

Defense side after that, starting with `bind(ctx)` and the two deterministic defenses. Not started.

Done since this plan was written but outside its scope, see `test-audit-2026-10-11.md`: an end-to-end test layer, eleven measurement and robustness bugs fixed, and the test suite pruned.

## Remaining work, split into three tracks

Three tracks, chosen so that no track waits on another for code.
The one cross-track rule: track 1 runs the baseline on today's `main` first, and every change from tracks 2 and 3 is measured against that baseline one at a time before it merges.

### Track 1: measurement

Owns the numbers.
Nothing here changes an attack or a defense; it makes the other two tracks' results trustworthy.

1. Fresh baseline sweep on `main` as of 2026-10-11: three adapters, four scenarios, every attack, every defense, 30 seeds per cell, on the deployed models (`gpt-4.1-mini`, `DeepSeek-V4-Pro`, `gpt-5.6-luna`).
2. No-attack control run, so a defense's utility cost can be separated from attack disruption.
3. Replay library, so a tree-search win at temperature can be checked for luck.
4. Stacked defenses as a measurement feature (a composite that applies several rungs), so L1+L2 and L2+allowlist cells exist when track 3 lands.
5. Rewrite `findings.md` from the new results and refresh the deck numbers.

### Track 2: attack side, second wave

Owns attack strength and realism.
All four items are independent of track 3 and of each other.

1. Lift the verbatim-only constraint in the PAIR and TAP prompts; the judge already detects encoded and split leaks.
2. Remove oracle knowledge of the secret label from every attack.
3. Port AgentDojo's `tool_knowledge` attack.
4. Injection slots: position within the tool result, a bounce message mid-action, and the tool description. Highest cost, last.

### Track 3: defense side

Owns the "here is the fix" result.
Item 1 is the enabler and goes first; items 2 and 3 are the headline and come next; the rest in order of expected effect over cost.

1. `bind(ctx)` hook on Defense, so a defense learns the scenario's authorized recipients and read tool before the episode.
2. `recipient_allowlist` and `secret_egress_scan`, the two deterministic rungs.
3. Guard hardening: authorized recipients in the guard's input and a deterministic pre-check before the model call.
4. Agent B coverage in multi_agent, which flips the expected failure in `tests/test_e2e.py`.
5. L1/L2 wording: recipient anchoring, datamarking, sandwich.
6. Taint tracking.
7. Quarantined reader, only if time remains.
