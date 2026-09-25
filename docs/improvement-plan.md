# Improvement plan: attackers and defenders

Status as of 2026-09-25.
This follows the audit in `audit-2026-09-25.md`.
Part 1 of that audit (measurement bugs) is fixed and committed.
This document records the remaining attack-side and defense-side changes, with a confidence and expected-effect estimate for each.

None of the estimates below have been measured.
The Part 1 fixes changed the baseline: multi_agent now sees the payload in every scenario, the outbound guard now runs a real model, and errored episodes are no longer dropped.
Before judging any change here, run a fresh sweep at 30 or more seeds per cell so the Wilson intervals are narrow enough to detect it.
Then measure each change against that baseline, one at a time.

Confidence scale: very high, high, medium, low.
"Enabler" means the change has no effect on its own but is required by later items.

## Attack side

| Change | Confidence it helps | Expected effect | Why |
|---|---|---|---|
| AttackContext through `render(canary, ctx)` | High | Large on helpdesk, calendar, expense. None on invoice. | Payloads are invoice-specific and get pasted into a VPN ticket or a meeting request. The mismatch is what an aligned model notices. Enabler for everything that follows. |
| Fix the objective: retarget `public_identifier` and `forged_boundary`, rewrite the PAIR prompt | High that numbers change, medium on magnitude | Two attacks go from structural 0% to something measurable. PAIR improves moderately. | PAIR optimizes a grade the judge does not count. Fixing a wrong target reliably helps. The attacker model's ceiling is unknown. |
| TAP scoring and search fixes | Medium-high | Moderate. Bounded by the small evaluation budget. | The scorer ranks a benign run above a defense-blocked attack, so it prunes the best branch. Dedup and memory save wasted evaluations rather than find new wins. |
| Lift the verbatim-only constraint | High against outbound_guard, near zero elsewhere | Guard ASR could rise substantially. | Encoding is the canonical classifier bypass. The judge now detects normalized, base64, hex, reversed and split leaks, so the constraint is no longer needed. Prompt-level defenses do not care how the id is written. |
| Injection slots: position, bounce message, tool description | Medium | Uncertain. Plausibly large for the bounce message. | Injection while the agent is mid-action is well documented as stronger. Position effects are real but smaller. Highest implementation cost on this list. |
| Relay-aware attack | Medium | multi_agent rows only. | The summarizer is told to list recipients and action items. That instruction is targetable, but the id must survive two hops. |
| Guard-directed attack | Medium-high against the guard only | Guard ASR up. | The guard reads the attacker-influenced body. Once the guard fences its input, this attack weakens. |
| AgentDojo `tool_knowledge` port | Medium | Moderate. | Among the strongest templated attacks in the AgentDojo paper. The named-user gap remains. |
| Replay library | Does not raise ASR | Changes honesty, not strength. | Tells you whether a tree win at temperature was luck. Expect reported adaptive ASR to fall. |
| Remove oracle knowledge of the secret label | High that it lowers ASR | Numbers go down. | Attacks currently know the deployment's variable name. Realism, not strength. |

## Defense side

| Change | Confidence it helps | Expected effect | Why |
|---|---|---|---|
| `bind(ctx)` hook on Defense | Enabler | None on its own. | Required by the allowlist, the egress scan, guard hardening, Agent B coverage and taint tracking. |
| `recipient_allowlist` and `secret_egress_scan` | Very high | Destination-aware ASR to about 0% with full utility. | Deterministic and by construction. Caveat: the allowlist comes from the same authorized set the judge uses. In a real deployment it must come from the user's message, which is the hard part. This sets the ceiling and pushes attackers toward integrity goals the judge does not score yet. |
| Stacked defenses | High for measurement, medium for ASR | L1+L2 modest. L1+L3 or L2+allowlist larger. | Prompt-level rungs share one failure mode, so they add little to each other. Different mechanisms add more. |
| L1/L2 wording, recipient anchoring, datamarking, sandwich | Medium-high | Spotlighting should drop from its documented 50% to at most hardening's 15% on mundane_redirect. Datamarking has large reported gains over delimiting. | The recipient-anchoring rule targets exactly what mundane_redirect exploits. Wording effects are model-dependent and can vanish on the next model version. |
| Guard hardening: fenced input, authorized recipients, deterministic pre-check | High against prerequisite_mirror | Guard ASR down a lot. | Given the recipient, the guard can see the send is unauthorized. This converges toward the deterministic allowlist. |
| Agent B coverage in multi_agent | High for multi_agent rows | Brings multi_agent L1/L2 to roughly single-agent levels. | The agent that sends email currently has no defense at all. |
| Taint tracking | High for redirect attacks, with false-positive risk | Blocks any decoy address that first appeared in tool output. | Every current redirect address appears only in tool results. Legitimate recipients appear in the user message, so utility should hold in the four scenarios. |
| Quarantined reader (CaMeL-style typed extraction) | Medium | Strong in the literature. Utility cost unknown here. | Highest implementation cost. Needs typed extraction per scenario. |
| No-attack control run | Measurement only | Separates a defense's utility cost from attack disruption. | Needed to say anything about cost. |

## Order of work

Attack side first.

1. AttackContext contract and scenario fields (enabler).
2. Templated hand-crafted attacks, retargeted `public_identifier` and `forged_boundary`, guard-directed and relay-aware classes.
3. PAIR rewrite around the destination-aware objective with the redacted observation feedback.
4. TAP scorer, critic as tiebreaker, dedup, technique memory, partial-JSON salvage, keep `best_payload`, lift the verbatim constraint.
5. Fresh baseline sweep, then measure.
6. Injection slots and `tool_knowledge` port as a second wave.

Defense side after that, starting with `bind(ctx)` and the two deterministic defenses.
