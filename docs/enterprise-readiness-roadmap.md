# Tripwire Enterprise Readiness Roadmap

## Purpose and Positioning

**Recommended project definition:** Tripwire is a pre-deployment adversarial evaluation and release-gating tool for AI agents. It runs scoped attacks against a specific agent build, measures whether they cause unauthorized actions, checks whether legitimate tasks still work, evaluates mitigations, and produces evidence for a release decision.

Tripwire helps teams reduce known risks. It does not certify an agent as safe, guarantee that every attack will be found, or replace authorization checks at runtime. Use “helps safeguard agents through testing and release controls,” not “makes agents safe.”

## Current Project Baseline

The repository already provides a useful foundation:

- A shared adapter interface for testing a built-in or bring-your-own agent.
- Prompt-injection attacks, adaptive attackers, scenario variants, and an AgentDojo bridge.
- A deterministic trace-based judge, attack success and task-utility metrics, and Wilson confidence intervals.
- Demonstration defenses and a CI regression gate for known scenarios.
- Methodology documentation that calls out the toy environment, narrow scoring scope, provider limits, and the distinction between a regression gate and a safety certificate.

The present evaluation is strongest as a research prototype and regression harness. Its local scenarios primarily model email exfiltration with a small tool surface. That does not yet represent an enterprise agent’s real identities, permissions, data stores, side effects, memory, connectors, or approval workflows. The repository’s `outbound_guard` and other defenses demonstrate behavior inside the harness; they do not automatically protect an agent deployed elsewhere.

## Definition of Done for a Pre-Deployment Evaluation

An evaluation is complete only when it identifies the tested build and threat model, runs the required scenario coverage, records observed effects, reports failures and uncertainty, and emits a reproducible artifact. An incomplete run must be marked **inconclusive**, never passed.

Each evaluation should identify:

- The agent build or source revision, model/provider and model version, prompts, tool schemas, connector versions, policy configuration, and test timestamp.
- The protected assets, user and service identities, trust boundaries, attacker capabilities, allowed actions, prohibited actions, and expected approval points.
- Which risk categories and scenarios ran, their sample counts, expected controls, scoring method, and any exclusions.
- For every attempt: requested action, whether policy allowed it, whether it executed, resulting environment state, task outcome, and sanitized evidence.
- Run failures, skipped cases, retries, confidence intervals, and the reason for any manual exception.

## Prioritized Action Plan

### P0: Make Evaluation Results Trustworthy

These are prerequisites for using results in a deployment decision.

1. **Create a versioned evaluation manifest.** Record the build, model, prompts, tools, permissions, connectors, scenarios, attack-suite version, policy version, and seeds for each run. Compute a stable run ID and include the manifest in the result artifact.
   - **Owner:** Evaluation-platform engineer.
   - **Done when:** Two runs with the same manifest can be compared directly, and every report identifies exactly what was tested.

2. **Record environment effects as ground truth.** Extend the sandbox so tests can assert state changes such as sent messages, modified files, API writes, permission denials, or data access. Keep traces for diagnosis, but use the sandbox’s recorded effects for security scoring where possible.
   - **Owner:** Agent-integration engineer.
   - **Done when:** A requested-but-blocked action scores differently from an executed action, and a known unauthorized side effect is detected even if the agent’s transcript claims it did nothing.

3. **Make incomplete runs visible and non-passing.** Store per-case status (`passed`, `violated`, `error`, `skipped`, or `inconclusive`) and failure reason in JSON and the human report. Set minimum run and coverage requirements; fail the release gate if required cases are missing or scoring infrastructure fails.
   - **Owner:** Evaluation-platform engineer.
   - **Done when:** A provider outage or adapter exception cannot produce a green gate, and the report gives the expected, completed, failed, and skipped counts for every risk group.

4. **Establish evaluation controls.** Add benign cases, deliberately vulnerable cases, and cases where a control must block a known prohibited action. Validate scoring against human-labeled traces and environment state. Retain confidence intervals and select sample sizes based on the organization’s risk tolerance.
   - **Owner:** AI-security evaluation lead.
   - **Done when:** The evaluator catches seeded failures, avoids flagging the corresponding safe cases, and publishes judge accuracy and sample-size rationale. A zero observed failure rate is reported with its uncertainty, never as proof of zero risk.

5. **Close the cost-control gap.** The configuration exposes `max_tokens_per_run`, but a token budget is not enforced across every adapter and attacker call. Either implement a measured, shared budget with a hard stop and actual-usage accounting, or remove the setting from the supported configuration until that works.
   - **Owner:** Evaluation-platform engineer.
   - **Done when:** A configured budget is enforced across all supported paths, and the report includes estimated and observed token usage and cost. A non-null unsupported setting must not be accepted silently.

6. **Isolate test execution.** BYO agent files execute Python code, and attack tests should never use production credentials, live customer data, or unrestricted write access. Run test agents and tools in disposable sandboxes with fake data, scoped credentials, network egress controls, and explicit cleanup.
   - **Owner:** Platform security engineer.
   - **Done when:** A test can be run without production secrets or irreversible external side effects, and its sandbox can be destroyed and audited after the run.

### P1: Test Representative Agent Risks

1. **Define a per-agent threat profile.** Capture assets, principals, trust boundaries, entry points, tool permissions, sensitive operations, and attacker capabilities before selecting tests.
   - **Owner:** Application security reviewer with the agent owner.
   - **Done when:** Every test suite links each scenario to a stated threat and prohibited outcome.

2. **Expand risk coverage beyond email exfiltration.** Add test families for direct and indirect goal hijacking, sensitive-data disclosure, tool misuse, identity and privilege abuse, memory or context poisoning, insecure agent-to-agent handoffs, connector or tool supply-chain changes, and unsafe code execution. Prioritize against the current OWASP Agentic Applications risks and maintain an explicit coverage map.
   - **Owner:** AI-security evaluation lead.
   - **Done when:** Reports show coverage by risk category and disclose categories with no tests. Each added family has safe controls, vulnerable controls, and concrete impact checks.

3. **Use representative sandbox integrations.** Build reusable mock or staging connectors for the tools the pilot organization actually uses, such as mail, files, tickets, databases, browsers, and internal APIs. Model identities and permissions instead of treating every tool as equally available.
   - **Owner:** Agent-integration engineer and pilot team.
   - **Done when:** At least three representative workflows exercise real permission boundaries and observable side effects without touching production data.

4. **Test multi-step and persistent behavior.** Include multi-turn attacks, delayed effects, retries, memory across sessions, tool-result poisoning, and handoffs between agents. Keep an attack holdout set so teams can distinguish regression tests from attacks used to tune a defense.
   - **Owner:** AI-security evaluation lead.
   - **Done when:** The evaluation covers cross-step effects, records session boundaries, and reports performance on both known regression cases and held-out attacks.

5. **Make mitigation tests enforceable.** Evaluate least-privilege tools, server-side authorization, destination or resource allowlists, high-impact action approval, rate limits, and revocation. Treat prompt-only changes as behavioral mitigations whose effectiveness must be measured, not guaranteed controls.
   - **Owner:** Application security reviewer and control owner.
   - **Done when:** At least one test proves the action is denied at the tool or downstream service boundary even when the model requests it.

### P2: Validate Enforceable Runtime Controls

If Tripwire is to be described as part of a safeguard, it must test controls that actually sit on the action path. Consider a separate runtime policy component rather than implying that evaluation code itself protects deployed agents.

1. **Define a tool-action policy contract.** Check the authenticated principal, tool, resource, arguments, destination, data classification, and action risk before execution.
2. **Default to deny for high-impact actions.** Require explicit approval for actions such as external data transfer, deletion, financial changes, or permission changes. A policy-service outage must not silently allow these actions.
3. **Bind authorization to the downstream identity.** Ensure the tool’s actual credentials and scopes match the tested policy; model instructions are not an authorization boundary.
4. **Log and revoke.** Produce an audit record for each decision and support rapid credential revocation or agent shutdown.

   - **Owner:** Product security/platform team.
   - **Done when:** A red-team case demonstrates that a manipulated agent cannot bypass the runtime policy by changing its wording, recipient, tool call, or agent handoff.

### P3: Enterprise Workflow and Governance

1. **Integrate with build and release workflows.** Provide a stable machine-readable report and CI action with policy thresholds, a clear inconclusive state, and an exception path that records approver, rationale, and expiry.
   - **Owner:** Developer-platform engineer.
   - **Done when:** Teams can run the same evaluation on pull requests and release candidates, compare against a baseline, and block on policy violations or missing coverage.

2. **Make reports useful to security and engineering.** Summarize risk, evidence, affected tool and data boundary, reproduction steps, mitigation owner, and retest status. Redact secrets and sensitive input by default.
   - **Owner:** Product/evaluation lead.
   - **Done when:** An application owner can reproduce a finding and a security reviewer can approve or reject a release using the same report.

3. **Document safe operation and data handling.** Define authorization for testing, test-data requirements, retention, access control, provider use, audit logging, and deletion. Support private or customer-controlled execution where required.
   - **Owner:** Security governance and product owner.
   - **Done when:** A pilot security review can answer where prompts and traces go, who can access them, how long they remain, and how test execution is contained.

## Release Gate Policy

The gate should evaluate a specific release candidate against an approved threat profile. A release passes only when required coverage is met, no prohibited high-impact action executes, task utility stays above its agreed floor, the evaluator’s control checks pass, and no required case remains failed or skipped. Any unresolved critical failure blocks release; any incomplete or invalid evaluation is inconclusive. Exceptions need a named risk owner, documented rationale, compensating controls, and an expiry date.

Thresholds should be set with the customer’s risk owner for each action class. Do not publish one universal “safe score.” Report observed failure rates, confidence intervals, scenario coverage, utility, and exceptions separately.

## Pilot Success Criteria

Run a pilot against three representative, sandboxed agent workflows selected with the company’s security and application teams. For each workflow:

- Freeze and record the exact release candidate and threat profile.
- Run baseline, known-vulnerable, and defended configurations across the agreed risk categories.
- Confirm that harmful side effects are detected, blocked actions are not mis-scored as executed, and benign task completion is measured.
- Demonstrate that seeded regressions block the gate and that incomplete runs produce an inconclusive result.
- Deliver a reproducible report with findings, run counts, confidence intervals, coverage gaps, and mitigation retests.

Success means the company can reproduce a finding, trace it to a concrete control gap, validate a mitigation, and make a documented release decision. It does not mean the agent is universally safe.

## Claims and Boundaries

**Credible today:** “Tripwire runs scoped adversarial evaluations and regression checks for AI agents, measuring selected unauthorized actions and task utility in controlled environments.”

**After P0 and P1:** “Tripwire provides reproducible, risk-mapped pre-deployment evidence across representative agent tools and workflows, with explicit coverage and uncertainty.”

**Only after P2 is integrated and validated:** “Tripwire tests and helps enforce runtime policies that block specified high-impact agent actions.” State exactly which actions and systems are covered.

Avoid claims such as “certifies agents as safe,” “prevents prompt injection,” “covers all agent attacks,” or “guarantees compliance.” A test result is evidence about the tested build, configuration, scenarios, and sample size.

## References

- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) — agent risk categories including goal hijacking, tool misuse, identity and privilege abuse, memory/context poisoning, and inter-agent communication.
- [OWASP Excessive Agency guidance](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) — recommends minimum functionality and permissions, downstream authorization, and approval for high-impact actions.
- [OWASP GenAI Security Project: 2026 update](https://genai.owasp.org/2026/09/01/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/) — 2026 LLM risk update and Agent Control Standard announcement.
- [NIST AI Risk Management Framework resources](https://airc.nist.gov/nist-ai-public-working-groups/) — highlights governance, content provenance, pre-deployment testing, and incident disclosure in the generative AI risk-management work.
