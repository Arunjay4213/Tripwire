# Security Policy

## Supported versions

Tripwire is pre-1.0 and released from `main`.
Security fixes land on the latest `0.1.x` release on PyPI (`tripwire-eval`); there is no backporting to older versions.

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not in a public issue.

- Preferred: open a private report via GitHub Security Advisories on this repository (the "Report a vulnerability" button under the **Security** tab).
- Alternatively: email the maintainer at arunjay101@gmail.com.

Include enough detail to reproduce: affected version, environment, a minimal example, and the impact you observed.
You can expect an initial acknowledgement within about a week.
Once a fix is available, the advisory will be published and the reporter credited unless you prefer to stay anonymous.

## Scope

Tripwire is a red-team evaluation harness: it deliberately generates and runs prompt-injection **attack payloads** against the agent under test.
Those payloads, the adaptive attackers, and the fact that a poorly defended agent leaks its canary are the intended behavior of the tool, not vulnerabilities.

The bring-your-own-agent path (`tripwire --agent path/to/agent.py`) imports and executes the Python file you point it at.
That is by design and equivalent to running your own script; only pass files you trust.

In scope for a report are security issues in the harness itself, for example:

- an unintended way for untrusted **input** (a config file, a scenario, a tool result, an attacker payload) to execute code or read/write files outside the harness's normal operation,
- a path-traversal or injection flaw in how Tripwire loads configs, agents, or results,
- a vulnerability introduced by one of Tripwire's own dependencies as used here.

When in doubt, report it privately and we will triage.
