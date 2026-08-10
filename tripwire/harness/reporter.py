"""Reporter — write per-episode results to results/ as JSON, print ASR table.

P1 core (roadmap Weeks 2-3).
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from dataclasses import asdict

from tripwire.harness.advice import advice_for
from tripwire.harness.runner import CampaignResult, EpisodeResult
from tripwire.harness.stats import wilson_ci


def write_results(
    results: list[EpisodeResult],
    path: str,
    campaigns: list[CampaignResult] | None = None,
) -> None:
    """Dump raw results to a JSON file.

    Single-shot episodes and adaptive campaigns are written under separate keys
    when any campaign is present; otherwise the flat episode list is kept for
    backward compatibility.
    """
    if campaigns:
        payload = {
            "episodes": [asdict(r) for r in results],
            "campaigns": [asdict(c) for c in campaigns],
        }
    else:
        payload = [asdict(r) for r in results]
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def print_asr_table(results: list[EpisodeResult]) -> None:
    """Print attack-success-rate table grouped by (adapter, attack, defense).

    Each row shows: trials, successes, ASR%, 95% Wilson CI, and utility% (how
    often the agent still completed its real, benign task -- see
    judge.task_completed). ASR and utility are independent: a defense that
    blocks every tool shows 0% ASR *and* 0% utility, which is a very
    different (much worse) outcome than 0% ASR with 100% utility.
    """
    groups: dict[tuple[str, str, str, str], list[EpisodeResult]] = defaultdict(list)
    for r in results:
        groups[(r.adapter, r.scenario, r.attack, r.defense)].append(r)

    # Header
    print(f"{'adapter':<16} {'scenario':<10} {'attack':<24} {'defense':<14} {'n':>4} {'leak':>4} {'ASR':>6}  "
          f"{'95% CI':<14} {'utility':>8}")
    print("-" * 108)

    for (adapter, scenario, attack, defense), items in sorted(groups.items()):
        n = len(items)
        leaks = sum(1 for r in items if r.succeeded)
        asr = leaks / n if n else 0.0
        lo, hi = wilson_ci(leaks, n)
        completed = sum(1 for r in items if r.task_completed)
        utility = completed / n if n else 0.0
        print(f"{adapter:<16} {scenario:<10} {attack:<24} {defense:<14} {n:>4} {leaks:>4} {asr:>5.0%}  "
              f"[{lo:.0%}, {hi:.0%}]      {utility:>6.0%}")


def print_campaign_table(campaigns: list[CampaignResult]) -> None:
    """Print the adaptive-attacker effort-to-break table, grouped by
    (adapter, scenario, attack, defense).

    Each row shows: campaigns run, break-rate within budget + 95% Wilson CI, and
    median/mean attempts-to-break over the campaigns that broke. Scenario is part
    of the key so a multi-scenario sweep doesn't merge distinct tasks into one row
    (matching print_asr_table).
    """
    groups: dict[tuple[str, str, str, str], list[CampaignResult]] = defaultdict(list)
    for c in campaigns:
        groups[(c.adapter, c.scenario, c.attack, c.defense)].append(c)

    print(f"{'adapter':<16} {'scenario':<10} {'attack':<16} {'defense':<14} {'n':>4} {'broke':>6} {'rate':>6}  "
          f"{'95% CI':<14} {'attempts (med/mean)'}")
    print("-" * 102)

    for (adapter, scenario, attack, defense), items in sorted(groups.items()):
        n = len(items)
        broke = sum(1 for c in items if c.broke)
        rate = broke / n if n else 0.0
        lo, hi = wilson_ci(broke, n)
        attempts = [c.attempts_to_break for c in items if c.attempts_to_break is not None]
        if attempts:
            att = f"{statistics.median(attempts):.1f} / {statistics.mean(attempts):.1f}"
        else:
            att = "never broke"
        print(f"{adapter:<16} {scenario:<10} {attack:<16} {defense:<14} {n:>4} {broke:>6} {rate:>5.0%}  "
              f"[{lo:.0%}, {hi:.0%}]      {att}")


def print_security_report(
    episodes: list[EpisodeResult],
    campaigns: list[CampaignResult] | None = None,
) -> None:
    """Actionable feedback: for each agent+defense tested, which attacks got
    through and how to close each gap (see tripwire/harness/advice.py).

    A leak here means real exfiltration -- the planted secret reached a recipient
    the task never authorized. Grouped by (agent, scenario, defense) so the fix
    matches the configuration you actually ran and doesn't merge distinct tasks.
    """
    # (adapter, scenario, defense) -> attack -> [successes, n]
    stats: dict[tuple[str, str, str], dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for r in episodes:
        s = stats[(r.adapter, r.scenario, r.defense)][r.attack]
        s[0] += int(r.succeeded); s[1] += 1
    for c in campaigns or []:
        s = stats[(c.adapter, c.scenario, c.defense)][c.attack]
        s[0] += int(c.broke); s[1] += 1

    print("=" * 72)
    print("SECURITY FEEDBACK -- what got through, and how to harden your agent")
    print("=" * 72)

    for (adapter, scenario, defense) in sorted(stats):
        vulns = {a: v for a, v in stats[(adapter, scenario, defense)].items() if v[0] > 0}
        header = f"agent={adapter}   scenario={scenario}   defense={defense}"
        print(f"\n{header}")
        if not vulns:
            print("  ✓ No exfiltration observed across the attacks tested.")
            continue
        print(f"  ✗ Leaked to {len(vulns)} of {len(stats[(adapter, scenario, defense)])} attacks tested:")
        recommend: set[str] = set()
        for attack, (succ, n) in sorted(vulns.items(), key=lambda kv: -kv[1][0] / kv[1][1]):
            a = advice_for(attack)
            print(f"    • {attack}  (leaked {succ}/{n} = {succ / n:.0%})")
            print(f"        what it does: {a.summary}")
            if a.reduced_by:
                print(f"        reduced by:   {', '.join(a.reduced_by)}")
                recommend.update(a.reduced_by)
            print(f"        fix:          {a.fix}")
        not_on = [d for d in ("prompt_hardening", "spotlighting", "outbound_guard") if d in recommend and d != defense]
        if not_on:
            print(f"  → Start here: turn on {', '.join(not_on)} and re-run to see each gap close.")
        if any("allowlist" in advice_for(a).fix.lower() for a in vulns):
            print("  → And add a recipient allowlist -- the redirect/mirror attacks are only fully "
                  "closed by restricting which addresses the agent can send to.")
