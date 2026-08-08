"""Reporter — write per-episode results to results/ as JSON, print ASR table.

P1 core (roadmap Weeks 2-3).
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from dataclasses import asdict

from src.harness.runner import CampaignResult, EpisodeResult
from src.harness.stats import wilson_ci


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
    groups: dict[tuple[str, str, str], list[EpisodeResult]] = defaultdict(list)
    for r in results:
        groups[(r.adapter, r.attack, r.defense)].append(r)

    # Header
    print(f"{'adapter':<16} {'attack':<24} {'defense':<14} {'n':>4} {'leak':>4} {'ASR':>6}  "
          f"{'95% CI':<14} {'utility':>8}")
    print("-" * 98)

    for (adapter, attack, defense), items in sorted(groups.items()):
        n = len(items)
        leaks = sum(1 for r in items if r.succeeded)
        asr = leaks / n if n else 0.0
        lo, hi = wilson_ci(leaks, n)
        completed = sum(1 for r in items if r.task_completed)
        utility = completed / n if n else 0.0
        print(f"{adapter:<16} {attack:<24} {defense:<14} {n:>4} {leaks:>4} {asr:>5.0%}  "
              f"[{lo:.0%}, {hi:.0%}]      {utility:>6.0%}")


def print_campaign_table(campaigns: list[CampaignResult]) -> None:
    """Print the adaptive-attacker effort-to-break table, grouped by (adapter, attack, defense).

    Each row shows: campaigns run, break-rate within budget + 95% Wilson CI, and
    median/mean attempts-to-break over the campaigns that broke.
    """
    groups: dict[tuple[str, str, str], list[CampaignResult]] = defaultdict(list)
    for c in campaigns:
        groups[(c.adapter, c.attack, c.defense)].append(c)

    print(f"{'adapter':<16} {'attack':<16} {'defense':<14} {'n':>4} {'broke':>6} {'rate':>6}  "
          f"{'95% CI':<14} {'attempts (med/mean)'}")
    print("-" * 92)

    for (adapter, attack, defense), items in sorted(groups.items()):
        n = len(items)
        broke = sum(1 for c in items if c.broke)
        rate = broke / n if n else 0.0
        lo, hi = wilson_ci(broke, n)
        attempts = [c.attempts_to_break for c in items if c.attempts_to_break is not None]
        if attempts:
            att = f"{statistics.median(attempts):.1f} / {statistics.mean(attempts):.1f}"
        else:
            att = "never broke"
        print(f"{adapter:<16} {attack:<16} {defense:<14} {n:>4} {broke:>6} {rate:>5.0%}  "
              f"[{lo:.0%}, {hi:.0%}]      {att}")
