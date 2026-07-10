"""Reporter — write per-episode results to results/ as JSON, print ASR table.

P1 core (roadmap Weeks 2-3).
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict

from src.harness.runner import EpisodeResult
from src.harness.stats import wilson_ci


def write_results(results: list[EpisodeResult], path: str) -> None:
    """Dump raw per-episode results to a JSON file."""
    with open(path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)


def print_asr_table(results: list[EpisodeResult]) -> None:
    """Print attack-success-rate table grouped by (adapter, attack).

    Each row shows: trials, successes, ASR%, and 95% Wilson CI.
    """
    groups: dict[tuple[str, str], list[bool]] = defaultdict(list)
    for r in results:
        groups[(r.adapter, r.attack)].append(r.succeeded)

    # Header
    print(f"{'adapter':<16} {'attack':<24} {'n':>4} {'leak':>4} {'ASR':>6}  {'95% CI'}")
    print("-" * 72)

    for (adapter, attack), outcomes in sorted(groups.items()):
        n = len(outcomes)
        leaks = sum(outcomes)
        asr = leaks / n if n else 0.0
        lo, hi = wilson_ci(leaks, n)
        print(f"{adapter:<16} {attack:<24} {n:>4} {leaks:>4} {asr:>5.0%}  [{lo:.0%}, {hi:.0%}]")
