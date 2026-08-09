"""Plot the security-utility Pareto frontier from a results JSON.

The money chart: one point per defense at (ASR, utility-retained), with 95%
Wilson confidence intervals on both axes so small-n runs stay honest. A good
defense sits toward the top-left -- low attack-success-rate, high utility. The
frontier's *shape* (a knee, not a flat line or a single point) is the whole
argument for a ladder of mitigations.

Reads the JSON written by scripts/experiments/defense_ladder_pareto.py (or any
run via write_results). Aggregates episodes by defense across attacks/seeds.

Run from repo root:
    tripwire-env/bin/python3 scripts/experiments/pareto_plot.py \
        --results results/defense_ladder_pareto.json \
        --out results/pareto.png

Pure stdlib + matplotlib + the repo's own wilson_ci -- no seaborn, no pandas.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.getcwd())

import matplotlib

matplotlib.use("Agg")  # headless: render straight to a file, no display needed
import matplotlib.pyplot as plt

from src.harness.stats import wilson_ci

# Ladder order (cheap-weak -> expensive-strong) and a colorblind-safe,
# print-friendly color per rung. Okabe-Ito palette; order fixes both the
# legend order and which rung gets which color so re-runs look identical.
LADDER = ["no_defense", "prompt_hardening", "spotlighting", "tool_filter", "outbound_guard"]
COLORS = {
    "no_defense": "#E69F00",       # orange
    "prompt_hardening": "#56B4E9",  # sky blue
    "spotlighting": "#009E73",      # bluish green
    "tool_filter": "#CC79A7",       # reddish purple
    "outbound_guard": "#0072B2",    # blue
}


def _load_episodes(payload) -> list[dict]:
    """write_results emits a flat episode list, or {episodes, campaigns} when
    campaigns are present. The Pareto uses single-shot episodes only (they
    carry the utility signal); campaigns have no task_completed field."""
    if isinstance(payload, dict):
        return payload.get("episodes", [])
    return payload


def aggregate(episodes: list[dict]) -> dict[str, dict]:
    """Group episodes by defense -> {n, leaks, completed, asr, utility, and
    Wilson CIs for each rate}. Aggregates across attack, seed, and adapter."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for e in episodes:
        groups[e.get("defense", "no_defense")].append(e)

    out: dict[str, dict] = {}
    for defense, items in groups.items():
        n = len(items)
        leaks = sum(1 for e in items if e.get("succeeded"))
        completed = sum(1 for e in items if e.get("task_completed"))
        asr_lo, asr_hi = wilson_ci(leaks, n)
        util_lo, util_hi = wilson_ci(completed, n)
        out[defense] = {
            "n": n,
            "asr": leaks / n if n else 0.0,
            "utility": completed / n if n else 0.0,
            "asr_ci": (asr_lo, asr_hi),
            "utility_ci": (util_lo, util_hi),
        }
    return out


def plot(agg: dict[str, dict], out_path: str, title: str) -> None:
    fig, ax = plt.subplots(figsize=(7.5, 6))

    ordered = [d for d in LADDER if d in agg] + [d for d in agg if d not in LADDER]
    for defense in ordered:
        s = agg[defense]
        x, y = s["asr"], s["utility"]
        # Asymmetric error bars: distance from the point to each CI bound.
        xerr = [[x - s["asr_ci"][0]], [s["asr_ci"][1] - x]]
        yerr = [[y - s["utility_ci"][0]], [s["utility_ci"][1] - y]]
        color = COLORS.get(defense, "#555555")
        ax.errorbar(
            x, y, xerr=xerr, yerr=yerr, fmt="o", markersize=10,
            color=color, ecolor=color, elinewidth=1.3, capsize=4, alpha=0.9,
            label=f"{defense} (n={s['n']})",
        )
        ax.annotate(defense, (x, y), textcoords="offset points", xytext=(9, 6),
                    fontsize=9, color=color)

    ax.set_xlabel("Attack success rate (ASR) — lower is better", fontsize=11)
    ax.set_ylabel("Utility retained (benign task completed) — higher is better", fontsize=11)
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.set_title(title, fontsize=12)
    # The top-left corner is the ideal: no leaks, full utility.
    ax.annotate("ideal", (0.02, 0.98), fontsize=10, color="#888888", style="italic")
    ax.grid(True, linestyle=":", alpha=0.4)
    ax.legend(loc="lower right", fontsize=8, framealpha=0.9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    print(f"wrote {out_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot the security-utility Pareto.")
    parser.add_argument("--results", default="results/defense_ladder_pareto.json")
    parser.add_argument("--out", default="results/pareto.png")
    parser.add_argument("--title", default="Security-utility Pareto across the defense ladder")
    args = parser.parse_args()

    with open(args.results) as f:
        payload = json.load(f)

    episodes = _load_episodes(payload)
    if not episodes:
        print(f"[pareto_plot] no episodes in {args.results}", file=sys.stderr)
        return 1

    agg = aggregate(episodes)
    for defense in [d for d in LADDER if d in agg] + [d for d in agg if d not in LADDER]:
        s = agg[defense]
        print(f"{defense:<18} n={s['n']:>3}  ASR={s['asr']:>5.0%}  utility={s['utility']:>5.0%}")
    plot(agg, args.out, args.title)
    return 0


if __name__ == "__main__":
    sys.exit(main())
