"""Summarize one or more results files into the tables docs/findings.md is written from.

    python scripts/experiments/summarize_results.py results/single_deepseek.json results/single_luna.json
    python scripts/experiments/summarize_results.py results/*.json --markdown > /tmp/tables.md

Reads what write_results wrote (a flat episode list, or {"episodes", "campaigns"}),
pools files, and prints, per model: an attack x defense ASR grid with Wilson
intervals, a defense table (ASR, utility, tokens, defense tokens, capped
episodes, errors), an adapter table, and a campaign table. Errored runs are
excluded from every rate and counted in their own column, matching
reporter.print_asr_table. No LLM, no network; pure aggregation.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict

sys.path.insert(0, ".")
from tripwire.harness.stats import wilson_ci  # noqa: E402


def load(paths: list[str]) -> tuple[list[dict], list[dict]]:
    episodes: list[dict] = []
    campaigns: list[dict] = []
    for path in paths:
        data = json.load(open(path))
        if isinstance(data, dict):
            episodes += data.get("episodes", [])
            campaigns += data.get("campaigns", [])
        else:
            episodes += data
    return episodes, campaigns


def rate(k: int, n: int) -> str:
    if not n:
        return "-"
    lo, hi = wilson_ci(k, n)
    return f"{k / n:.0%} [{lo:.0%}, {hi:.0%}]"


def tokens(e: dict) -> int:
    return e.get("prompt_tokens", 0) + e.get("completion_tokens", 0) + e.get("defense_tokens", 0)


def table(headers: list[str], rows: list[list[str]], markdown: bool) -> None:
    if markdown:
        print("| " + " | ".join(headers) + " |")
        print("|" + "---|" * len(headers))
        for r in rows:
            print("| " + " | ".join(r) + " |")
    else:
        widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
        print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
        for r in rows:
            print("  ".join(c.ljust(w) for c, w in zip(r, widths)))
    print()


def summarize(episodes: list[dict], campaigns: list[dict], markdown: bool) -> None:
    ok = [e for e in episodes if e.get("status", "ok") == "ok"]
    errors = [e for e in episodes if e.get("status", "ok") != "ok"]
    models = sorted({e["model"] for e in episodes} | {c["model"] for c in campaigns})
    h = (lambda s: print(f"## {s}\n")) if markdown else (lambda s: print(f"=== {s} ==="))

    h(f"{len(episodes)} episodes ({len(errors)} errored), {len(campaigns)} campaigns, "
      f"served: {', '.join(sorted({e.get('served_model') or e['model'] for e in ok}))}")
    if errors:
        reasons = defaultdict(int)
        for e in errors:
            reasons[(e.get("error") or "").split(":")[0][:60]] += 1
        table(["error", "count"], [[k, str(v)] for k, v in sorted(reasons.items(), key=lambda kv: -kv[1])], markdown)

    for model in models:
        rows = [e for e in ok if e["model"] == model]
        if not rows:
            continue
        attacks = sorted({e["attack"] for e in rows}, key=lambda a: (a == "no_attack", a))
        defenses = sorted({e["defense"] for e in rows}, key=lambda d: (d != "no_defense", d))

        h(f"{model}: exfiltration ASR, attack x defense (n per cell = {len(rows) // max(1, len(attacks) * len(defenses))})")
        grid = []
        for a in attacks:
            line = [a]
            for d in defenses:
                cell = [e for e in rows if e["attack"] == a and e["defense"] == d]
                line.append(rate(sum(e["succeeded"] for e in cell), len(cell)))
            grid.append(line)
        table(["attack", *defenses], grid, markdown)

        h(f"{model}: per defense")
        drows = []
        for d in defenses:
            cell = [e for e in rows if e["defense"] == d]
            attacked = [e for e in cell if e["attack"] != "no_attack"]
            control = [e for e in cell if e["attack"] == "no_attack"]
            errs = [e for e in errors if e["model"] == model and e["defense"] == d]
            drows.append([
                d,
                rate(sum(e["succeeded"] for e in attacked), len(attacked)),
                rate(sum(e["task_completed"] for e in attacked), len(attacked)),
                rate(sum(e["task_completed"] for e in control), len(control)),
                f"{statistics.mean(map(tokens, cell)):.0f}" if cell else "-",
                f"{statistics.mean(e.get('defense_tokens', 0) for e in cell):.0f}" if cell else "-",
                str(sum(e.get("stop_reason") == "max_turns" for e in cell)),
                str(len(errs)),
            ])
        table(["defense", "ASR (attacked)", "utility (attacked)", "utility (no_attack)",
               "tokens/episode", "defense tokens", "capped", "errors"], drows, markdown)

        h(f"{model}: per adapter (attacked episodes)")
        arows = []
        for ad in sorted({e["adapter"] for e in rows}):
            cell = [e for e in rows if e["adapter"] == ad and e["attack"] != "no_attack"]
            arows.append([ad, rate(sum(e["succeeded"] for e in cell), len(cell)),
                          rate(sum(e["task_completed"] for e in cell), len(cell)),
                          f"{statistics.mean(e.get('model_calls', 0) for e in cell):.1f}" if cell else "-"])
        table(["adapter", "ASR", "utility", "model calls/episode"], arows, markdown)

    if campaigns:
        cok = [c for c in campaigns if c.get("status", "ok") == "ok"]
        h(f"campaigns: {len(campaigns)} ({len(campaigns) - len(cok)} aborted), break rate within budget")
        crows = []
        for model in models:
            for attack in sorted({c["attack"] for c in cok if c["model"] == model}):
                for d in sorted({c["defense"] for c in cok if c["model"] == model}, key=lambda d: (d != "no_defense", d)):
                    cell = [c for c in cok if c["model"] == model and c["attack"] == attack and c["defense"] == d]
                    if not cell:
                        continue
                    att = [c["attempts_to_break"] for c in cell if c.get("attempts_to_break") is not None]
                    ctok = [c.get("target_prompt_tokens", 0) + c.get("target_completion_tokens", 0)
                            + c.get("attacker_tokens", 0) + c.get("defense_tokens", 0) for c in cell]
                    crows.append([model, attack, d, str(cell[0]["budget"]),
                                  rate(sum(c["broke"] for c in cell), len(cell)),
                                  f"{statistics.median(att):.0f}" if att else "never",
                                  f"{statistics.mean(ctok):.0f}", str(sum(c.get("errors", 0) for c in cell))])
        table(["model", "attack", "defense", "budget", "break rate", "median attempts", "tokens/campaign", "eval errors"],
              crows, markdown)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("results", nargs="+", help="results JSON files written by tripwire")
    parser.add_argument("--markdown", action="store_true", help="emit markdown tables")
    args = parser.parse_args()
    episodes, campaigns = load(args.results)
    summarize(episodes, campaigns, args.markdown)


if __name__ == "__main__":
    main()
