"""Summarize a held-out replay run against the library it replayed.

    python scripts/experiments/summarize_replay.py results/replay_deepseek_defended.json \
        results/replay_deepseek_defended_heldout.json --markdown

A replay row only carries the case name (``replay:<attacker>:<digest>``), so the
provenance of each payload (which attacker found it, against which defense) is
read from the library and joined by that name. Prints, per (source attacker,
source defense): how many payloads were replayed, the pooled replay ASR on each
rung with Wilson intervals, and how many payloads leaked at least once on the
rung they were discovered against. Errored episodes are excluded from every rate
and counted separately, as in summarize_results.py. No LLM, no network.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict

sys.path.insert(0, ".")
from tripwire.attacks.replay import ReplayCase  # noqa: E402
from tripwire.harness.stats import wilson_ci  # noqa: E402

SOURCE_ORDER = ("no_defense", "prompt_hardening", "spotlighting", "outbound_guard")


def rate(k: int, n: int) -> str:
    if not n:
        return "-"
    lo, hi = wilson_ci(k, n)
    return f"{k / n:.0%} [{lo:.0%}, {hi:.0%}]"


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


def load_episodes(path: str) -> list[dict]:
    data = json.load(open(path))
    return data.get("episodes", []) if isinstance(data, dict) else data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("library", help="the replay library that was replayed")
    parser.add_argument("results", help="the results file the replay wrote")
    parser.add_argument("--markdown", action="store_true", help="emit markdown tables")
    args = parser.parse_args()

    cases = {ReplayCase(**r).name: ReplayCase(**r) for r in json.load(open(args.library))["records"]}
    episodes = load_episodes(args.results)
    unknown = sorted({e["attack"] for e in episodes} - set(cases))
    if unknown:
        sys.exit(f"{len(unknown)} replay case(s) in the results are not in the library: {unknown[:3]}")

    ok = [e for e in episodes if e.get("status", "ok") == "ok"]
    errors = [e for e in episodes if e.get("status", "ok") != "ok"]
    defenses = sorted({e["defense"] for e in ok}, key=lambda d: (d != "no_defense", d))
    replayed = {e["attack"] for e in episodes}
    markdown = args.markdown
    h = (lambda s: print(f"## {s}\n")) if markdown else (lambda s: print(f"=== {s} ==="))

    seeds = sorted({e["seed"] for e in episodes})
    h(f"{len(replayed)} of {len(cases)} payloads replayed on seeds {seeds[0]}..{seeds[-1]}: "
      f"{len(episodes)} episodes ({len(errors)} errored), served: "
      f"{', '.join(sorted({e.get('served_model') or e['model'] for e in ok}))}")

    # Pooled replay ASR per (source attacker, source defense) on every rung.
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for name in replayed:
        case = cases[name]
        groups[(case.source_attack, case.source_defense)].append(name)

    def ordered(keys):
        return sorted(keys, key=lambda k: (k[0], SOURCE_ORDER.index(k[1]) if k[1] in SOURCE_ORDER else 99))

    h("replay ASR by source cell (pooled over the payloads' scenarios, both adapters, all held-out seeds)")
    rows = []
    for attacker, source in ordered(groups):
        names = set(groups[(attacker, source)])
        line = [attacker, source, str(len(names))]
        for d in defenses:
            cell = [e for e in ok if e["attack"] in names and e["defense"] == d]
            line.append(rate(sum(e["succeeded"] for e in cell), len(cell)))
        rows.append(line)
    table(["attacker", "found against", "payloads", *[f"replay on {d}" for d in defenses]], rows, markdown)

    # Per payload, on the rung it was found against: does the discovery hold up?
    h("per payload, on the rung it was found against")
    rows = []
    for attacker, source in ordered(groups):
        per_payload = []
        for name in groups[(attacker, source)]:
            cell = [e for e in ok if e["attack"] == name and e["defense"] == source]
            if cell:
                per_payload.append(sum(e["succeeded"] for e in cell) / len(cell))
        if not per_payload:
            continue
        leaked = sum(p > 0 for p in per_payload)
        rows.append([attacker, source, str(len(per_payload)),
                     f"{leaked} of {len(per_payload)}",
                     f"{statistics.median(per_payload):.0%}",
                     f"{min(per_payload):.0%}", f"{max(per_payload):.0%}"])
    table(["attacker", "found against", "payloads", "leaked at least once", "median ASR", "min", "max"],
          rows, markdown)

    h("replay ASR by adapter, on the rung each payload was found against")
    rows = []
    for adapter in sorted({e["adapter"] for e in ok}):
        cell = [e for e in ok if e["adapter"] == adapter and e["defense"] == cases[e["attack"]].source_defense]
        rows.append([adapter, rate(sum(e["succeeded"] for e in cell), len(cell))])
    table(["adapter", "replay ASR"], rows, markdown)

    if errors:
        reasons = defaultdict(int)
        for e in errors:
            reasons[(e.get("error") or "").split(":")[0][:60]] += 1
        h("errors (excluded from every rate)")
        table(["error", "count"], [[k, str(v)] for k, v in sorted(reasons.items(), key=lambda kv: -kv[1])], markdown)


if __name__ == "__main__":
    main()
