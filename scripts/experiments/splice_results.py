"""Splice a re-run's rows into a results file in place of the rows they replace.

    python scripts/experiments/splice_results.py results/single_deepseek.json \
        --replace results/single_deepseek_calendar.json --out results/single_deepseek.v2.json

When a judge fix or a provider outage makes one slice of a sweep wrong, re-run
that slice (a config with one scenario, one defense, ...) and splice it in:
every row in the replacement whose cell key (adapter, model, scenario, attack,
defense, seed) exists in the base replaces that row; keys new to the base are
appended; base rows with no replacement are kept. The output is a results file
write_results could have written, so every script that reads results reads it.
Prints what was replaced, so the provenance is on the console and in the
commit message, not lost.
"""

from __future__ import annotations

import argparse
import json

KEY = ("adapter", "model", "scenario", "attack", "defense", "seed")


def key(row: dict) -> tuple:
    return tuple(row.get(k) for k in KEY)


def load(path: str) -> tuple[list[dict], list[dict], bool]:
    data = json.load(open(path))
    if isinstance(data, dict):
        return data.get("episodes", []), data.get("campaigns", []), True
    return data, [], False


def splice(base: list[dict], replacement: list[dict]) -> tuple[list[dict], int, int]:
    by_key = {key(r): r for r in replacement}
    out, replaced = [], 0
    for row in base:
        if key(row) in by_key:
            out.append(by_key.pop(key(row)))
            replaced += 1
        else:
            out.append(row)
    appended = len(by_key)
    out.extend(by_key.values())
    return out, replaced, appended


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("base")
    parser.add_argument("--replace", required=True, action="append", help="a re-run results file (repeatable)")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    episodes, campaigns, structured = load(args.base)
    for path in args.replace:
        rep_episodes, rep_campaigns, _ = load(path)
        episodes, replaced, appended = splice(episodes, rep_episodes)
        print(f"{path}: {replaced} episode rows replaced, {appended} appended")
        if rep_campaigns:
            campaigns, replaced, appended = splice(campaigns, rep_campaigns)
            print(f"{path}: {replaced} campaign rows replaced, {appended} appended")
    payload = {"episodes": episodes, "campaigns": campaigns} if (structured or campaigns) else episodes
    with open(args.out, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"wrote {args.out}: {len(episodes)} episodes, {len(campaigns)} campaigns")


if __name__ == "__main__":
    main()
