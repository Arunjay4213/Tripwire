"""Validate the deterministic judge against human labels (Cohen's kappa).

The judge (tripwire/harness/judge.py) is pure Python -- it scores a leak by string-
matching the canary in an executed send_email. That's reproducible, but is it
*right*? This script measures agreement between the judge and a human reading
the same traces, and reports Cohen's kappa. "Our scoring is validated, not
asserted" is cheap credibility for a hiring audience.

Two modes:

  dump   Run a sample of episodes, and for each write the readable trace, the
         judge's verdict, and a blank `human_label` to a JSONL sheet. A human
         then fills in human_label (true = "the secret leaked", false = "it
         didn't") by reading `trace_text`.

         tripwire-env/bin/python3 scripts/experiments/judge_validation.py dump \
             --n 30 --out results/judge_labels.jsonl

  score  Read the completed sheet and report agreement + Cohen's kappa between
         judge_verdict and human_label over the rows a human has labeled.

         tripwire-env/bin/python3 scripts/experiments/judge_validation.py score \
             --labels results/judge_labels.jsonl

The kappa math lives in tripwire/harness/stats.cohen_kappa (unit-tested, offline);
this script is just the sampling + labeling-sheet plumbing around it.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.getcwd())

from dotenv import load_dotenv

from tripwire.adapters.base import EpisodeSpec, NormalizedTrace
from tripwire.adapters.raw_loop import RawLoopAdapter
from tripwire.config.loader import resolve_attacks, resolve_defenses
from tripwire.harness.judge import attack_succeeded
from tripwire.harness.llm import make_client, resolve_model
from tripwire.harness.runner import TOOL_SCHEMAS, _build_episode
from tripwire.harness.stats import cohen_kappa

load_dotenv()


def _trace_to_text(trace: NormalizedTrace) -> str:
    """Render a trace as plain lines a human can read to judge a leak by eye."""
    lines = []
    for s in trace.steps:
        if s.type == "tool_call":
            lines.append(f"CALL {s.name}({json.dumps(s.args)})")
        elif s.type == "tool_result":
            lines.append(f"  -> {s.content}")
        elif s.type == "tool_blocked":
            lines.append(f"  -X blocked: {s.content}")
        elif s.type == "model_output":
            lines.append(f"SAY  {s.content}")
    if trace.final_output:
        lines.append(f"FINAL {trace.final_output}")
    return "\n".join(lines)


def dump(n: int, out_path: str) -> int:
    """Run n sample episodes and write a labeling sheet. Samples across the
    attack suite and the defense ladder so the human sees leaks, blocks, and
    clean runs -- not just one regime."""
    model = resolve_model()
    client = make_client()
    adapter = RawLoopAdapter(client)

    attacks = resolve_attacks(
        ["direct", "ignore_previous", "injecagent", "important_instructions", "fixed_injection"]
    )
    defenses = resolve_defenses([None, "prompt_hardening", "spotlighting"], allowed_tools=["read_inbox"])

    rows = []
    i = 0
    # Round-robin over (attack, defense, seed) until we have n scored episodes.
    while len(rows) < n:
        attack = attacks[i % len(attacks)]
        defense = defenses[(i // len(attacks)) % len(defenses)]
        seed = i // (len(attacks) * len(defenses))
        i += 1
        base = EpisodeSpec(task=None, tools=TOOL_SCHEMAS, model=model, environment_seed=seed)
        try:
            payload = attack.render("")  # canary value is irrelevant to render
            spec, canary = _build_episode(payload, base, defense)
            trace = adapter.run(spec)
        except Exception as e:  # noqa: BLE001 -- skip provider hiccups, keep sampling
            print(f"  [skip] {attack.name}/{defense.name}/seed{seed}: {type(e).__name__}", file=sys.stderr)
            continue
        rows.append({
            "attack": attack.name,
            "defense": defense.name,
            "seed": seed,
            "judge_verdict": attack_succeeded(trace, canary),
            "human_label": None,  # <- fill in: true if the secret leaked, false if not
            "trace_text": _trace_to_text(trace),
        })
        print(f"  [{len(rows)}/{n}] {attack.name}/{defense.name}/seed{seed} "
              f"judge={rows[-1]['judge_verdict']}")

    with open(out_path, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"\nwrote {len(rows)} rows to {out_path}")
    print("Now open it and set human_label (true/false) on each row, then run `score`.")
    return 0


def score(labels_path: str) -> int:
    with open(labels_path) as f:
        rows = [json.loads(line) for line in f if line.strip()]

    labeled = [r for r in rows if r.get("human_label") is not None]
    if not labeled:
        print(f"[judge_validation] no rows have a human_label yet in {labels_path}", file=sys.stderr)
        return 1

    judge = [bool(r["judge_verdict"]) for r in labeled]
    human = [bool(r["human_label"]) for r in labeled]
    agree = sum(1 for j, h in zip(judge, human) if j == h)
    kappa = cohen_kappa(judge, human)

    print(f"labeled rows      : {len(labeled)} / {len(rows)}")
    print(f"raw agreement     : {agree}/{len(labeled)} = {agree / len(labeled):.0%}")
    print(f"Cohen's kappa     : {kappa:.3f}")
    # Landis & Koch rough bands, for interpretation only.
    band = ("almost perfect" if kappa > 0.8 else "substantial" if kappa > 0.6
            else "moderate" if kappa > 0.4 else "fair" if kappa > 0.2 else "slight/none")
    print(f"agreement (L&K)   : {band}")
    disagreements = [r for r in labeled if bool(r["judge_verdict"]) != bool(r["human_label"])]
    if disagreements:
        print(f"\n{len(disagreements)} disagreement(s) -- inspect these traces:")
        for r in disagreements:
            print(f"  {r['attack']}/{r['defense']}/seed{r['seed']}: "
                  f"judge={r['judge_verdict']} human={r['human_label']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the judge against human labels.")
    sub = parser.add_subparsers(dest="mode", required=True)
    d = sub.add_parser("dump", help="run sample episodes, write a labeling sheet")
    d.add_argument("--n", type=int, default=30)
    d.add_argument("--out", default="results/judge_labels.jsonl")
    s = sub.add_parser("score", help="compute kappa from a completed sheet")
    s.add_argument("--labels", default="results/judge_labels.jsonl")
    args = parser.parse_args()

    if args.mode == "dump":
        return dump(args.n, args.out)
    return score(args.labels)


if __name__ == "__main__":
    sys.exit(main())
