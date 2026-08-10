"""Experiment: the adaptive (TAP) attacker vs the defense ladder.

The headline red-team result. The single-shot metadata_exfil attack is trivially
blocked by every content-inspecting defense (0% ASR), which could mean the
defenses are strong -- or that the attack was weak. This experiment settles it:
point a genuinely adaptive adversary (TreeAttacker: reasons about the defense
from rich feedback, branches, prunes) at each defense and see which hold.

A defense that holds against an attacker that *adapts to it* is strong; one the
single-shot couldn't beat but the adaptive one can was security theater.

Set a STRONG, separate attacker model -- ATTACKER_MODEL -- distinct from the
target; a weak or target-identical attacker brain is the main thing that caps
result quality. Depth/width/budget trade thoroughness for cost; broke=False is a
lower bound on defense strength at that budget, never proof of robustness.

Run from repo root:
    ATTACKER_MODEL=claude-sonnet-4-5 \
    tripwire-env/bin/python3 scripts/experiments/adaptive_vs_defenses.py
"""
import os
import re
import sys

sys.path.insert(0, os.getcwd())

from dotenv import load_dotenv

from tripwire.adapters.raw_loop import RawLoopAdapter
from tripwire.adapters.base import EpisodeSpec
from tripwire.attacks.tree_attacker import TreeAttacker
from tripwire.defenses.base import NoDefense
from tripwire.defenses.outbound_guard import OutboundGuard
from tripwire.defenses.prompt_hardening import PromptHardening
from tripwire.defenses.spotlighting import Spotlighting
from tripwire.harness.llm import make_client, resolve_model
from tripwire.harness.reporter import print_campaign_table, write_results
from tripwire.harness.runner import CampaignResult, run_tree_campaign

load_dotenv()
TARGET = resolve_model()
SEEDS = list(range(int(os.getenv("ADAPTIVE_SEEDS", "2"))))
BUDGET = int(os.getenv("ADAPTIVE_BUDGET", "15"))   # max target evaluations per campaign
BRANCHING = int(os.getenv("ADAPTIVE_BRANCHING", "3"))
WIDTH = int(os.getenv("ADAPTIVE_WIDTH", "3"))
DEPTH = int(os.getenv("ADAPTIVE_DEPTH", "5"))

client = make_client()
adapter = RawLoopAdapter(client)

# Two outbound_guard variants, because they behave very differently against an
# adaptive attacker:
#  - structural: a regex that flags any long hex token. It inspects for exactly
#    what the judge scores, so it is unbeatable in principle (hiding the token
#    from the guard hides it from the judge too) -- the "perfect but blunt" case.
#  - semantic: the default LLM detector, which judges by CONTEXT. This is the
#    realistic guard, and the one framing/language evasion can actually beat.
_structural_guard = OutboundGuard(detector=lambda t: re.search(r"\b[0-9a-f]{32}\b", t) is not None)
_semantic_guard = OutboundGuard()  # default LLM detector
# (label, defense) -- distinct labels so the two guards don't collide in results.
DEFENSES = [
    ("no_defense", NoDefense()),
    ("prompt_hardening", PromptHardening()),
    ("spotlighting", Spotlighting()),
    ("outbound_guard_semantic", _semantic_guard),
    ("outbound_guard_structural", _structural_guard),
]

print(f"attacker={os.getenv('ATTACKER_MODEL') or TARGET}  target={TARGET}")
print(f"tree: branching={BRANCHING} width={WIDTH} depth={DEPTH} budget={BUDGET}  seeds={SEEDS}\n")

campaigns: list[CampaignResult] = []
for label, defense in DEFENSES:
    for seed in SEEDS:
        atk = TreeAttacker(branching=BRANCHING, width=WIDTH, max_depth=DEPTH)
        spec = EpisodeSpec(task=None, tools=None, model=TARGET, environment_seed=seed)
        try:
            res = run_tree_campaign(adapter, spec, atk, budget=BUDGET, defense=defense)
            res.defense = label  # distinct label (the two guards share defense.name)
            campaigns.append(res)
            print(f"[{label:<26} seed={seed}] broke={res.broke} "
                  f"attempts_to_break={res.attempts_to_break} attacker_calls={atk.attacker_calls}",
                  flush=True)
        except Exception as e:  # noqa: BLE001 -- isolate provider hiccups
            print(f"[{label} seed={seed}] ERR {type(e).__name__}: {e}", file=sys.stderr, flush=True)

print()
print_campaign_table(campaigns)
write_results([], "results/adaptive_vs_defenses.json", campaigns)
print(f"\nwrote results/adaptive_vs_defenses.json ({len(campaigns)} campaigns)")
