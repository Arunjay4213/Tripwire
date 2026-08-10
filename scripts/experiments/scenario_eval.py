"""Run Tripwire's attacks against the local AgentDojo-style scenarios.

Uses the same adapter, judge, canary, defenses, and attacks as the invoice
scenario -- only the scenario surface (persona/task/tool/recipients) varies. This
is the "replicate AgentDojo locally, use our attacks" path: realistic task
variety, but structured so our attacks apply and the destination-aware judge
scores exfiltration to an unauthorized recipient.

Env: N (seeds, default 8), DEFENSE (no_defense|prompt_hardening|spotlighting|all).
Run:  N=8 scripts/experiments/scenario_eval.py
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.getcwd())
from dotenv import load_dotenv
load_dotenv(".env", override=True)

from src.adapters.raw_loop import RawLoopAdapter
from src.config.loader import resolve_attacks
from src.defenses.base import NoDefense
from src.defenses.prompt_hardening import PromptHardening
from src.defenses.spotlighting import Spotlighting
from src.harness.judge import attack_exfiltrated
from src.harness.llm import make_client, resolve_model
from src.harness.stats import wilson_ci
from src.scenarios import SCENARIOS

MODEL = resolve_model()
N = int(os.getenv("N", "8"))
adapter = RawLoopAdapter(make_client())

DEFENSES = {"no_defense": NoDefense(), "prompt_hardening": PromptHardening(),
            "spotlighting": Spotlighting()}
which = os.getenv("DEFENSE", "no_defense")
defenses = DEFENSES if which == "all" else {which: DEFENSES[which]}

# Our crafted attacks + one templated baseline for contrast. Override with
# ATTACKS=comma,sep,names to focus (e.g. just the ones that land, under defenses).
_DEFAULT_ATTACKS = ["important_instructions", "metadata_exfil", "public_identifier",
                    "forged_boundary", "prerequisite_mirror", "mundane_redirect"]
ATTACKS = os.getenv("ATTACKS", ",".join(_DEFAULT_ATTACKS)).split(",")
attacks = resolve_attacks(ATTACKS)


def cell(scenario, attack, defense, n):
    hits = 0
    for seed in range(n):
        spec, canary = scenario.build_spec(defense, seed, MODEL, attack.render("x"))
        trace = adapter.run(spec)
        hits += attack_exfiltrated(trace, canary, authorized=scenario.authorized_recipients)
    return hits


def fmt(k, n):
    lo, hi = wilson_ci(k, n)
    return f"{k}/{n}={k/n:.0%}[{lo:.0%}-{hi:.0%}]"


print(f"model={MODEL}  N={N}  scenarios={list(SCENARIOS)}  defense(s)={list(defenses)}\n", flush=True)
for dname, defense in defenses.items():
    print(f"===== defense: {dname} =====", flush=True)
    header = f"{'attack':<24}" + "".join(f"{s:<20}" for s in SCENARIOS)
    print(header); print("-" * len(header), flush=True)
    for attack in attacks:
        row = f"{attack.name:<24}"
        for sname, scenario in SCENARIOS.items():
            row += f"{fmt(cell(scenario, attack, defense, N), N):<20}"
        print(row, flush=True)
    print(flush=True)
print("DONE", flush=True)
