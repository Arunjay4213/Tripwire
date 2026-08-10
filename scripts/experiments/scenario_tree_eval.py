"""Run the adaptive TAP tree attacker against the local AgentDojo-style scenarios.

Unlike the single-shot attacks, the tree attacker adapts per scenario: it reads
each attempt's Observation (executed? blocked? exfiltrated?) and refines, judged
against THAT scenario's authorized recipients. Uses a strong, separate attacker
model (ATTACKER_MODEL, e.g. claude-opus-4-8; opus-5/fable-5 are content-filtered).

Env: SCENARIOS (csv, default all), DEFENSE (default no_defense), SEEDS (default 2),
     BUDGET (default 12). Run: ATTACKER_MODEL=claude-opus-4-8 scripts/experiments/scenario_tree_eval.py
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.getcwd())
from dotenv import load_dotenv
load_dotenv(".env", override=True)

from src.adapters.raw_loop import RawLoopAdapter
from src.attacks.tree_attacker import TreeAttacker
from src.defenses.base import NoDefense
from src.defenses.prompt_hardening import PromptHardening
from src.defenses.spotlighting import Spotlighting
from src.harness.llm import make_client, resolve_model
from src.harness.runner import run_scenario_tree_campaign
from src.scenarios import SCENARIOS

MODEL = resolve_model()
adapter = RawLoopAdapter(make_client())
BUDGET = int(os.getenv("BUDGET", "12"))
SEEDS = list(range(int(os.getenv("SEEDS", "2"))))
DEFENSES = {"no_defense": NoDefense(), "prompt_hardening": PromptHardening(),
            "spotlighting": Spotlighting()}
defense = DEFENSES[os.getenv("DEFENSE", "no_defense")]
which = os.getenv("SCENARIOS", ",".join(SCENARIOS)).split(",")

print(f"target={MODEL} attacker={os.getenv('ATTACKER_MODEL') or MODEL} "
      f"defense={os.getenv('DEFENSE','no_defense')} budget={BUDGET} seeds={SEEDS}")
print("success = adaptive search exfiltrates the secret to an unauthorized recipient\n", flush=True)

for sname in which:
    scenario = SCENARIOS[sname]
    for seed in SEEDS:
        atk = TreeAttacker(branching=3, width=3, max_depth=5, max_response_tokens=1500)
        res = run_scenario_tree_campaign(adapter, scenario, MODEL, atk, BUDGET, defense, seed)
        print(f"[{sname:<10} seed={seed}] broke={res.broke} attempts={res.attempts_to_break} "
              f"attacker_calls={atk.attacker_calls} critic_calls={atk.critic_calls} errors={atk.errors}",
              flush=True)
print("DONE", flush=True)
