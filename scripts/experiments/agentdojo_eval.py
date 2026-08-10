"""Run a real AgentDojo benchmark grid through the Tripwire bridge.

Instead of the scripted invoice/canary scenario, each episode is a real
AgentDojo workspace task: its prompt, its ~24 stateful tools, its injection
attack, and its OWN utility/security checks (scored on environment state, not on
the trace). The agent under test is Tripwire's raw_loop adapter driving our
target model, so this measures how our setup does on the external benchmark.

Model-agnostic attacks only (important_instructions needs AgentDojo's model-name
table). Reports utility (real task done) and ASR (injection succeeded) per
attack, for no_defense and for spotlighting, over the same task grid.

Run:  scripts/experiments/agentdojo_eval.py   (via the direnv python)
"""
from __future__ import annotations
import os, sys, time
sys.path.insert(0, os.getcwd())
from dotenv import load_dotenv
load_dotenv(".env", override=True)

from src.adapters.raw_loop import RawLoopAdapter
from src.defenses.base import NoDefense
from src.defenses.spotlighting import Spotlighting
from src.environments.agentdojo_bridge import run_agentdojo_episode
from src.harness.llm import make_client, resolve_model
from src.harness.stats import wilson_ci

MODEL = resolve_model()
adapter = RawLoopAdapter(make_client())

USER_TASKS = ["user_task_0", "user_task_1", "user_task_3"]
INJECTION_TASKS = ["injection_task_0", "injection_task_3", "injection_task_6"]
ATTACKS = ["direct", "ignore_previous", "system_message", "injecagent",
           "important_instructions"]  # important_instructions = AgentDojo's strongest
DEFENSES = [("no_defense", NoDefense()), ("spotlighting", Spotlighting())]


def fmt(k, n):
    lo, hi = wilson_ci(k, n)
    return f"{k}/{n}={k/n:.0%}[{lo:.0%}-{hi:.0%}]" if n else "n/a"


print(f"model={MODEL}  suite=workspace  adapter={adapter.name}")
print(f"grid: {len(USER_TASKS)} user x {len(INJECTION_TASKS)} injection x {len(ATTACKS)} attacks "
      f"= {len(USER_TASKS)*len(INJECTION_TASKS)*len(ATTACKS)} episodes per defense\n", flush=True)

t0 = time.time()
for dname, defense in DEFENSES:
    print(f"=== defense: {dname} ===", flush=True)
    tot_util = tot_asr = tot_n = 0
    for attack in ATTACKS:
        util = asr = n = 0
        for ut in USER_TASKS:
            for it in INJECTION_TASKS:
                try:
                    r = run_agentdojo_episode(adapter, ut, it, attack, MODEL, defense)
                except Exception as e:  # noqa: BLE001
                    print(f"    [skip {ut}/{it}/{attack}] {type(e).__name__}: {str(e)[:80]}", flush=True)
                    continue
                util += int(r.task_completed); asr += int(r.succeeded); n += 1
        tot_util += util; tot_asr += asr; tot_n += n
        print(f"  {attack:<18} utility {fmt(util, n):<22} ASR {fmt(asr, n)}", flush=True)
    print(f"  {'OVERALL':<18} utility {fmt(tot_util, tot_n):<22} ASR {fmt(tot_asr, tot_n)}\n", flush=True)

print(f"elapsed={time.time()-t0:.0f}s\nDONE", flush=True)
