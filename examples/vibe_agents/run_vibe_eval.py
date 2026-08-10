"""Run Tripwire's attack suite against the vibecoded sample agents.

Loads the three examples/vibe_agents/* agents through the same BYO loader real
users get, plus the careful raw_loop baseline, and sweeps the single-shot attack
suite against all four so you can read hijackability per agent, per attack.

Two blocks:
  1. no_defense -- the realistic vibecode deployment (nobody wired a defense in).
  2. spotlighting on the context_stuffer vs raw_loop -- shows that an agent which
     launders untrusted content into the system prompt is NOT protected by an
     input-side defense, because the content never arrives as tool output.

Run:  N=3 examples/vibe_agents/run_vibe_eval.py   (via the direnv python)
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.getcwd())
from dotenv import load_dotenv
load_dotenv(".env", override=True)

from src.adapters.loader import load_agent_module
from src.adapters.raw_loop import RawLoopAdapter
from src.config.loader import resolve_attacks
from src.defenses.base import NoDefense
from src.defenses.spotlighting import Spotlighting
from src.harness.llm import make_client, resolve_model
from src.harness.reporter import print_asr_table
from src.harness.runner import run_sweep

MODEL = resolve_model()
SEEDS = list(range(int(os.getenv("N", "3"))))

VIBE_DIR = "examples/vibe_agents"
vibe_adapters = [
    load_agent_module(f"{VIBE_DIR}/vibe_helpful_assistant.py"),
    load_agent_module(f"{VIBE_DIR}/vibe_context_stuffer.py"),
    load_agent_module(f"{VIBE_DIR}/vibe_autonomous_agent.py"),
]
careful = RawLoopAdapter(make_client())
adapters = [careful, *vibe_adapters]

ATTACKS = ["direct", "important_instructions", "fixed_injection", "metadata_exfil",
           "public_identifier", "forged_boundary", "prerequisite_mirror", "mundane_redirect"]
attacks = resolve_attacks(ATTACKS)

print(f"model={MODEL}  seeds={SEEDS}  adapters={[a.name for a in adapters]}\n", flush=True)

print("=" * 70)
print("BLOCK 1 -- no_defense (realistic vibecode deployment)")
print("=" * 70, flush=True)
episodes, _ = run_sweep(adapters, [MODEL], attacks, SEEDS, defenses=[NoDefense()])
print_asr_table(episodes)

print("\n" + "=" * 70)
print("BLOCK 2 -- spotlighting: does it protect a context-stuffing agent?")
print("=" * 70, flush=True)
stuffer = load_agent_module(f"{VIBE_DIR}/vibe_context_stuffer.py")
demo_attacks = resolve_attacks(["metadata_exfil", "mundane_redirect"])
episodes2, _ = run_sweep([careful, stuffer], [MODEL], demo_attacks, SEEDS,
                         defenses=[Spotlighting()])
print_asr_table(episodes2)
print("\nDONE", flush=True)
