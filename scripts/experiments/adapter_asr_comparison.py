"""Experiment: does the orchestration layer change attack success rate?

The project's core hypothesis (see README's "The bet"), measured directly:
same model, same attack, same seeds, only the adapter varies. Real results
from a full run of this script are recorded in docs/experiments.md.

Run from repo root:
    tripwire-env/bin/python3 scripts/experiments/adapter_asr_comparison.py
"""
import os
import sys

sys.path.insert(0, os.getcwd())

from dotenv import load_dotenv

from tripwire.adapters.langgraph_adapter import LangGraphAdapter
from tripwire.adapters.multi_agent_adapter import MultiAgentAdapter
from tripwire.adapters.raw_loop import RawLoopAdapter
from tripwire.attacks.agentdojo_wrappers import DirectAttack
from tripwire.harness.llm import make_client, resolve_model
from tripwire.harness.reporter import print_asr_table, write_results
from tripwire.harness.runner import run_sweep

load_dotenv()
MODEL = resolve_model()
SEEDS = list(range(15))

client = make_client()
adapters = [RawLoopAdapter(client), LangGraphAdapter(), MultiAgentAdapter()]

episodes, _ = run_sweep(adapters, [MODEL], [DirectAttack()], SEEDS)
print_asr_table(episodes)
write_results(episodes, "results/adapter_asr_comparison.json")
print(f"\nn episodes scored: {len(episodes)} / {len(adapters) * len(SEEDS)} attempted")
