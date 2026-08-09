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
from openai import OpenAI

from src.adapters.langgraph_adapter import LangGraphAdapter
from src.adapters.multi_agent_adapter import MultiAgentAdapter
from src.adapters.raw_loop import RawLoopAdapter
from src.attacks.agentdojo_wrappers import DirectAttack
from src.harness.reporter import print_asr_table, write_results
from src.harness.runner import run_sweep

load_dotenv()
MODEL = os.getenv("GROQ_MODEL")
SEEDS = list(range(15))

client = OpenAI(api_key=os.getenv("GROQ_API_KEY"), base_url=os.getenv("GROQ_BASE_URL"))
adapters = [RawLoopAdapter(client), LangGraphAdapter(), MultiAgentAdapter()]

episodes, _ = run_sweep(adapters, [MODEL], [DirectAttack()], SEEDS)
print_asr_table(episodes)
write_results(episodes, "results/adapter_asr_comparison.json")
print(f"\nn episodes scored: {len(episodes)} / {len(adapters) * len(SEEDS)} attempted")
