"""Experiment: how many adaptive attempts does it take to break an adapter?

Runs the PAIR-style IterativeAttacker as a budgeted campaign per seed and
reports break rate + attempts-to-break. Real results from a run of this
script are recorded in docs/experiments.md, including a real constraint
worth knowing before rerunning this at the seed counts below: Groq's free
tier caps at 100k tokens/day, and adaptive campaigns are far more
token-hungry per data point than single-shot episodes (each attempt = 1
attacker-LLM call + 1 full target-agent tool loop, x up to `budget`
attempts x len(adapters) x len(seeds)). Reduce SEEDS or BUDGET below if you
hit RateLimitError -- run_sweep() will skip and report exhausted seeds
rather than crash, but a mostly-skipped run isn't a usable result.

Run from repo root:
    tripwire-env/bin/python3 scripts/experiments/iterative_attacker_efficiency.py
"""
import os
import sys

sys.path.insert(0, os.getcwd())

from dotenv import load_dotenv

from src.adapters.langgraph_adapter import LangGraphAdapter
from src.adapters.raw_loop import RawLoopAdapter
from src.attacks.iterative import IterativeAttacker
from src.harness.llm import make_client, resolve_model
from src.harness.reporter import print_campaign_table, write_results
from src.harness.runner import run_sweep

load_dotenv()
MODEL = resolve_model()
SEEDS = list(range(10))
BUDGET = 6

client = make_client()
adapters = [RawLoopAdapter(client), LangGraphAdapter()]

_, campaigns = run_sweep(adapters, [MODEL], [IterativeAttacker()], SEEDS, campaign_budget=BUDGET)
print_campaign_table(campaigns)
write_results([], "results/iterative_attacker_efficiency.json", campaigns)
print(f"\nn campaigns scored: {len(campaigns)} / {len(adapters) * len(SEEDS)} attempted")
