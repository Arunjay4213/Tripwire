"""Experiment: the security-utility Pareto across the defense ladder.

Sweeps one adapter over the full attack suite against every defense on the
ladder (no_defense -> prompt_hardening -> spotlighting -> tool_filter ->
outbound_guard), holding model and seeds constant. Writes a results JSON that
scripts/experiments/pareto_plot.py turns into the money chart: ASR (x) vs
utility-retained (y), one point per defense.

This is the run that gives the frontier its shape -- a single defense is a
single point, and the whole argument of the project is that different
mitigations trade security for utility differently.

Run from repo root (needs GROQ_API_KEY etc. in .env):
    tripwire-env/bin/python3 scripts/experiments/defense_ladder_pareto.py

Cost note: outbound_guard adds a second model call per send_email, and the
full grid is len(attacks) x len(defenses) x len(seeds) episodes. On the Groq
free tier this can hit the daily token cap; the runner fault-isolates each
episode (see run_sweep), so a capped run still writes whatever completed.
"""
import os
import sys

sys.path.insert(0, os.getcwd())

from dotenv import load_dotenv

from src.adapters.raw_loop import RawLoopAdapter
from src.config.loader import resolve_attacks, resolve_defenses
from src.harness.llm import make_client, resolve_model
from src.harness.reporter import print_asr_table, write_results
from src.harness.runner import run_sweep

load_dotenv()
MODEL = resolve_model()
SEEDS = list(range(int(os.getenv("PARETO_SEEDS", "5"))))

# The single-shot templated attacks -- deterministic and seed-reproducible.
# The adaptive `iterative` attacker is left out here: it runs a budgeted
# campaign (not one episode) and is not seed-reproducible, so it belongs in
# the attacker-efficiency experiment, not the Pareto grid.
# Includes metadata_exfil -- the strong operational-reframe attack that drives an
# undefended aligned model to high ASR (the naive templated attacks leave a robust
# model near 0%, which flattens the frontier). See attacks/fixed_injection.py.
ATTACKS = ["direct", "ignore_previous", "system_message", "injecagent",
           "important_instructions", "fixed_injection", "metadata_exfil"]

# The full ladder, cheap-weak -> expensive-strong. tool_filter needs an
# allowlist; the rest take no args (see resolve_defenses).
DEFENSE_NAMES = [None, "prompt_hardening", "spotlighting", "tool_filter", "outbound_guard"]
ALLOWED_TOOLS = ["read_inbox"]

client = make_client()
adapters = [RawLoopAdapter(client)]
attacks = resolve_attacks(ATTACKS)
defenses = resolve_defenses(DEFENSE_NAMES, ALLOWED_TOOLS)

n_expected = len(adapters) * len(attacks) * len(defenses) * len(SEEDS)
print(f"model={MODEL}  adapters={[a.name for a in adapters]}")
print(f"attacks={ATTACKS}")
print(f"defenses={[d.name for d in defenses]}  seeds={SEEDS}")
print(f"episodes (max)={n_expected}\n")

episodes, campaigns = run_sweep(adapters, [MODEL], attacks, SEEDS, defenses=defenses)

print_asr_table(episodes)
write_results(episodes, "results/defense_ladder_pareto.json", campaigns)
print(f"\nn episodes scored: {len(episodes)} / {n_expected} attempted")
