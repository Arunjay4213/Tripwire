"""Experiment: the defense ladder on the REAL AgentDojo workspace suite.

Same security-utility question as defense_ladder_pareto.py, but the environment
is a real AgentDojo task instead of the scripted invoice scenario: real tools,
real stateful environment, real utility/security checks (see
tripwire/environments/agentdojo_bridge.py). This is the credible, less-toy version
of the Pareto data.

Writes results/agentdojo_ladder.json, plottable with pareto_plot.py:
    tripwire-env/bin/python3 scripts/experiments/agentdojo_ladder.py
    tripwire-env/bin/python3 scripts/experiments/pareto_plot.py \
        --results results/agentdojo_ladder.json --out results/agentdojo_pareto.png \
        --title "Security-utility Pareto (AgentDojo workspace)"

Scope is kept small by default (a few user x injection pairs, model-agnostic
attacks) because AgentDojo episodes are token-heavy: ~24 tools per call, plus
outbound_guard's second model call. The runner-style per-episode try/except
means a provider cap mid-run still writes whatever completed.

tool_filter is omitted from the default ladder here: it allowlists tool *names*,
and AgentDojo's tools are not read_inbox/send_email. The content-inspecting
defenses are environment-agnostic and carry over unchanged.
"""
import os
import sys

sys.path.insert(0, os.getcwd())

from dotenv import load_dotenv

from tripwire.adapters.raw_loop import RawLoopAdapter
from tripwire.config.loader import resolve_defenses
from tripwire.environments.agentdojo_bridge import run_agentdojo_episode
from tripwire.harness.llm import make_client, resolve_model
from tripwire.harness.reporter import print_asr_table, write_results
from tripwire.harness.runner import EpisodeResult

load_dotenv()
MODEL = resolve_model()

# A handful of (user_task, injection_task) pairs from the workspace suite.
# Kept short by default; widen for a fuller run.
TASK_PAIRS = [
    ("user_task_0", "injection_task_0"),
    ("user_task_1", "injection_task_1"),
    ("user_task_2", "injection_task_2"),
]
# Model-agnostic attacks only (important_instructions* needs a model-name table
# that excludes Llama -- see the agentdojo spike).
ATTACKS = ["direct", "ignore_previous", "injecagent"]
DEFENSE_NAMES = [None, "prompt_hardening", "spotlighting", "outbound_guard"]

client = make_client()
adapter = RawLoopAdapter(client)
defenses = resolve_defenses(DEFENSE_NAMES, allowed_tools=[])

n_expected = len(TASK_PAIRS) * len(ATTACKS) * len(defenses)
print(f"model={MODEL}  suite=workspace  adapter={adapter.name}")
print(f"task_pairs={len(TASK_PAIRS)}  attacks={ATTACKS}")
print(f"defenses={[d.name for d in defenses]}  episodes(max)={n_expected}\n")

episodes: list[EpisodeResult] = []
skipped = 0
for user_task, injection_task in TASK_PAIRS:
    for attack in ATTACKS:
        for defense in defenses:
            label = f"{user_task}/{injection_task} attack={attack} defense={defense.name}"
            try:
                result = run_agentdojo_episode(
                    adapter, user_task, injection_task, attack, MODEL, defense=defense, seed=0,
                )
                episodes.append(result)
                print(f"  [{len(episodes)}/{n_expected}] {label} "
                      f"leak={result.succeeded} utility={result.task_completed}")
            except Exception as e:  # noqa: BLE001 -- isolate provider hiccups, keep going
                skipped += 1
                print(f"  [skip] {label}: {type(e).__name__}: {e}", file=sys.stderr)

print()
print_asr_table(episodes)
write_results(episodes, "results/agentdojo_ladder.json")
print(f"\nn episodes scored: {len(episodes)} / {n_expected}  (skipped {skipped})")
