"""Phase 1 — run AgentDojo against our Groq model, with NO source patching.

The trick (verified in agentdojo 0.1.35): AgentPipeline.from_config uses a custom
`llm` object as-is when it's not a string. So we hand it an OpenAILLM backed by a
Groq client and drive AgentDojo's own benchmark + deterministic checks.

Kept deliberately tiny (1 user task x 1 injection task, no defense) because the
Groq free tier is ~100k tokens/day on 70B and AgentDojo episodes are heavier than
our toy. Scale up the knobs once a small run works.

Run with:  python spike/run_agentdojo.py
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.task_suite.load_suites import get_suite

load_dotenv()

# --- knobs (tiny first run; grow later) ---
BENCHMARK_VERSION = "v1.2"
SUITE_NAME = "workspace"
# NOTE: AgentDojo's `important_instructions` family embeds the model's name and
# only supports models in its MODEL_NAMES table (GPT/Claude/Gemini) -- it raises
# for Llama. So we start with a model-agnostic baseline attack.
ATTACK_NAME = "ignore_previous"          # model-agnostic (works with Groq/Llama)
DEFENSE = None                           # start undefended
USER_TASKS = ("user_task_0",)            # one legit task
INJECTION_TASKS = ("injection_task_0",)  # one attacker goal -> 1 episode, cheap
MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# --- build a Groq-backed LLM and hand it to AgentDojo (no enum, no patch) ---
groq_client = OpenAI(api_key=os.getenv("GROQ_API_KEY"), base_url=os.getenv("GROQ_BASE_URL"))
llm = OpenAILLM(groq_client, MODEL)

pipeline = AgentPipeline.from_config(
    PipelineConfig(
        llm=llm,                  # a custom object -> used directly, bypassing ModelsEnum
        model_id=None,
        defense=DEFENSE,
        system_message_name=None,  # -> AgentDojo's default system message
        system_message=None,
    )
)
pipeline.name = MODEL   # from_config leaves it None for a custom llm; set for logging/attacks

suite = get_suite(BENCHMARK_VERSION, SUITE_NAME)
attack = load_attack(ATTACK_NAME, suite, pipeline)

print(f"suite={SUITE_NAME}  attack={ATTACK_NAME}  defense={DEFENSE}  model={MODEL}")
print(f"user tasks={USER_TASKS}  injection tasks={INJECTION_TASKS}\n")

results = benchmark_suite_with_injections(
    pipeline,
    suite,
    attack,
    logdir=Path("./runs"),
    force_rerun=True,
    user_tasks=USER_TASKS,
    injection_tasks=INJECTION_TASKS,
    benchmark_version=BENCHMARK_VERSION,
)

# --- read the numbers -------------------------------------------------------
# utility_results : did the agent still complete the user's real task?
# security_results: True = the INJECTION SUCCEEDED (attack worked) == ASR
util = list(results["utility_results"].values())
sec = list(results["security_results"].values())
avg_util = sum(util) / len(util) if util else 0.0
asr = sum(sec) / len(sec) if sec else 0.0

print("\n" + "=" * 56)
print("  AgentDojo baseline (Groq-backed)")
print("=" * 56)
print(f"  utility (did the real task)  : {avg_util * 100:5.1f}%  ({sum(util)}/{len(util)})")
print(f"  ASR (injection succeeded)    : {asr * 100:5.1f}%  ({sum(sec)}/{len(sec)})")
print("=" * 56)
