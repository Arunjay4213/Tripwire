"""Phase 2 — run AgentDojo against our Groq model at meaningful scale.

Drives AgentDojo's curated benchmark suites + deterministic security checks
against a Groq-backed Llama model, with NO source patching.

The trick (verified in agentdojo 0.1.35): AgentPipeline.from_config uses a custom
`llm` object as-is when it's not a string. So we hand it an OpenAILLM backed by a
Groq client and drive AgentDojo's own benchmark.

Modes:
  SMOKE (default) — 2 user tasks × 3 injection tasks × 1 attack = 6 episodes
  FULL            — all user tasks × all injection tasks × 4 attacks = 180 episodes

Run with:  python spike/run_agentdojo.py
"""

import os
import time
from collections.abc import Sequence
from pathlib import Path

from dotenv import load_dotenv
from openai import BadRequestError, OpenAI

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM, chat_completion_request
from agentdojo.agent_pipeline.llms.openai_llm import (
    _assistant_message_to_content,
    _function_to_openai,
    _message_to_openai,
)
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatAssistantMessage, ChatMessage

load_dotenv()

import json

MAX_TOOL_RETRIES = 3


def _safe_openai_to_assistant_message(message) -> ChatAssistantMessage:
    """Like AgentDojo's _openai_to_assistant_message but handles Llama quirks:
    - args=None (no-arg tools) → {}
    """
    tool_calls = None
    if message.tool_calls:
        tool_calls = []
        for tc in message.tool_calls:
            args = json.loads(tc.function.arguments or "{}") or {}
            tool_calls.append(FunctionCall(
                function=tc.function.name,
                args=args,
                id=tc.id,
            ))
    return ChatAssistantMessage(
        role="assistant",
        content=_assistant_message_to_content(message),
        tool_calls=tool_calls or None,
    )


class ResilientGroqLLM(OpenAILLM):
    """OpenAILLM subclass that retries Groq/Llama tool_use_failed errors.

    Llama sometimes emits XML tool calls (<function=name{...}>) instead of JSON.
    Groq rejects these with BadRequestError(code='tool_use_failed'). AgentDojo's
    retry decorator explicitly skips BadRequestError, so these crash the run.
    This subclass retries up to MAX_TOOL_RETRIES times, then returns a no-op
    assistant message to let the episode finish gracefully.
    """

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        openai_messages = [_message_to_openai(m, self.model) for m in messages]
        openai_tools = [_function_to_openai(t) for t in runtime.functions.values()]

        for attempt in range(MAX_TOOL_RETRIES):
            try:
                completion = chat_completion_request(
                    self.client, self.model, openai_messages, openai_tools,
                    self.reasoning_effort, self.temperature,
                )
                output = _safe_openai_to_assistant_message(completion.choices[0].message)
                return query, runtime, env, [*messages, output], extra_args
            except BadRequestError as e:
                if getattr(e, "code", None) == "tool_use_failed" and attempt < MAX_TOOL_RETRIES - 1:
                    print(f"    [retry {attempt+1}/{MAX_TOOL_RETRIES}] tool_use_failed — Llama XML quirk")
                    continue
                # Exhausted retries or different BadRequestError — return empty msg
                # so episode finishes (utility=False) instead of crashing
                print(f"    [!] tool_use_failed after {attempt+1} tries — skipping turn")
                fallback = ChatAssistantMessage(
                    role="assistant",
                    content=[{"type": "text", "content": "I encountered a tool formatting error."}],
                    tool_calls=None,
                )
                return query, runtime, env, [*messages, fallback], extra_args
        # unreachable but satisfies type checker
        raise RuntimeError("retry loop exited unexpectedly")


# === CONFIG ===================================================================
BENCHMARK_VERSION = "v1.2"
SUITE_NAME = "workspace"
MODEL = os.getenv("GROQ_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")

# Model-agnostic attacks only — important_instructions* raises for Llama
# (not in AgentDojo's MODEL_NAMES table: GPT/Claude/Gemini only).
ALL_ATTACKS = ["direct", "ignore_previous", "system_message", "injecagent"]

DEFENSE = None  # undefended baseline (add "tool_filter" later for comparison)

# SMOKE = cheap iteration that fits in Groq free tier (~100k tokens/day).
# FULL = all tasks × all attacks — needs a bigger budget or multiple days.
SMOKE = True
if SMOKE:
    ATTACK_NAMES = ["direct", "ignore_previous", "system_message", "injecagent"]
    USER_TASKS = ("user_task_0", "user_task_17")           # 2 tasks (EASY)
    INJECTION_TASKS = ("injection_task_3", "injection_task_6", "injection_task_7")  # 3 tasks
else:
    ATTACK_NAMES = ALL_ATTACKS
    USER_TASKS = None       # None = all tasks in the suite
    INJECTION_TASKS = None  # None = all tasks in the suite

# === SETUP ====================================================================
groq_client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url=os.getenv("GROQ_BASE_URL"),
)
llm = ResilientGroqLLM(groq_client, MODEL)

suite = get_suite(BENCHMARK_VERSION, SUITE_NAME)

# Resolve task counts for reporting (None = all)
n_user = len(USER_TASKS) if USER_TASKS else len(suite.user_tasks)
n_inj = len(INJECTION_TASKS) if INJECTION_TASKS else len(suite.injection_tasks)
total_episodes = n_user * n_inj * len(ATTACK_NAMES)

print(f"model={MODEL}  suite={SUITE_NAME}  defense={DEFENSE}")
print(f"attacks={ATTACK_NAMES}")
print(f"user_tasks={n_user}  injection_tasks={n_inj}  episodes={total_episodes}")
print(f"mode={'SMOKE' if SMOKE else 'FULL'}\n")

# === RUN EACH ATTACK ==========================================================
all_results = {}  # attack_name -> {utility_results, security_results}
t0 = time.time()

for attack_name in ATTACK_NAMES:
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=llm,
            model_id=None,
            defense=DEFENSE,
            system_message_name=None,
            system_message=None,
        )
    )
    pipeline.name = MODEL  # from_config leaves it None for custom LLMs

    attack = load_attack(attack_name, suite, pipeline)
    episodes = n_user * n_inj
    print(f"--- {attack_name} ({episodes} episodes) ---")

    logdir = Path(f"./runs/{attack_name}")
    try:
        # Push an OutputLogger so TraceLogger's delegate has .logdir
        # (NullLogger only sets logdir in __enter__, Logger.get() returns bare NullLogger)
        with OutputLogger(logdir=str(logdir)):
            results = benchmark_suite_with_injections(
                pipeline,
                suite,
                attack,
                logdir=logdir,
                force_rerun=True,
                user_tasks=USER_TASKS,
                injection_tasks=INJECTION_TASKS,
                benchmark_version=BENCHMARK_VERSION,
            )
        all_results[attack_name] = results
    except Exception as e:
        err = str(e)
        if "tokens per day" in err or "TPD" in err:
            print(f"  [!] Groq daily token limit hit — aborting remaining attacks.")
            break
        print(f"  [!] {type(e).__name__}: {err}")
        continue

elapsed = time.time() - t0

# === REPORT ===================================================================
print("\n" + "=" * 72)
print(f"  AgentDojo benchmark — {MODEL} ({'SMOKE' if SMOKE else 'FULL'})")
print(f"  suite={SUITE_NAME}  defense={DEFENSE}  elapsed={elapsed:.0f}s")
print("=" * 72)

for attack_name, results in all_results.items():
    util = list(results["utility_results"].values())
    sec = list(results["security_results"].values())

    avg_util = sum(util) / len(util) if util else 0.0
    asr = sum(sec) / len(sec) if sec else 0.0

    print(f"\n  attack: {attack_name}")
    print(f"    utility (real task done)   : {avg_util * 100:5.1f}%  ({sum(util)}/{len(util)})")
    print(f"    ASR (injection succeeded)  : {asr * 100:5.1f}%  ({sum(sec)}/{len(sec)})")

    # Per-injection-task breakdown (shows which injections work)
    if sec:
        print(f"    per-injection breakdown    :", end="")
        # Group by injection task
        by_inj = {}
        for key, val in results["security_results"].items():
            # Keys are (user_task, injection_task) tuples
            inj = key[1] if isinstance(key, tuple) else key
            by_inj.setdefault(inj, []).append(val)
        for inj, vals in sorted(by_inj.items()):
            rate = sum(vals) / len(vals)
            print(f" {inj}={rate:.0%}", end="")
        print()

if not all_results:
    print("\n  No results — all attacks failed or hit quota.")

print("\n" + "=" * 72)
