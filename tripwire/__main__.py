"""CLI entrypoint — python -m tripwire --config threat_model.yaml"""

from __future__ import annotations

import argparse
import os
import sys

from dotenv import find_dotenv, load_dotenv

from tripwire.adapters.loader import load_agent_module
from tripwire.config.loader import load_config, resolve_attacks
from tripwire.harness.reporter import (
    print_asr_table,
    print_campaign_table,
    print_security_report,
    write_results,
)
from tripwire.harness.llm import active_provider, has_provider_key, make_client, provider_key_names
from tripwire.harness.runner import run_sweep

# Exit codes, so CI can tell "nothing was measured" apart from a bad config.
EXIT_CONFIG_ERROR = 1   # bad config / agent file / missing key / failed preflight
EXIT_NOTHING_SCORED = 2  # the sweep ran but not a single episode was scored
EXIT_ERRORS_STRICT = 3   # --strict and at least one episode errored

# A ready-to-run starter config written by `tripwire init` -- so a fresh
# `pip install` has something to point --config at without cloning the repo.
STARTER_CONFIG = """\
# Tripwire config -- created by `tripwire init`. Edit, then run:
#   tripwire --config threat_model.yaml --smoke                 # quick check
#   tripwire --config threat_model.yaml                         # full run
#   tripwire --config threat_model.yaml --agent my_agent.py     # your own agent

# The model under test. Pick an id your provider serves and set the matching
# API key: ANTHROPIC_API_KEY (default here), OPENAI_API_KEY, OPENROUTER_API_KEY,
# or GROQ_API_KEY. Examples: claude-haiku-4-5, gpt-4o-mini, openai/gpt-4o-mini.
models:
  - claude-haiku-4-5

# The agent(s) to test. Built-ins: raw_loop, langgraph, multi_agent.
# Override them entirely with `tripwire --agent path/to/your_agent.py`.
adapters:
  - raw_loop

# The tasks to attack the agent on, each with its own authorized recipient.
scenarios:
  - invoice
  - helpdesk
  - calendar
  - expense

# The attacks to run (see docs/attacks.md). The hand-crafted ones are the ones
# that actually break defenses; `direct` is a weak baseline for reference.
# `--smoke` runs only the first attack, so a strong one leads. Add `iterative`
# / `tree_attacker` for adaptive attacks (needs ATTACKER_MODEL).
attacks:
  - metadata_exfil
  - public_identifier
  - forged_boundary
  - prerequisite_mirror
  - mundane_redirect
  - direct

# Defenses to measure. `null` = no defense. prompt_hardening and spotlighting
# change what the model is told; recipient_allowlist enforces: a send to an
# address the user never named does not run. Also available: sandwich,
# datamarking, outbound_guard (a second model), secret_egress_scan,
# taint_tracking, tool_filter (see docs/methodology.md).
defenses:
  - null
  - prompt_hardening
  - spotlighting
  - recipient_allowlist

# Seeds = independent trials (the model still samples at temperature). More
# seeds -> tighter confidence intervals. 3 is a quick look; 15+ for real numbers.
seeds: [0, 1, 2]

# Run controls. max_turns = model calls per episode, the same for every adapter.
limits:
  max_turns: 5
"""


def _init_command(argv: list[str]) -> None:
    """`tripwire init [path]` -- write a starter config the user can run."""
    p = argparse.ArgumentParser(
        prog="tripwire init",
        description="Write a starter threat_model.yaml you can edit and run.",
    )
    p.add_argument("path", nargs="?", default="threat_model.yaml",
                   help="where to write the config (default: threat_model.yaml)")
    p.add_argument("--force", action="store_true", help="overwrite if the file already exists")
    args = p.parse_args(argv)

    if os.path.exists(args.path) and not args.force:
        print(f"Error: {args.path} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)
    with open(args.path, "w") as f:
        f.write(STARTER_CONFIG)
    print(
        f"Wrote {args.path}. Next:\n"
        f"  export ANTHROPIC_API_KEY=...              # or OPENAI_/OPENROUTER_/GROQ_API_KEY\n"
        f"  tripwire --config {args.path} --smoke     # quick check\n"
        f"  tripwire --config {args.path} --agent path/to/your_agent.py"
    )


def _load_env_file() -> None:
    """Load the user's .env, searching from the current directory upward.

    Plain load_dotenv() searches upward from the directory of the calling
    file, which for a pip-installed tripwire is site-packages, so a .env next
    to the user's config would never be found.
    """
    env_path = find_dotenv(usecwd=True)
    if env_path:
        load_dotenv(env_path)


def _provider_label() -> str:
    provider = active_provider()
    if provider is None:
        return "none"
    return f"{provider.key_env} -> {provider.base_url() or 'https://api.openai.com/v1'}"


def _preflight_models(config) -> list[str]:
    """Every model id the sweep will call: the targets, plus ATTACKER_MODEL /
    GUARD_MODEL when the attacks/defenses that use them are configured."""
    models = list(config.models)
    if os.getenv("ATTACKER_MODEL") and any(a in ("iterative", "tree_attacker") for a in config.attacks):
        models.append(os.environ["ATTACKER_MODEL"])
    if os.getenv("GUARD_MODEL") and any(d.name == "outbound_guard" for d in config.defenses):
        models.append(os.environ["GUARD_MODEL"])
    return list(dict.fromkeys(models))


def _preflight(config) -> None:
    """One cheap chat completion per model, so a model/provider mismatch fails
    in seconds with a clear message instead of as N errored episodes."""
    client = make_client()
    for model in _preflight_models(config):
        try:
            client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Reply with the single word OK."}],
            )
        except Exception as e:  # noqa: BLE001 -- any failure here is the finding
            print(
                f"Error: preflight call to model {model!r} failed on provider "
                f"{_provider_label()}: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            sys.exit(EXIT_CONFIG_ERROR)
        print(f"Preflight ok: {model}")


def _is_scored(result: object) -> bool:
    return getattr(result, "status", "ok") == "ok"


def _report_outcome(episodes: list, campaigns: list, strict: bool) -> None:
    """Exit non-zero when the sweep measured nothing, and flag errored runs.

    Errored episodes/campaigns stay in the results (and tables) as errors;
    they are never counted as defended. This makes sure a sweep where some or
    all runs errored cannot look like a clean, complete run.
    """
    results = [*episodes, *campaigns]
    errored = [r for r in results if not _is_scored(r)]
    scored = len(results) - len(errored)

    if scored == 0:
        print(
            f"\nError: nothing was scored ({len(errored)} episode(s)/campaign(s) errored, "
            "none scored), so there is no result to report.",
            file=sys.stderr,
        )
        messages = [str(getattr(r, "error", "") or "").strip() for r in errored]
        for message in list(dict.fromkeys(m for m in messages if m))[:3]:
            print(f"  e.g. {message.splitlines()[-1]}", file=sys.stderr)
        print(
            f"Check that the models in your config are served by the active provider "
            f"({_provider_label()}); `--preflight` checks this up front.",
            file=sys.stderr,
        )
        sys.exit(EXIT_NOTHING_SCORED)

    if errored:
        print(
            f"\nWARNING: {len(errored)} of {len(results)} episode(s)/campaign(s) errored and "
            f"were not scored. The rates above cover only the {scored} scored run(s); see "
            "the error rows in the results file.",
            file=sys.stderr,
        )
        if strict:
            sys.exit(EXIT_ERRORS_STRICT)


def main() -> None:
    # `tripwire init ...` writes a starter config; anything else is a run.
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        _init_command(sys.argv[2:])
        return

    parser = argparse.ArgumentParser(
        prog="tripwire",
        description="Run a prompt-injection eval sweep against an agent.",
        epilog="Tip: run `tripwire init` first to create a starter config. "
               "Exit codes: 0 ok, 1 config/setup error, 2 nothing scored, "
               "3 errored episodes under --strict.",
    )
    parser.add_argument("--config", required=True, help="Path to threat_model.yaml (see `tripwire init`)")
    parser.add_argument("--output", default="results/results.json", help="Output JSON path")
    parser.add_argument("--smoke", action="store_true", help="Tiny run: 1 seed, first model/scenario/attack/defense")
    parser.add_argument("--concurrency", type=int, default=None,
                        help="Parallel cells (adapter x model x scenario x attack x defense). "
                             "Overrides limits.max_concurrency. The sweep is I/O-bound on the "
                             "provider, so >1 cuts wall-clock roughly in proportion.")
    parser.add_argument(
        "--agent",
        metavar="PATH",
        help="Path to a Python file exposing your own agent as an Adapter "
             "(`adapter = ...` or `def run(spec): ...`) -- runs the attack "
             "suite against it instead of the configured adapters",
    )
    parser.add_argument(
        "--details", action="store_true",
        help="add the utility and tokens columns to the tables (always in the results file)",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help=f"exit {EXIT_ERRORS_STRICT} if any episode errored (default: warn and exit 0)",
    )
    parser.add_argument(
        "--preflight", action="store_true",
        help="before the sweep, make one cheap call per configured model and stop "
             "if the provider rejects it (catches a model/provider mismatch)",
    )
    replay_flags = parser.add_mutually_exclusive_group()
    replay_flags.add_argument("--save-replay-library", metavar="PATH",
                              help="Save successful adaptive payloads for held-out replay")
    replay_flags.add_argument("--replay-library", metavar="PATH",
                              help="Run frozen payloads on held-out config seeds without an attacker LLM")
    args = parser.parse_args()

    _load_env_file()

    # Checked before load_config(): it resolves adapters eagerly, and adapters
    # need a provider key to construct their client (see harness.llm).
    if not has_provider_key():
        print("Error: set one of " + ", ".join(provider_key_names()) +
              " in environment or .env", file=sys.stderr)
        sys.exit(EXIT_CONFIG_ERROR)

    # Config loading, agent loading, and attack resolution raise ValueError
    # (or FileNotFoundError) with actionable messages for the mistakes a new
    # user makes -- a bad config key, an unknown adapter/attack name, a missing
    # --agent file. TypeError/AttributeError cover a config value of a shape
    # nothing validated. Turn all of them into a clean one-line error.
    try:
        config = load_config(args.config)

        if args.smoke:
            config.smoke = True

        # Apply smoke overrides (after load_config validated every name).
        if config.smoke:
            config.seeds = [config.seeds[0]] if config.seeds else [0]
            config.models = config.models[:1]
            config.attacks = config.attacks[:1]
            config.defenses = config.defenses[:1]
            config.scenarios = config.scenarios[:1]

        # --agent replaces the configured adapters entirely -- same environment,
        # attacks, defenses, and judge, just a different tool loop under test.
        adapters = [load_agent_module(args.agent)] if args.agent else config.adapters
        attacks = [] if args.replay_library else resolve_attacks(config.attacks)
        from tripwire.attacks.replay import load_library, validate_replay
        replay_cases = None
        if args.replay_library:
            bases = {s.name.split("/", 1)[0] for s in config.scenarios}
            replay_cases = [c for c in load_library(args.replay_library)
                            if c.scenario.split("/", 1)[0] in bases]
            if not replay_cases:
                raise ValueError("Replay library has no cases for the configured scenarios")
            if config.smoke:
                replay_cases = replay_cases[:1]
            validate_replay(replay_cases, config.seeds)
        for library_path in (args.replay_library, args.save_replay_library):
            if library_path and os.path.realpath(library_path) == os.path.realpath(args.output):
                raise ValueError("Replay library and results output must use different paths")
    except (ValueError, FileNotFoundError, TypeError, AttributeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(EXIT_CONFIG_ERROR)

    for warning in config.warnings:
        print(f"Warning: {warning}", file=sys.stderr)

    print(f"Target model(s): {', '.join(config.models)}")
    print(f"Provider: {_provider_label()}")
    if args.preflight:
        _preflight(config)

    if replay_cases is None:
        print(f"Running sweep: {len(adapters)} adapter(s) x {len(config.models)} model(s) "
              f"x {len(config.scenarios)} scenario(s) x {len(attacks)} attack(s) "
              f"x {len(config.defenses)} defense(s) x {len(config.seeds)} seed(s), "
              f"max {config.max_turns} turn(s) per episode")
    else:
        print(f"Running replay: {len(replay_cases)} payload/profile pair(s) x "
              f"{len(adapters)} adapter(s) x {len(config.models)} model(s) x "
              f"{len(config.defenses)} defense(s) x {len(config.seeds)} held-out seed(s), "
              f"max {config.max_turns} turn(s) per episode")

    concurrency = args.concurrency if args.concurrency is not None else config.max_concurrency
    if concurrency > 1:
        print(f"Concurrency: {concurrency} cells in parallel")
    if replay_cases is not None:
        from tripwire.attacks.replay import run_replay_sweep
        print(f"Replaying {len(replay_cases)} frozen payload(s) with their discovery profiles")
        episodes, campaigns = run_replay_sweep(
            adapters, config.models, replay_cases, config.seeds, config.defenses,
            max_turns=config.max_turns, concurrency=concurrency, max_tokens=config.max_tokens_per_run,
        )
    else:
        episodes, campaigns = run_sweep(
            adapters, config.models, attacks, config.seeds, config.campaign_budget,
            config.defenses, config.scenarios, max_turns=config.max_turns,
            concurrency=concurrency, max_tokens=config.max_tokens_per_run,
        )

    # Ensure output directory exists
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    write_results(episodes, args.output, campaigns)
    print(f"\nResults written to {args.output}")
    if args.save_replay_library:
        from tripwire.attacks.replay import save_library
        try:
            count = save_library(campaigns, args.save_replay_library)
        except (ValueError, OSError) as exc:
            print(f"Error saving replay library: {exc}", file=sys.stderr)
            sys.exit(EXIT_CONFIG_ERROR)
        print(f"Saved {count} successful discovery payload(s) to {args.save_replay_library}")

    if any(_is_scored(r) for r in [*episodes, *campaigns]):
        if episodes:
            print()
            print_asr_table(episodes, details=args.details)
        if campaigns:
            print()
            print_campaign_table(campaigns, details=args.details)
        print()
        print_security_report(episodes, campaigns)

    _report_outcome(episodes, campaigns, args.strict)


if __name__ == "__main__":
    main()
