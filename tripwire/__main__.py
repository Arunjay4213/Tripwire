"""CLI entrypoint — python -m tripwire --config threat_model.yaml"""

from __future__ import annotations

import argparse
import os
import sys

from dotenv import load_dotenv

# Allow running as `python -m tripwire` from repo root (tripwire/ is the package
# but imports use `from tripwire.…`).  Ensure repo root is on sys.path.
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from tripwire.adapters.loader import load_agent_module
from tripwire.config.loader import load_config, resolve_attacks
from tripwire.harness.reporter import (
    print_asr_table,
    print_campaign_table,
    print_security_report,
    write_results,
)
from tripwire.harness.runner import run_sweep

# A ready-to-run starter config written by `tripwire init` -- so a fresh
# `pip install` has something to point --config at without cloning the repo.
STARTER_CONFIG = """\
# Tripwire config -- created by `tripwire init`. Edit, then run:
#   tripwire --config threat_model.yaml --smoke                 # quick check
#   tripwire --config threat_model.yaml                         # full run
#   tripwire --config threat_model.yaml --agent my_agent.py     # your own agent

# The model under test. Any OpenAI-compatible endpoint: set OPENAI_API_KEY (and
# OPENAI_BASE_URL for Anthropic/Groq). Examples: gpt-4o-mini, claude-haiku-4-5.
models:
  - gpt-4o-mini

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

# Defenses to measure, cheap-weak to expensive-strong. `null` = no defense.
defenses:
  - null
  - prompt_hardening
  - spotlighting

# Seeds = independent trials (the model still samples at temperature). More
# seeds -> tighter confidence intervals. 3 is a quick look; 15+ for real numbers.
seeds: [0, 1, 2]
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
        f"  export OPENAI_API_KEY=...                 # any OpenAI-compatible endpoint\n"
        f"  tripwire --config {args.path} --smoke     # quick check\n"
        f"  tripwire --config {args.path} --agent path/to/your_agent.py"
    )


def main() -> None:
    # `tripwire init ...` writes a starter config; anything else is a run.
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        _init_command(sys.argv[2:])
        return

    parser = argparse.ArgumentParser(
        prog="tripwire",
        description="Run a prompt-injection eval sweep against an agent.",
        epilog="Tip: run `tripwire init` first to create a starter config.",
    )
    parser.add_argument("--config", required=True, help="Path to threat_model.yaml (see `tripwire init`)")
    parser.add_argument("--output", default="results/results.json", help="Output JSON path")
    parser.add_argument("--smoke", action="store_true", help="Tiny run: 1 seed, first model/scenario/attack/defense")
    parser.add_argument(
        "--agent",
        metavar="PATH",
        help="Path to a Python file exposing your own agent as an Adapter "
             "(`adapter = ...` or `def run(spec): ...`) -- runs the attack "
             "suite against it instead of the configured adapters",
    )
    args = parser.parse_args()

    load_dotenv()

    # Checked before load_config(): it resolves adapters eagerly, and adapters
    # need a provider key to construct their client (see harness.llm).
    if not (os.environ.get("OPENAI_API_KEY") or os.environ.get("GROQ_API_KEY")):
        print("Error: set OPENAI_API_KEY (OpenAI) or GROQ_API_KEY (Groq) in environment or .env",
              file=sys.stderr)
        sys.exit(1)

    # Config loading, agent loading, and attack resolution all raise ValueError
    # (or FileNotFoundError) with actionable messages for the mistakes a new
    # user makes -- a bad config key, an unknown adapter/attack name, a missing
    # --agent file. Turn those into a clean one-line error, not a traceback.
    try:
        config = load_config(args.config)

        if args.smoke:
            config.smoke = True

        # Apply smoke overrides
        if config.smoke:
            config.seeds = [config.seeds[0]] if config.seeds else [0]
            config.models = config.models[:1]
            config.attacks = config.attacks[:1]
            config.defenses = config.defenses[:1]
            config.scenarios = config.scenarios[:1]

        # --agent replaces the configured adapters entirely -- same environment,
        # attacks, defenses, and judge, just a different tool loop under test.
        adapters = [load_agent_module(args.agent)] if args.agent else config.adapters
        attacks = resolve_attacks(config.attacks)
    except (ValueError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Running sweep: {len(adapters)} adapter(s) x {len(config.models)} model(s) "
          f"x {len(config.scenarios)} scenario(s) x {len(attacks)} attack(s) "
          f"x {len(config.defenses)} defense(s) x {len(config.seeds)} seed(s)")

    episodes, campaigns = run_sweep(
        adapters, config.models, attacks, config.seeds, config.campaign_budget,
        config.defenses, config.scenarios,
    )

    # Ensure output directory exists
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    write_results(episodes, args.output, campaigns)
    print(f"\nResults written to {args.output}")

    if episodes:
        print()
        print_asr_table(episodes)
    if campaigns:
        print()
        print_campaign_table(campaigns)
    if episodes or campaigns:
        print()
        print_security_report(episodes, campaigns)


if __name__ == "__main__":
    main()
