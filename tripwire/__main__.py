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


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tripwire",
        description="Run prompt-injection eval sweep.",
    )
    parser.add_argument("--config", required=True, help="Path to threat_model.yaml")
    parser.add_argument("--output", default="results/results.json", help="Output JSON path")
    parser.add_argument("--smoke", action="store_true", help="Tiny run: 1 seed, first model/attack only")
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
