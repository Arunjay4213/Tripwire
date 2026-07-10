"""CLI entrypoint — python -m tripwire --config threat_model.yaml"""

from __future__ import annotations

import argparse
import os
import sys

from dotenv import load_dotenv
from openai import OpenAI

# Allow running as `python -m tripwire` from repo root (src/ is the package
# but imports use `from src.…`).  Ensure repo root is on sys.path.
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from src.config.loader import load_config, resolve_adapters, resolve_attacks
from src.harness.reporter import print_asr_table, print_campaign_table, write_results
from src.harness.runner import run_sweep


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tripwire",
        description="Run prompt-injection eval sweep.",
    )
    parser.add_argument("--config", required=True, help="Path to threat_model.yaml")
    parser.add_argument("--output", default="results/results.json", help="Output JSON path")
    parser.add_argument("--smoke", action="store_true", help="Tiny run: 1 seed, first model/attack only")
    args = parser.parse_args()

    load_dotenv()

    config = load_config(args.config)

    if args.smoke:
        config.smoke = True

    # Apply smoke overrides
    if config.smoke:
        config.seeds = [config.seeds[0]] if config.seeds else [0]
        config.models = config.models[:1]
        config.attacks = config.attacks[:1]

    api_key = os.environ.get("GROQ_API_KEY")
    base_url = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    if not api_key:
        print("Error: GROQ_API_KEY not set in environment or .env", file=sys.stderr)
        sys.exit(1)

    client = OpenAI(api_key=api_key, base_url=base_url)
    adapters = resolve_adapters(client)
    attacks = resolve_attacks(config.attacks)

    print(f"Running sweep: {len(adapters)} adapter(s) x {len(config.models)} model(s) "
          f"x {len(attacks)} attack(s) x {len(config.seeds)} seed(s)")

    episodes, campaigns = run_sweep(
        adapters, config.models, attacks, config.seeds, config.campaign_budget
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


if __name__ == "__main__":
    main()
