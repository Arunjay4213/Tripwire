"""Config loader — parse threat_model.yaml into a typed dataclass."""

from __future__ import annotations

from dataclasses import dataclass

import yaml

from src.adapters.base import Adapter
from src.adapters.loader import resolve_adapters
from src.attacks.agentdojo_wrappers import (
    DirectAttack,
    IgnorePreviousAttack,
    ImportantInstructionsAttack,
    InjecAgentAttack,
    SystemMessageAttack,
)
from src.attacks.base import Attack
from src.attacks.fixed_injection import FixedInjection
from src.attacks.iterative import IterativeAttacker

# Registry of known attack names -> classes. Each is instantiated with cls()
# (no args), so every attack class must construct with no required arguments.
_ATTACK_REGISTRY: dict[str, type] = {
    "fixed_injection": FixedInjection,
    "direct": DirectAttack,
    "ignore_previous": IgnorePreviousAttack,
    "system_message": SystemMessageAttack,
    "injecagent": InjecAgentAttack,
    "important_instructions": ImportantInstructionsAttack,
    "iterative": IterativeAttacker,
}


@dataclass
class TripwireConfig:
    models: list[str]
    suites: list[str]
    attacks: list[str]
    adapters: list[Adapter]
    defenses: list[str | None]
    seeds: list[int]
    max_tokens_per_run: int | None = None
    smoke: bool = False
    campaign_budget: int = 8


def load_config(path: str) -> TripwireConfig:
    """Read YAML config, validate required keys, return dataclass."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    limits = raw.get("limits", {}) or {}

    return TripwireConfig(
        models=raw["models"],
        suites=raw["suites"],
        attacks=raw["attacks"],
        adapters=resolve_adapters(raw["adapters"]),
        defenses=raw.get("defenses", [None]),
        seeds=raw["seeds"],
        max_tokens_per_run=limits.get("max_tokens_per_run"),
        smoke=limits.get("smoke", False),
        campaign_budget=limits.get("campaign_budget", 8),
    )


def resolve_attacks(names: list[str]) -> list[Attack]:
    """Map attack name strings to Attack instances. Raise on unknown."""
    attacks: list[Attack] = []
    for name in names:
        cls = _ATTACK_REGISTRY.get(name)
        if cls is None:
            known = ", ".join(sorted(_ATTACK_REGISTRY))
            raise ValueError(f"Unknown attack {name!r}. Known: {known}")
        attacks.append(cls())
    return attacks
