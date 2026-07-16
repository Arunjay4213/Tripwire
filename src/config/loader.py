"""Config loader — parse threat_model.yaml into a typed dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field

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
from src.defenses.base import Defense, NoDefense
from src.defenses.tool_filter import ToolFilter

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
    defenses: list[Defense]
    seeds: list[int]
    allowed_tools: list[str] = field(default_factory=list)
    max_tokens_per_run: int | None = None
    smoke: bool = False
    campaign_budget: int = 8


def load_config(path: str) -> TripwireConfig:
    """Read YAML config, validate required keys, return dataclass."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    limits = raw.get("limits", {}) or {}
    allowed_tools = raw.get("allowed_tools", [])

    return TripwireConfig(
        models=raw["models"],
        suites=raw["suites"],
        attacks=raw["attacks"],
        adapters=resolve_adapters(raw["adapters"]),
        defenses=resolve_defenses(raw.get("defenses", [None]), allowed_tools),
        seeds=raw["seeds"],
        allowed_tools=allowed_tools,
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


def resolve_defenses(names: list[str | None], allowed_tools: list[str]) -> list[Defense]:
    """Map defense name strings to Defense instances. Raise on unknown.

    A `None` entry resolves to `NoDefense()` — useful for sweeping "no defense"
    alongside real ones in the same run. `tool_filter` is instantiated with
    `allowed_tools`, which must be non-empty.
    """
    defenses: list[Defense] = []
    for name in names:
        if name is None:
            defenses.append(NoDefense())
        elif name == "tool_filter":
            if not allowed_tools:
                raise ValueError(
                    "tool_filter defense requires a non-empty 'allowed_tools' list in config"
                )
            defenses.append(ToolFilter(allowed_tools))
        else:
            raise ValueError(f"Unknown defense {name!r}. Known: tool_filter, null (no defense)")
    return defenses
