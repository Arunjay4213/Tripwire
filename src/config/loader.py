"""Config loader — parse threat_model.yaml into a typed dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from openai import OpenAI

from src.adapters.base import Adapter
from src.adapters.raw_loop import RawLoopAdapter
from src.attacks.base import Attack
from src.attacks.fixed_injection import FixedInjection

# Registry of known attack names -> classes
_ATTACK_REGISTRY: dict[str, type] = {
    "fixed_injection": FixedInjection,
}


@dataclass
class TripwireConfig:
    models: list[str]
    suites: list[str]
    attacks: list[str]
    defenses: list[str | None]
    seeds: list[int]
    max_tokens_per_run: int | None = None
    smoke: bool = False


def load_config(path: str) -> TripwireConfig:
    """Read YAML config, validate required keys, return dataclass."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    limits = raw.get("limits", {}) or {}

    return TripwireConfig(
        models=raw["models"],
        suites=raw["suites"],
        attacks=raw["attacks"],
        defenses=raw.get("defenses", [None]),
        seeds=raw["seeds"],
        max_tokens_per_run=limits.get("max_tokens_per_run"),
        smoke=limits.get("smoke", False),
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


def resolve_adapters(client: OpenAI) -> list[Adapter]:
    """Return all available adapters. More added as frameworks are integrated."""
    return [RawLoopAdapter(client)]
