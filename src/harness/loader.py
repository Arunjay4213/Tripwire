"""Config loader — parse threat_model.yaml into a typed config and resolve
defense name strings (e.g. "tool_filter") to Defense instances.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from src.defenses.base import Defense, NoDefense
from src.defenses.tool_filter import ToolFilter


@dataclass
class TripwireConfig:
    models: list[str]
    suites: list[str]
    attacks: list[str]
    defenses: list[str | None]
    seeds: list[int]
    allowed_tools: list[str] = field(default_factory=list)
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
        allowed_tools=raw.get("allowed_tools", []),
        max_tokens_per_run=limits.get("max_tokens_per_run"),
        smoke=limits.get("smoke", False),
    )


def resolve_defenses(config: TripwireConfig) -> list[Defense]:
    """Map config.defenses name strings to instantiated Defense objects.

    A `None` entry resolves to `NoDefense()`. `tool_filter` is instantiated
    with `config.allowed_tools`, which must be non-empty.
    """
    defenses: list[Defense] = []
    for name in config.defenses:
        if name is None:
            defenses.append(NoDefense())
        elif name == "tool_filter":
            if not config.allowed_tools:
                raise ValueError(
                    "tool_filter defense requires a non-empty 'allowed_tools' list in config"
                )
            defenses.append(ToolFilter(config.allowed_tools))
        else:
            raise ValueError(f"Unknown defense {name!r}. Known: tool_filter")
    return defenses
