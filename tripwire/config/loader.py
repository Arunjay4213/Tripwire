"""Config loader — parse threat_model.yaml into a typed dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from tripwire.adapters.base import Adapter
from tripwire.adapters.loader import resolve_adapters
from tripwire.attacks.agentdojo_wrappers import (
    DirectAttack,
    IgnorePreviousAttack,
    ImportantInstructionsAttack,
    InjecAgentAttack,
    SystemMessageAttack,
)
from tripwire.attacks.base import Attack
from tripwire.attacks.fixed_injection import (
    FixedInjection,
    ForgedBoundary,
    MetadataExfil,
    MundaneRedirect,
    PrerequisiteMirror,
    PublicIdentifier,
)
from tripwire.attacks.iterative import IterativeAttacker
from tripwire.attacks.tree_attacker import TreeAttacker
from tripwire.defenses.base import Defense, NoDefense
from tripwire.defenses.outbound_guard import OutboundGuard
from tripwire.defenses.prompt_hardening import PromptHardening
from tripwire.defenses.spotlighting import Spotlighting
from tripwire.defenses.tool_filter import ToolFilter
from tripwire.scenarios import SCENARIOS, Scenario

# Registry of zero-argument defenses: name -> class, instantiated with cls().
# tool_filter (needs allowed_tools) is handled separately in resolve_defenses.
_DEFENSE_REGISTRY: dict[str, type] = {
    "prompt_hardening": PromptHardening,
    "spotlighting": Spotlighting,
    "outbound_guard": OutboundGuard,
}

# Registry of known attack names -> classes. Each is instantiated with cls()
# (no args), so every attack class must construct with no required arguments.
_ATTACK_REGISTRY: dict[str, type] = {
    "fixed_injection": FixedInjection,
    "metadata_exfil": MetadataExfil,
    "public_identifier": PublicIdentifier,
    "forged_boundary": ForgedBoundary,
    "prerequisite_mirror": PrerequisiteMirror,
    "mundane_redirect": MundaneRedirect,
    "direct": DirectAttack,
    "ignore_previous": IgnorePreviousAttack,
    "system_message": SystemMessageAttack,
    "injecagent": InjecAgentAttack,
    "important_instructions": ImportantInstructionsAttack,
    "iterative": IterativeAttacker,
    "tree_attacker": TreeAttacker,
}


@dataclass
class TripwireConfig:
    models: list[str]
    suites: list[str]
    attacks: list[str]
    adapters: list[Adapter]
    defenses: list[Defense]
    seeds: list[int]
    scenarios: list[Scenario] = field(default_factory=lambda: [SCENARIOS["invoice"]])
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
        scenarios=resolve_scenarios(raw.get("scenarios", ["invoice"])),
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


def resolve_scenarios(names: list[str]) -> list[Scenario]:
    """Map scenario name strings to Scenario instances. Raise on unknown.

    Scenarios (tripwire/scenarios.py) are the tasks the agent is attacked on --
    invoice (default), helpdesk, calendar, expense. A sweep runs every attack
    against every listed scenario, so the agent is tested on varied tasks, each
    with its own authorized recipient.
    """
    scenarios: list[Scenario] = []
    for name in names:
        s = SCENARIOS.get(name)
        if s is None:
            known = ", ".join(sorted(SCENARIOS))
            raise ValueError(f"Unknown scenario {name!r}. Known: {known}")
        scenarios.append(s)
    return scenarios


def resolve_defenses(names: list[str | None], allowed_tools: list[str]) -> list[Defense]:
    """Map defense name strings to Defense instances. Raise on unknown.

    The ladder, cheap-weak -> expensive-strong (see threat_model.example.yaml):
      - `null` -> NoDefense() (baseline)
      - `prompt_hardening` -> L1, appends a distrust-tool-content instruction
      - `spotlighting` -> L2, fences untrusted tool output (Microsoft)
      - `tool_filter` -> restricts the offered/runnable tool menu to
        `allowed_tools`, which must be non-empty
      - `outbound_guard` -> L3, a second-model checker gates send_email

    A `None` entry resolves to `NoDefense()` -- useful for sweeping "no defense"
    alongside real ones in the same run.
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
        elif name in _DEFENSE_REGISTRY:
            defenses.append(_DEFENSE_REGISTRY[name]())
        else:
            known = ", ".join(["tool_filter", *sorted(_DEFENSE_REGISTRY), "null (no defense)"])
            raise ValueError(f"Unknown defense {name!r}. Known: {known}")
    return defenses
