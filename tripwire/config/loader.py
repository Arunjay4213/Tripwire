"""Config loader — parse threat_model.yaml into a typed dataclass."""

from __future__ import annotations

import difflib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

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
    GuardInjection,
    MetadataExfil,
    MundaneRedirect,
    PrerequisiteMirror,
    PublicIdentifier,
    RelayActionItem,
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
    "guard_injection": GuardInjection,
    "relay_action_item": RelayActionItem,
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
    attacks: list[str]
    adapters: list[Adapter]
    defenses: list[Defense]
    seeds: list[int]
    scenarios: list[Scenario] = field(default_factory=lambda: [SCENARIOS["invoice"]])
    # The user's extra tool_filter allowlist exactly as written in the config.
    # The ToolFilter itself also allows every configured scenario's read tool.
    allowed_tools: list[str] = field(default_factory=list)
    # outbound_guard: block the call when the detector errors (True, the
    # default) or let it through (False). Either way the runner records a
    # run whose guard errored as an error outcome, not as defended.
    guard_fail_closed: bool = True
    max_tokens_per_run: int | None = None
    smoke: bool = False
    campaign_budget: int = 8
    # Shared per-episode model-call budget (EpisodeSpec.max_turns).
    max_turns: int = 5
    max_concurrency: int = 1
    # Non-fatal problems found while validating the config. The CLI prints them
    # before the sweep; they never change what runs.
    warnings: list[str] = field(default_factory=list)


# Keys the config must define. Validated up front so a typo or omission yields a
# clear message instead of a bare KeyError deep in construction.
_REQUIRED_KEYS = ("models", "attacks", "adapters", "seeds")

# Every key load_config understands. Anything else is rejected: a misspelled
# `defense:` would otherwise be dropped silently and the run would measure the
# undefended baseline while the user reads it as "spotlighting results".
_TOP_LEVEL_KEYS = frozenset(
    {*_REQUIRED_KEYS, "scenarios", "defenses", "allowed_tools", "outbound_guard", "limits"}
)
_OUTBOUND_GUARD_KEYS = frozenset({"fail_closed"})
_LIMITS_KEYS = frozenset(
    {"max_tokens_per_run", "smoke", "campaign_budget", "max_turns", "max_concurrency"}
)

# The leak-capable tool every scenario offers (scenarios._tool_schemas). The
# tool_filter defense exists to take it away.
_SINK_TOOL = "send_email"

# make_canary() packs the seed into 8 bytes, so seeds must fit a signed int64.
_MAX_SEED = 2**63


def _did_you_mean(name: object, known: Iterable[str]) -> str:
    """' Did you mean 'x'?' for the closest known name, or '' if none is close."""
    if not isinstance(name, str):
        return ""
    matches = difflib.get_close_matches(name, list(known), n=1)
    return f" Did you mean {matches[0]!r}?" if matches else ""


def _unknown_name_error(kind: str, name: object, known: Iterable[str]) -> ValueError:
    known = sorted(known)
    return ValueError(
        f"Unknown {kind} {name!r}.{_did_you_mean(name, known)} Known: {', '.join(known)}"
    )


def _check_keys(raw: dict[str, Any], allowed: frozenset[str], where: str, path: str) -> None:
    for key in raw:
        if key not in allowed:
            raise ValueError(
                f"Unknown {where} key {key!r} (in {path}).{_did_you_mean(key, allowed)} "
                f"Allowed: {', '.join(sorted(allowed))}"
            )


def _require_str_list(value: Any, key: str, path: str, *, allow_null_items: bool = False) -> list:
    """A non-empty list whose items are strings (or None, if allowed)."""
    if not isinstance(value, list) or not value:
        raise ValueError(
            f"Config key {key!r} must be a non-empty list (in {path}); e.g. `{key}: [ ... ]`"
        )
    for item in value:
        if item is None and allow_null_items:
            continue
        if not isinstance(item, str):
            raise ValueError(
                f"Config key {key!r} must list names as strings, got {item!r} "
                f"({type(item).__name__}) (in {path})"
            )
    return value


def _require_seeds(value: Any, path: str) -> list[int]:
    if not isinstance(value, list) or not value:
        raise ValueError(
            f"Config key 'seeds' must be a non-empty list (in {path}); e.g. `seeds: [0, 1, 2]`"
        )
    for seed in value:
        # bool is a subclass of int; `seeds: [true]` is a mistake, not seed 1.
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < _MAX_SEED:
            raise ValueError(
                f"Config key 'seeds' must contain non-negative integers, got {seed!r} (in {path})"
            )
    if len(set(value)) != len(value):
        # A duplicate seed replays the identical canary and environment, so it
        # would be counted as an independent trial and shrink the CI falsely.
        raise ValueError(f"Config key 'seeds' contains duplicates: {value!r} (in {path})")
    return value


def _require_int(value: Any, key: str, path: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(
            f"limits.{key} must be an integer >= {minimum}, got {value!r} (in {path})"
        )
    return value


def _parse_limits(raw: dict[str, Any], path: str) -> dict[str, Any]:
    limits = raw.get("limits")
    if limits is None:
        limits = {}
    if not isinstance(limits, dict):
        raise ValueError(
            f"Config key 'limits' must be a mapping of limit names to values, "
            f"got {type(limits).__name__} (in {path}); e.g. `limits: {{max_turns: 5}}`"
        )
    _check_keys(limits, _LIMITS_KEYS, "limits", path)

    smoke = limits.get("smoke", False)
    if not isinstance(smoke, bool):
        # YAML `smoke: "false"` is a truthy string and would turn smoke mode on.
        raise ValueError(f"limits.smoke must be true or false, got {smoke!r} (in {path})")

    max_tokens = limits.get("max_tokens_per_run")
    if max_tokens is not None:
        _require_int(max_tokens, "max_tokens_per_run", path, minimum=1)

    return {
        "smoke": smoke,
        "max_tokens_per_run": max_tokens,
        "campaign_budget": _require_int(
            limits.get("campaign_budget", 8), "campaign_budget", path, minimum=1
        ),
        "max_turns": _require_int(limits.get("max_turns", 5), "max_turns", path, minimum=1),
        "max_concurrency": _require_int(
            limits.get("max_concurrency", 1), "max_concurrency", path, minimum=1
        ),
    }


def known_tool_names() -> frozenset[str]:
    """Every tool name a Tripwire scenario can offer: the sink plus each read tool."""
    return frozenset({_SINK_TOOL, *(s.read_tool for s in SCENARIOS.values())})


def _parse_outbound_guard(raw: dict[str, Any], path: str) -> bool:
    """`outbound_guard: {fail_closed: bool}`; absent or null means fail-closed."""
    opts = raw.get("outbound_guard")
    if opts is None:
        return True
    if not isinstance(opts, dict):
        raise ValueError(
            f"outbound_guard must be a mapping such as {{fail_closed: false}}, got "
            f"{type(opts).__name__} (in {path})"
        )
    _check_keys(opts, _OUTBOUND_GUARD_KEYS, "outbound_guard", path)
    fail_closed = opts.get("fail_closed", True)
    if not isinstance(fail_closed, bool):
        raise ValueError(
            f"outbound_guard.fail_closed must be true or false, got {fail_closed!r} (in {path})"
        )
    return fail_closed


def _allowed_tools_warnings(
    allowed_tools: list[str], defense_names: list[str | None], scenarios: list[Scenario]
) -> list[str]:
    """Non-fatal problems with how tool_filter is configured."""
    if "tool_filter" not in defense_names:
        if allowed_tools:
            return ["allowed_tools is set but the tool_filter defense is not in `defenses`, "
                    "so it has no effect."]
        return []
    warnings: list[str] = []
    if allowed_tools:
        # An explicit list that misses a scenario's read tool would, on its own,
        # hide the injected content from the agent in that scenario, so the row
        # would show 0% ASR without the defense doing anything. tool_filter keeps
        # the read tool regardless; say so, so the list is not misread.
        for scenario in scenarios:
            if scenario.read_tool not in allowed_tools:
                warnings.append(
                    f"allowed_tools does not list {scenario.read_tool!r}, the read tool of "
                    f"scenario {scenario.name!r}; tool_filter keeps it anyway so the agent "
                    f"can still read the task (and the injection)."
                )
    if _SINK_TOOL in allowed_tools:
        warnings.append(
            f"allowed_tools includes {_SINK_TOOL!r}, the leak-capable tool, so tool_filter "
            f"removes nothing that can leak and will measure like no defense."
        )
    return warnings


def load_config(path: str) -> TripwireConfig:
    """Read YAML config, validate every key, return dataclass.

    Raises ValueError with an actionable message (which the CLI turns into a
    clean error, not a traceback) for the mistakes a new user actually makes:
    a missing file, an empty/comment-only file, a non-mapping top level, a
    missing or misspelled key, a value of the wrong type, or an unknown
    adapter/attack/defense/scenario/tool name.
    """
    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except FileNotFoundError:
        raise ValueError(f"Config file not found: {path} (run `tripwire init` to create one)")

    if raw is None:
        raise ValueError(f"Config file is empty (or only comments): {path}")
    if not isinstance(raw, dict):
        raise ValueError(
            f"Config file must be a YAML mapping of keys to values, got {type(raw).__name__}: {path}"
        )

    _check_keys(raw, _TOP_LEVEL_KEYS, "top-level", path)
    for key in _REQUIRED_KEYS:
        if key not in raw:
            raise ValueError(f"Config missing required key: {key!r} (in {path})")

    models = _require_str_list(raw["models"], "models", path)
    attacks = _require_str_list(raw["attacks"], "attacks", path)
    adapter_names = _require_str_list(raw["adapters"], "adapters", path)
    seeds = _require_seeds(raw["seeds"], path)
    scenario_names = _require_str_list(raw.get("scenarios", ["invoice"]), "scenarios", path)
    defense_names = _require_str_list(
        raw.get("defenses", [None]), "defenses", path, allow_null_items=True
    )
    allowed_tools: list[str] = []
    if "allowed_tools" in raw:
        allowed_tools = _require_str_list(raw["allowed_tools"], "allowed_tools", path)
        known_tools = known_tool_names()
        for tool in allowed_tools:
            if tool not in known_tools:
                raise _unknown_name_error("tool in allowed_tools", tool, known_tools)
    limits = _parse_limits(raw, path)
    guard_fail_closed = _parse_outbound_guard(raw, path)

    # Resolve attack names here (not after --smoke truncation in the CLI) so a
    # typo in the 2nd attack fails a smoke run too.
    for name in attacks:
        if name not in _ATTACK_REGISTRY:
            raise _unknown_name_error("attack", name, _ATTACK_REGISTRY)

    scenarios = resolve_scenarios(scenario_names)
    warnings = _allowed_tools_warnings(allowed_tools, defense_names, scenarios)
    if limits["max_tokens_per_run"] is not None:
        warnings.append("limits.max_tokens_per_run is not enforced yet; it does not cap spend.")

    return TripwireConfig(
        models=models,
        attacks=attacks,
        adapters=resolve_adapters(adapter_names),
        defenses=resolve_defenses(defense_names, allowed_tools, scenarios,
                                  guard_fail_closed=guard_fail_closed),
        seeds=seeds,
        scenarios=scenarios,
        allowed_tools=allowed_tools,
        guard_fail_closed=guard_fail_closed,
        max_tokens_per_run=limits["max_tokens_per_run"],
        smoke=limits["smoke"],
        campaign_budget=limits["campaign_budget"],
        max_turns=limits["max_turns"],
        max_concurrency=limits["max_concurrency"],
        warnings=warnings,
    )


def resolve_attacks(names: list[str]) -> list[Attack]:
    """Map attack name strings to Attack instances. Raise on unknown."""
    attacks: list[Attack] = []
    for name in names:
        cls = _ATTACK_REGISTRY.get(name)
        if cls is None:
            raise _unknown_name_error("attack", name, _ATTACK_REGISTRY)
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
            raise _unknown_name_error("scenario", name, SCENARIOS)
        scenarios.append(s)
    return scenarios


def resolve_defenses(
    names: list[str | None],
    allowed_tools: Sequence[str],
    scenarios: Sequence[Scenario] | None = None,
    guard_fail_closed: bool = True,
) -> list[Defense]:
    """Map defense name strings to Defense instances. Raise on unknown.

    The ladder, cheap-weak -> expensive-strong (see threat_model.example.yaml):
      - `null` -> NoDefense() (baseline)
      - `prompt_hardening` -> L1, appends a distrust-tool-content instruction
      - `spotlighting` -> L2, fences untrusted tool output (Microsoft)
      - `tool_filter` -> removes every tool not on its allowlist from the
        offered menu and blocks it at execution time
      - `outbound_guard` -> L3, a second-model checker gates send_email

    tool_filter is scenario-relative when `scenarios` is given (load_config
    always gives it): the allowlist is every scenario's read tool plus
    `allowed_tools`, so the agent can always read its task and the defense only
    takes away the sink (send_email). Without `scenarios` (direct callers such
    as the experiment scripts) the allowlist is exactly `allowed_tools`, which
    must then be non-empty. Either way ToolFilter gets a frozenset, so a stray
    string can never turn membership into a substring test.

    A `None` entry resolves to `NoDefense()` -- useful for sweeping "no defense"
    alongside real ones in the same run.
    """
    if isinstance(allowed_tools, str):
        raise ValueError(
            f"allowed_tools must be a list of tool names, got the string {allowed_tools!r}"
        )
    defenses: list[Defense] = []
    for name in names:
        if name is None:
            defenses.append(NoDefense())
        elif name == "tool_filter":
            allowed = frozenset(allowed_tools)
            if scenarios is not None:
                allowed |= {s.read_tool for s in scenarios}
            if not allowed:
                raise ValueError(
                    "tool_filter defense requires a non-empty 'allowed_tools' list in config"
                )
            # ToolFilter only does `name in self.allowed_tools`, so a frozenset
            # works unchanged and cannot degrade to a substring match.
            defenses.append(ToolFilter(allowed))  # type: ignore[arg-type]
        elif name == "outbound_guard":
            defenses.append(OutboundGuard(fail_closed=guard_fail_closed))
        elif name in _DEFENSE_REGISTRY:
            defenses.append(_DEFENSE_REGISTRY[name]())
        else:
            raise _unknown_name_error(
                "defense", name, ["tool_filter", *_DEFENSE_REGISTRY, "null (no defense)"]
            )
    return defenses
