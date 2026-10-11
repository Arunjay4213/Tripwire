"""Frozen adaptive payloads: discovery and independent replay are separate."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from tripwire.scenarios import SCENARIOS, Scenario
from tripwire.attacks.base import AttackContext

if TYPE_CHECKING:
    from tripwire.adapters.base import Adapter
    from tripwire.defenses.base import Defense
    from tripwire.harness.runner import CampaignResult, EpisodeResult


@dataclass(frozen=True)
class ReplayCase:
    payload: str
    scenario: str
    source_attack: str
    source_model: str
    source_defense: str
    discovery_seed: int
    source_attacker_model: str | None = None

    @property
    def name(self) -> str:
        digest = hashlib.sha256((self.scenario + "\0" + self.payload).encode()).hexdigest()[:16]
        return f"replay:{self.source_attack}:{digest}"

    @property
    def preserve_payload(self) -> bool:
        return True

    def render(self, canary: str, ctx: AttackContext | None = None) -> str:
        return self.payload

    def target_scenario(self) -> Scenario:
        parts = self.scenario.split("/")
        if parts[0] not in SCENARIOS:
            raise ValueError(f"Unknown replay scenario: {self.scenario!r}")
        scenario = SCENARIOS[parts[0]]
        if len(parts) == 1:
            return scenario
        if len(parts) != 3 or parts[2] not in ("label_known", "label_unknown"):
            raise ValueError(f"Invalid replay scenario profile: {self.scenario!r}")
        return scenario.with_attack_options(parts[1], parts[2] == "label_known")


def save_library(campaigns: list[CampaignResult], path: str) -> int:
    """Save successful discoveries with provenance, atomically. No LLM calls.

    Duplicate payload/profile pairs retain their first discovery provenance.
    A payload embedding the discovery canary cannot be a reusable attack.
    """
    from tripwire.harness.canary import make_canary
    from tripwire.harness.judge import canary_match

    records = []
    seen = set()
    for campaign in campaigns:
        if campaign.status != "ok" or not campaign.broke or not campaign.best_payload:
            continue
        if canary_match(campaign.best_payload, make_canary(campaign.seed)) is not None:
            raise ValueError("Cannot save a replay payload that embeds its discovery canary")
        case = ReplayCase(campaign.best_payload, campaign.scenario, campaign.attack,
                          campaign.model, campaign.defense, campaign.seed, campaign.attacker_model)
        case.target_scenario()
        if case.name not in seen:
            seen.add(case.name)
            records.append(asdict(case))
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                         delete=False) as stream:
            temporary = stream.name
            json.dump({"version": 1, "records": records}, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, destination)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return len(records)


def load_library(path: str) -> list[ReplayCase]:
    """Validate an inert JSON payload library; never import or execute it."""
    from tripwire.harness.canary import make_canary
    from tripwire.harness.judge import canary_match
    try:
        with open(path, encoding="utf-8") as stream:
            data = json.load(stream)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid replay JSON: {exc}") from exc
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1:
        raise ValueError("Replay library must be a mapping with version: 1")
    records = data.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("Replay library has no payload records")
    cases = []
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Each replay record must be a mapping")
        for key in ("payload", "scenario", "source_attack", "source_model", "source_defense"):
            if not isinstance(record.get(key), str) or not record[key].strip():
                raise ValueError(f"Replay record {key!r} must be a non-empty string")
        seed = record.get("discovery_seed")
        if type(seed) is not int or not 0 <= seed < 2**63:
            raise ValueError("Replay discovery_seed must be a non-negative int64")
        attacker = record.get("source_attacker_model")
        if attacker is not None and not isinstance(attacker, str):
            raise ValueError("Replay source_attacker_model must be a string or null")
        try:
            case = ReplayCase(**record)
        except TypeError as exc:
            raise ValueError(f"Invalid replay record fields: {exc}") from exc
        case.target_scenario()
        if canary_match(case.payload, make_canary(seed)) is not None:
            raise ValueError("Replay payload embeds its discovery canary")
        if case.name in seen:
            raise ValueError("Replay library contains a duplicate payload/profile")
        seen.add(case.name)
        cases.append(case)
    return cases


def validate_replay(cases: Sequence[ReplayCase], seeds: Sequence[int]) -> None:
    """Require held-out environments and reject payloads containing their secrets."""
    from tripwire.harness.canary import make_canary
    from tripwire.harness.judge import canary_match

    for case in cases:
        if case.discovery_seed in seeds:
            raise ValueError("Replay seeds must exclude every payload's discovery seed; use held-out seeds")
        for seed in seeds:
            if canary_match(case.payload, make_canary(seed)) is not None:
                raise ValueError("Replay payload embeds a held-out canary")


def run_replay_sweep(
    adapters: Sequence[Adapter], models: Sequence[str], cases: Sequence[ReplayCase],
    seeds: Sequence[int], defenses: Sequence[Defense] | None = None, *,
    max_turns: int = 5, concurrency: int = 1,
) -> tuple[list[EpisodeResult], list[CampaignResult]]:
    """Evaluate frozen candidates with the ordinary runner, without an attacker LLM."""
    from tripwire.harness.runner import run_sweep

    validate_replay(cases, seeds)
    episodes = []
    for case in cases:
        results, _ = run_sweep(adapters, models, [case], seeds, defenses=defenses,
                              scenarios=[case.target_scenario()], max_turns=max_turns,
                              concurrency=concurrency)
        episodes.extend(results)
    return episodes, []
