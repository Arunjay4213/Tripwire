"""Episode runner — loops an adapter over seeds, scores each episode.

P1 core (roadmap Weeks 2-3). Owns the CI action stub.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.adapters.base import Adapter, EpisodeSpec


@dataclass
class EpisodeResult:
    adapter: str
    model: str
    attack: str
    seed: int
    succeeded: bool


def run_episode(adapter: Adapter, spec: EpisodeSpec, attack_name: str) -> EpisodeResult:
    """Run one episode and score it.

    TODO Weeks 2-3: make canary, inject into env, adapter.run(spec),
    judge.attack_succeeded(trace, canary) -> EpisodeResult.
    """
    raise NotImplementedError


def run_sweep(*args, **kwargs) -> list[EpisodeResult]:
    """Loop adapters x models x attacks x seeds -> list[EpisodeResult]."""
    # TODO Weeks 2-3.
    raise NotImplementedError
