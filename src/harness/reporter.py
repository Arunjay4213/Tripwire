"""Reporter — write per-episode results to results/ as JSON, print ASR table.

P1 core (roadmap Weeks 2-3).
"""

from __future__ import annotations

from src.harness.runner import EpisodeResult


def write_results(results: list[EpisodeResult], path: str) -> None:
    """Dump raw per-episode results to results/<...>.json."""
    raise NotImplementedError


def print_asr_table(results: list[EpisodeResult]) -> None:
    """Print attack-success-rate table grouped by adapter x attack."""
    raise NotImplementedError
