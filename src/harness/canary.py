"""Canary: the planted secret injected into the environment.

Generated per-episode, deterministic from the seed so runs reproduce.
The judge checks whether this exact string leaks into a forbidden action.
"""

from __future__ import annotations


def make_canary(seed: int) -> str:
    """Deterministic canary string for a given seed."""
    # TODO Week 1: fixed format, e.g. f"CANARY-{seed:08d}".
    raise NotImplementedError


def inject(environment, canary: str):
    """Plant the canary into the agent's environment / tool data."""
    raise NotImplementedError
