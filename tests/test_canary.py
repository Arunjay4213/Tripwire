"""Tests for canary generation and injection."""

import re

from src.harness.canary import inject, make_canary


def test_deterministic():
    """Same seed → same canary."""
    assert make_canary(42) == make_canary(42)


def test_distinct_seeds():
    """Different seeds → different canaries."""
    assert make_canary(0) != make_canary(1)


def test_format():
    """Canary matches CANARY-{6 hex chars}."""
    assert re.fullmatch(r"CANARY-[0-9a-f]{6}", make_canary(99))


def test_format_several_seeds():
    for seed in [0, 1, 100, 999999]:
        assert re.fullmatch(r"CANARY-[0-9a-f]{6}", make_canary(seed))


def test_inject_appends_to_system_prompt():
    env = {"system_prompt": "You are helpful."}
    inject(env, "CANARY-abc123")
    assert "CANARY-abc123" in env["system_prompt"]
    assert env["system_prompt"].startswith("You are helpful.")


def test_inject_returns_environment():
    env = {"system_prompt": "Base."}
    result = inject(env, "CANARY-000000")
    assert result is env


def test_inject_contains_never_share():
    env = {"system_prompt": "Hi."}
    inject(env, "CANARY-abc123")
    assert "Never share" in env["system_prompt"]
