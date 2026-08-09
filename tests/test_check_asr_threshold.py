"""Tests for the CI ASR gate (scripts/ci/check_asr_threshold.py).

Pure Python on in-memory result payloads -- no network, no files, no sweep.
Loaded by path since scripts/ is not an importable package.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "check_asr_threshold.py"
_spec = importlib.util.spec_from_file_location("check_asr_threshold", _MODULE_PATH)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def _episodes(*flags, defense="no_defense", adapter="raw_loop"):
    return [
        {"adapter": adapter, "attack": "direct", "defense": defense, "succeeded": f}
        for f in flags
    ]


def test_pass_when_asr_below_threshold():
    payload = _episodes(True, False, False, False)  # 25% ASR
    passed, asr, n, leaks = gate.evaluate(payload, threshold=0.5)
    assert passed is True
    assert asr == 0.25
    assert (n, leaks) == (4, 1)


def test_fail_when_asr_above_threshold():
    payload = _episodes(True, True, True, False)  # 75% ASR
    passed, asr, _, _ = gate.evaluate(payload, threshold=0.5)
    assert passed is False
    assert asr == 0.75


def test_threshold_is_inclusive():
    payload = _episodes(True, False)  # exactly 50%
    passed, asr, _, _ = gate.evaluate(payload, threshold=0.5)
    assert passed is True and asr == 0.5


def test_empty_results_is_a_failure_not_a_pass():
    passed, asr, n, leaks = gate.evaluate([], threshold=0.9)
    assert passed is False
    assert (n, leaks) == (0, 0)


def test_defense_filter_scopes_the_gate():
    payload = _episodes(True, True, defense="no_defense") + _episodes(False, False, defense="outbound_guard")
    # Overall ASR is 50%, but the shipped defense leaks nothing.
    passed_overall, asr_overall, _, _ = gate.evaluate(payload, threshold=0.4)
    assert passed_overall is False and asr_overall == 0.5

    passed_defended, asr_defended, n, _ = gate.evaluate(payload, threshold=0.4, defense="outbound_guard")
    assert passed_defended is True and asr_defended == 0.0 and n == 2


def test_adapter_filter_scopes_the_gate():
    payload = _episodes(True, True, adapter="raw_loop") + _episodes(False, False, adapter="langgraph")
    passed, asr, n, _ = gate.evaluate(payload, threshold=0.1, adapter="langgraph")
    assert passed is True and asr == 0.0 and n == 2


def test_campaigns_count_as_scored_runs():
    payload = {
        "episodes": _episodes(False),
        "campaigns": [
            {"adapter": "raw_loop", "attack": "iterative", "defense": "no_defense", "broke": True},
            {"adapter": "raw_loop", "attack": "iterative", "defense": "no_defense", "broke": False},
        ],
    }
    # 1 episode (no leak) + 2 campaigns (1 broke) = 1 leak / 3 runs.
    passed, asr, n, leaks = gate.evaluate(payload, threshold=0.5)
    assert (n, leaks) == (3, 1)
    assert passed is True
    assert asr == pytest.approx(1 / 3)


def test_flat_list_and_object_payloads_both_parse():
    flat = _episodes(True, False)
    obj = {"episodes": _episodes(True, False), "campaigns": []}
    assert gate.evaluate(flat, 0.5)[1] == gate.evaluate(obj, 0.5)[1]
