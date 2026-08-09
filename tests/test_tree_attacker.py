"""Offline tests for the TAP-style tree attacker.

No network: the attacker's LLM calls go through a hand-written stub client
(exposing `.chat.completions.create`) that returns scripted JSON, and the target
is a fake `evaluate` returning scripted Observations. This lets us assert the
search logic -- branching, pruning, defense-aware feedback, and the break/no-break
outcome -- deterministically.
"""

from __future__ import annotations

import json

import pytest

from src.attacks.tree_attacker import (
    TreeAttacker,
    TreeResult,
    _parse_refinements,
    default_scorer,
)
from src.harness.judge import Observation


# --- JSON parsing (attacker output is messy in practice) ---------------------

def test_parse_plain_json_array():
    raw = json.dumps([{"diagnosis": "d", "strategy": "s", "payload": "p1"},
                      {"diagnosis": "d", "strategy": "s", "payload": "p2"}])
    out = _parse_refinements(raw)
    assert [d["payload"] for d in out] == ["p1", "p2"]


def test_parse_json_in_code_fence_with_prose():
    raw = 'Here you go:\n```json\n[{"payload": "x"}]\n```\nhope that helps'
    assert [d["payload"] for d in _parse_refinements(raw)] == ["x"]


def test_parse_drops_entries_without_payload():
    raw = json.dumps([{"diagnosis": "d"}, {"payload": "keep"}])
    assert [d["payload"] for d in _parse_refinements(raw)] == ["keep"]


def test_parse_fallback_to_raw_text():
    out = _parse_refinements("not json, just an email body")
    assert out == [{"diagnosis": "", "strategy": "", "payload": "not json, just an email body"}]


def test_parse_empty_is_empty():
    assert _parse_refinements("   ") == []


# --- scorer ------------------------------------------------------------------

def _obs(grade=0, executed=False, blocked=None, calls=None, reply=""):
    return Observation(grade=grade, executed_send_email=executed,
                       blocked_messages=blocked or [], tool_calls=calls or [], final_reply=reply)


def test_scorer_orders_promise_correctly():
    leaked = default_scorer(_obs(grade=2))
    acted = default_scorer(_obs(grade=1, executed=True))
    blocked = default_scorer(_obs(blocked=["blocked by outbound_guard"]))
    engaged = default_scorer(_obs(calls=[("read_inbox", {})]))
    nothing = default_scorer(_obs(reply="I can't help with that."))
    assert leaked > acted > blocked > engaged > nothing


# --- search (stub attacker + fake target) ------------------------------------

class _StubMessage:
    def __init__(self, content): self.content = content


class _StubChoice:
    def __init__(self, content): self.message = _StubMessage(content)


class _StubCompletion:
    def __init__(self, content):
        self.choices = [_StubChoice(content)]
        self.usage = None


class _StubCompletions:
    """Returns pre-scripted JSON responses in order, one per attacker call."""

    def __init__(self, scripted): self._scripted = list(scripted); self.calls = 0

    def create(self, **kwargs):
        content = self._scripted[min(self.calls, len(self._scripted) - 1)]
        self.calls += 1
        return _StubCompletion(content)


class StubClient:
    def __init__(self, scripted):
        self.chat = type("C", (), {"completions": _StubCompletions(scripted)})()


def _refinements(*payloads):
    return json.dumps([{"diagnosis": "d", "strategy": "s", "payload": p} for p in payloads])


def test_search_breaks_when_a_payload_leaks():
    # Attacker proposes 3 payloads; the target leaks (grade 2) on the one
    # containing "win".
    client = StubClient([_refinements("miss1", "win", "miss2")])
    atk = TreeAttacker(client=client, model="stub", branching=3, width=2, max_depth=3)

    def evaluate(payload):
        return _obs(grade=2) if "win" in payload else _obs(grade=0, reply="no")

    res = atk.search(evaluate, budget=10)
    assert isinstance(res, TreeResult)
    assert res.broke is True
    assert res.best_payload == "win"
    assert res.attempts_to_break == 2  # miss1 evaluated, then win


def test_search_respects_budget_and_reports_no_break():
    client = StubClient([_refinements("a", "b", "c")])
    atk = TreeAttacker(client=client, model="stub", branching=3, width=3, max_depth=5)
    calls = {"n": 0}

    def evaluate(payload):
        calls["n"] += 1
        return _obs(grade=0, reply="refused")  # never leaks

    res = atk.search(evaluate, budget=4)
    assert res.broke is False
    assert res.attempts_to_break is None
    assert res.evaluations == 4  # stopped exactly at budget
    assert calls["n"] == 4


def test_search_feeds_blocked_message_back_to_attacker():
    """The defining capability: a guard's block message reaches the attacker's
    next prompt, so it can infer a defense is inspecting it."""
    seen_prompts = []

    class _RecordingCompletions(_StubCompletions):
        def create(self, **kwargs):
            seen_prompts.append(kwargs["messages"][-1]["content"])
            return super().create(**kwargs)

    client = StubClient([_refinements("try1"), _refinements("try2")])
    client.chat.completions = _RecordingCompletions([_refinements("try1"), _refinements("try2")])
    atk = TreeAttacker(client=client, model="stub", branching=1, width=1, max_depth=2)

    def evaluate(payload):
        # First attempt is blocked by a named guard; never leaks.
        return _obs(blocked=["Tool 'send_email' blocked by the outbound_guard defense"])

    atk.search(evaluate, budget=2)
    # The second attacker prompt must contain the block message from round 1.
    assert any("outbound_guard" in p for p in seen_prompts[1:])


def test_search_prunes_to_width():
    """With branching 3 and width 1, only the single best branch survives to
    seed the next depth -- so depth-2 generation happens once, not 3x."""
    # Round 1: 3 payloads, all evaluated. Round 2: 3 more from the 1 survivor.
    client = StubClient([_refinements("p1", "p2", "p3"), _refinements("q1", "q2", "q3")])
    atk = TreeAttacker(client=client, model="stub", branching=3, width=1, max_depth=2)

    scores = {"p1": 0, "p2": 0, "p3": 0}

    def evaluate(payload):
        # p2 is the most promising (a blocked send_email); it should be the sole survivor.
        if payload == "p2":
            return _obs(blocked=["blocked by outbound_guard"])
        return _obs(grade=0, reply="no")

    res = atk.search(evaluate, budget=12)
    assert res.broke is False
    # 3 (round1) + 3 (round2 from the single survivor) = 6 evaluations.
    assert res.evaluations == 6
    # 2 attacker generations: root + the one survivor's refinement.
    assert atk.attacker_calls == 2


def test_protocol_name_and_registry():
    from src.attacks.base import Attack
    from src.config.loader import resolve_attacks
    atk = resolve_attacks(["tree_attacker"])[0]
    assert atk.name == "tree_attacker"
    assert isinstance(atk, Attack) or hasattr(atk, "search")  # campaign attacker
