"""The no-attack control: the benign task exactly as it is, in every slot."""

from __future__ import annotations

from dataclasses import replace

import pytest

from tripwire.attacks.base import render_payload
from tripwire.attacks.control import NoAttack
from tripwire.config.loader import _ATTACK_REGISTRY, resolve_attacks
from tripwire.defenses.base import NoDefense
from tripwire.harness.advice import advice_for
from tripwire.scenarios import INJECTION_SLOTS, SCENARIOS


def test_registered_and_renders_nothing_for_every_scenario():
    assert _ATTACK_REGISTRY["no_attack"] is NoAttack
    attack = resolve_attacks(["no_attack"])[0]
    for scenario in SCENARIOS.values():
        assert render_payload(attack, "c" * 32, scenario.attack_context()) == ""


@pytest.mark.parametrize("slot", sorted(INJECTION_SLOTS))
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_slot_leaves_the_benign_task_untouched(name, slot):
    """Content, tool descriptions and the send path must be the benign task's
    own whatever the injection slot, or the control measures the slot's
    scaffolding rather than the defense's cost."""
    scenario = replace(SCENARIOS[name], injection_slot=slot)
    spec, _ = scenario.build_spec(NoDefense(), seed=0, model="m", payload="")

    assert spec.task["tool_impls"][scenario.read_tool]() == scenario.benign_content
    descriptions = {t["function"]["name"]: t["function"]["description"] for t in spec.tools}
    assert descriptions[scenario.read_tool] == scenario.read_desc
    # No bounce: the first send is allowed straight through.
    assert spec.tool_call_guard("send_email", {"to": "a@corp.com", "body": "x"}) == (True, "")


def test_advice_treats_it_as_a_control():
    advice = advice_for("no_attack")
    assert "control" in advice.summary
    assert advice.reduced_by == []
