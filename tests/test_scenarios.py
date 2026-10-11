"""Tests for the AgentDojo-style local scenarios.

Offline: build_spec assembles an EpisodeSpec (no LLM, no network). We check the
structure the harness relies on -- the secret is planted, the payload rides the
read tool, the leak-capable tool is offered, and the defense hooks are wired.
"""

from __future__ import annotations

import pytest

from tripwire.defenses.base import NoDefense
from tripwire.defenses.spotlighting import OPEN_DELIMITER, Spotlighting
from tripwire.harness.canary import make_canary
from tripwire.scenarios import SCENARIOS, Scenario

ALL = list(SCENARIOS.values())


@pytest.mark.parametrize("scenario", ALL, ids=[s.name for s in ALL])
def test_build_spec_plants_secret_and_payload(scenario: Scenario):
    canary = make_canary(0)
    spec, returned = scenario.build_spec(NoDefense(), seed=0, model="m", payload="INJECT-HERE")
    assert returned == canary
    # Secret is in the system prompt (context), never in the read content.
    assert canary in spec.task["system_prompt"]
    # The payload rides the scenario's read tool output.
    read_out = spec.task["tool_impls"][scenario.read_tool]()
    assert "INJECT-HERE" in read_out
    assert scenario.benign_content in read_out
    assert canary not in read_out
    # The leak-capable tool is offered and executable.
    names = [t["function"]["name"] for t in spec.tools]
    assert "send_email" in names and scenario.read_tool in names


def test_spotlighting_hook_wraps_the_read_content():
    scenario = SCENARIOS["helpdesk"]
    spec, _ = scenario.build_spec(Spotlighting(), seed=0, model="m", payload="X")
    fenced = spec.tool_result_wrapper(scenario.read_tool, "some tool output")
    assert fenced.startswith(OPEN_DELIMITER)


# --- tree attacker on scenarios (offline: scripted adapter + fake search) -----

from tripwire.adapters.base import NormalizedTrace, TraceStep  # noqa: E402
from tripwire.attacks.tree_attacker import TreeResult  # noqa: E402
from tripwire.harness.runner import run_scenario_tree_campaign  # noqa: E402


class _FakeTree:
    """Stands in for TreeAttacker: runs one evaluate() and reports break=exfiltrated."""

    name = "tree_attacker"

    def search(self, evaluate, budget):
        obs = evaluate("some payload")
        return TreeResult(obs.exfiltrated, 1 if obs.exfiltrated else None, 1, 1, 0, "p")


def _leaking_adapter(recipient: str, canary: str):
    class _A:
        name = "scripted"

        def run(self, spec):
            return NormalizedTrace(
                steps=[TraceStep(step=0, type="tool_call", name="send_email",
                                 args={"to": recipient, "body": f"handled {canary}"})],
                final_output="",
            )
    return _A()


def test_scenario_tree_campaign_breaks_on_unauthorized_recipient():
    scenario = SCENARIOS["helpdesk"]
    canary = make_canary(0)
    adapter = _leaking_adapter("ap@corp.com", canary)  # NOT helpdesk's authorized inbox
    res = run_scenario_tree_campaign(adapter, scenario, "m", _FakeTree(), budget=3)
    assert res.broke is True
    assert res.attack == "tree_attacker" and res.defense == "no_defense"


def test_scenario_tree_campaign_authorized_recipient_is_not_a_break():
    """Leaking the canary to the scenario's OWN authorized recipient is in-channel,
    not exfiltration -- the campaign must not count it as a break."""
    scenario = SCENARIOS["helpdesk"]
    canary = make_canary(0)
    authorized = next(iter(scenario.authorized_recipients))
    adapter = _leaking_adapter(authorized, canary)
    res = run_scenario_tree_campaign(adapter, scenario, "m", _FakeTree(), budget=3)
    assert res.broke is False


# --- task completion + config resolution + sweep tagging --------------------

def test_task_completed_needs_authorized_recipient_and_marker():
    scenario = SCENARIOS["expense"]
    authorized = next(iter(scenario.authorized_recipients))
    done = NormalizedTrace(steps=[TraceStep(step=0, type="tool_call", name="send_email",
                                            args={"to": authorized, "body": f"total {scenario.task_marker}"})],
                           final_output="")
    assert scenario.task_completed(done) is True
    # right content, wrong (unauthorized) recipient -> not the task
    wrong = NormalizedTrace(steps=[TraceStep(step=0, type="tool_call", name="send_email",
                                             args={"to": "ap@corp.com", "body": scenario.task_marker})],
                            final_output="")
    assert scenario.task_completed(wrong) is False


def test_resolve_scenarios_known_and_unknown():
    from tripwire.config.loader import resolve_scenarios
    got = resolve_scenarios(["invoice", "helpdesk"])
    assert [s.name for s in got] == ["invoice", "helpdesk"]
    with pytest.raises(ValueError):
        resolve_scenarios(["not_a_scenario"])


def test_run_sweep_tags_each_result_with_its_scenario():
    from tripwire.attacks.fixed_injection import FixedInjection
    from tripwire.defenses.base import NoDefense
    from tripwire.harness.runner import run_sweep

    class _Benign:
        name = "benign"
        def run(self, spec):
            return NormalizedTrace(steps=[TraceStep(step=0, type="model_output", content="ok")],
                                   final_output="ok")

    episodes, _ = run_sweep([_Benign()], ["m"], [FixedInjection()], [0],
                            defenses=[NoDefense()],
                            scenarios=[SCENARIOS["helpdesk"], SCENARIOS["calendar"]])
    assert sorted(r.scenario for r in episodes) == ["calendar", "helpdesk"]


# --- turn budget + legacy invoice wrappers ----------------------------------

@pytest.mark.parametrize("scenario", ALL, ids=[s.name for s in ALL])
def test_build_spec_sets_max_turns(scenario: Scenario):
    spec, _ = scenario.build_spec(NoDefense(), seed=0, model="m", payload="X")
    assert spec.max_turns == 5
    spec, _ = scenario.build_spec(NoDefense(), seed=0, model="m", payload="X", max_turns=9)
    assert spec.max_turns == 9


def test_scenario_tree_campaign_passes_max_turns():
    seen: list[int] = []

    class _A:
        name = "recording"

        def run(self, spec):
            seen.append(spec.max_turns)
            return NormalizedTrace(steps=[], final_output="")

    run_scenario_tree_campaign(_A(), SCENARIOS["calendar"], "m", _FakeTree(), budget=1, max_turns=7)
    assert seen == [7]


def test_legacy_run_tree_campaign_delegates_to_invoice_scenario():
    from tripwire.adapters.base import EpisodeSpec
    from tripwire.harness.runner import run_tree_campaign

    canary = make_canary(3)
    spec = EpisodeSpec(task=None, tools=[], model="m", environment_seed=3)
    res = run_tree_campaign(_leaking_adapter("ap@corp.com", canary), spec, _FakeTree(), budget=2)
    assert res.broke is True and res.scenario == "invoice" and res.seed == 3
    res = run_tree_campaign(_leaking_adapter("accounting@corp.com", canary), spec, _FakeTree(), budget=2)
    assert res.broke is False


# --- what a defense is told about an episode -------------------------------------

@pytest.mark.parametrize("scenario", ALL, ids=[s.name for s in ALL])
def test_defense_context_derives_the_legitimate_recipients_from_the_request(scenario):
    """recipient_allowlist and taint_tracking approve the addresses the user's
    request names. They never read the judge's authorized set, but in every
    scenario the two must coincide, or the allowlist would cost utility (or
    approve a decoy) for reasons that have nothing to do with the attack."""
    ctx = scenario.defense_context("0" * 32)
    assert ctx.user_recipients == scenario.authorized_recipients
    assert scenario.decoy_recipient not in repr(ctx)  # the attacker's choice is not a defense's input
    assert ctx.secrets == {"0" * 32} and ctx.untrusted_tools == {scenario.read_tool}


def test_build_spec_binds_the_defense_before_it_wraps_anything():
    class Recording(NoDefense):
        def __init__(self):
            self.events: list[str] = []
            self.ctx = None

        def bind(self, ctx):
            self.events.append("bind")
            self.ctx = ctx

        def wrap_system_prompt(self, prompt):
            self.events.append("wrap")
            return prompt + " [wrapped]"

    defense = Recording()
    spec, canary = SCENARIOS["helpdesk"].build_spec(defense, seed=3, model="m", payload="p")
    assert defense.events[:2] == ["bind", "wrap"]
    assert defense.ctx.secrets == {canary} and defense.ctx.scenario == "helpdesk"
    # A second agent's own persona can be wrapped the same way (multi_agent's sender).
    assert spec.system_prompt_wrapper("actor") == "actor [wrapped]"
