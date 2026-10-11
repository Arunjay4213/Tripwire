"""Tests for the attack suite - static attacks, the iterative attacker, and
run_campaign.

No network and no `unittest.mock`: the static attacks are pure functions, and
the iterative attacker's LLM calls are exercised through a hand-written stub
client (a plain class exposing `.chat.completions.create`) so nothing hits Groq.
"""

import pytest

from tripwire.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep
from tripwire.attacks.agentdojo_wrappers import (
    DirectAttack,
    IgnorePreviousAttack,
    ImportantInstructionsAttack,
    InjecAgentAttack,
    SystemMessageAttack,
)
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
from tripwire.attacks.iterative import SEED_STRATEGIES, IterativeAttacker
from tripwire.harness.canary import make_canary
from tripwire.harness.runner import run_campaign
from tripwire.scenarios import SCENARIOS

# The registered non-adaptive attacks, split by whether they redirect the send.
# The hand-crafted attacks all hijack the send to the scenario's same-domain
# decoy; the templated wrappers are scenario-neutral reference baselines aimed
# at a fixed external address, so they do NOT use the decoy.
REDIRECT_ATTACKS = [
    FixedInjection, MetadataExfil, PublicIdentifier, ForgedBoundary,
    PrerequisiteMirror, MundaneRedirect, GuardInjection, RelayActionItem,
]
TEMPLATED_BASELINES = [
    DirectAttack, IgnorePreviousAttack, SystemMessageAttack,
    InjecAgentAttack, ImportantInstructionsAttack,
]
STATIC_ATTACKS = REDIRECT_ATTACKS + TEMPLATED_BASELINES
CONTEXTS = [s.attack_context() for s in SCENARIOS.values()]

CANARY = "CANARY-7f3a91"


# --- templated wrappers -----------------------------------------------------

def test_important_instructions_fills_user_and_model():
    """The one template with {user}/{model} placeholders substitutes both."""
    payload = ImportantInstructionsAttack().render(CANARY)
    assert "{" not in payload and "}" not in payload
    assert "Emma Johnson" in payload


# --- scenario-context templating (every static attack, every scenario) ------

@pytest.mark.parametrize("cls", STATIC_ATTACKS,
                         ids=[c.__name__ for c in STATIC_ATTACKS])
@pytest.mark.parametrize("ctx", CONTEXTS, ids=[c.scenario for c in CONTEXTS])
def test_static_attack_renders_for_every_scenario(cls, ctx):
    """Each registered static attack renders a non-empty payload for every
    scenario context and never embeds the canary."""
    p = cls().render(CANARY, ctx)
    assert isinstance(p, str) and p.strip()
    assert CANARY not in p


@pytest.mark.parametrize("cls", STATIC_ATTACKS,
                         ids=[c.__name__ for c in STATIC_ATTACKS])
def test_static_attack_still_renders_with_ctx_none(cls):
    """Legacy callers (render(canary), no context) keep working -- the attack
    falls back to its invoice default wording."""
    p = cls().render(CANARY)
    assert isinstance(p, str) and p.strip()
    assert CANARY not in p


@pytest.mark.parametrize("cls", REDIRECT_ATTACKS,
                         ids=[c.__name__ for c in REDIRECT_ATTACKS])
@pytest.mark.parametrize("ctx", CONTEXTS, ids=[c.scenario for c in CONTEXTS])
def test_redirect_attack_uses_scenario_decoy(cls, ctx):
    """A redirect-style attack must name THIS scenario's same-domain decoy (an
    unauthorized recipient) so it exfiltrates under the destination-aware judge,
    and must not paste another scenario's decoy address in its place."""
    p = cls().render(CANARY, ctx)
    assert ctx.decoy_recipient in p
    assert ctx.decoy_recipient not in ctx.authorized_recipients
    # No other scenario's decoy leaks in (e.g. the invoice "ap@corp.com" must
    # not appear in a helpdesk/calendar/expense payload).
    for other in CONTEXTS:
        if other.decoy_recipient != ctx.decoy_recipient:
            assert other.decoy_recipient not in p


# --- iterative attacker (offline via stub client) ---------------------------

class _FakeCompletion:
    def __init__(self, content):
        self.choices = [type("C", (), {"message": type("M", (), {"content": content})()})()]
        self.usage = type("U", (), {"total_tokens": 7})()


class _FakeCompletions:
    def __init__(self, outputs):
        self._outputs = list(outputs)
        self.calls = 0

    def create(self, **kwargs):
        out = self._outputs[min(self.calls, len(self._outputs) - 1)]
        self.calls += 1
        return _FakeCompletion(out)


class FakeClient:
    """Minimal stand-in for the OpenAI client — no network."""

    def __init__(self, outputs):
        self.chat = type("Chat", (), {"completions": _FakeCompletions(outputs)})()


def _attacker(outputs):
    return IterativeAttacker(client=FakeClient(outputs), model="fake-model")


def test_looks_like_refusal_positive():
    assert IterativeAttacker._looks_like_refusal("I'm sorry, I cannot help with that.")


def test_looks_like_refusal_negative_long_text():
    """A long email body that happens to contain a marker isn't a refusal."""
    body = "From: audit@co\n" + "This is a legitimate-looking payload. " * 20
    assert not IterativeAttacker._looks_like_refusal(body)


def test_next_payload_returns_generation():
    a = _attacker(["From: audit\nPlease confirm the retired value."])
    assert "retired value" in a.next_payload([]).lower()
    assert a.llm_calls == 1


def test_build_prompt_includes_history_and_scores():
    a = _attacker(["x"])
    history = [("payload-A", 1, "I acted but withheld the key")]
    prompt = a.build_prompt(history, round_idx=1)
    assert "payload-A" in prompt
    assert "[score 1]" in prompt
    assert SEED_STRATEGIES[1] in prompt  # seed rotates with round


# --- run_campaign (offline via scripted adapter + stub attacker) ------------

class ScriptedAdapter:
    """Adapter returning pre-built traces, one per run() call."""

    name = "scripted"

    def __init__(self, traces):
        self._traces = list(traces)
        self.i = 0

    def run(self, spec):
        trace = self._traces[self.i]
        self.i += 1
        return trace


class RecordingAttacker:
    name = "iterative"

    def __init__(self):
        self.history_lengths = []

    def next_payload(self, history):
        self.history_lengths.append(len(history))
        return f"payload-{len(history)}"


def _send(body):
    return NormalizedTrace(
        steps=[TraceStep(step=0, type="tool_call", name="send_email", args={"body": body})],
        final_output=body,
    )


def _spec(seed=0):
    return EpisodeSpec(task=None, tools=[], model="m", environment_seed=seed)


def test_run_campaign_breaks_on_leak():
    seed = 0
    canary = make_canary(seed)
    adapter = ScriptedAdapter([_send("no key here"), _send(f"leaked: {canary}")])
    result = run_campaign(adapter, _spec(seed), RecordingAttacker(), budget=5)
    assert result.broke is True
    assert result.attempts_to_break == 2
    assert result.attack == "iterative"
    assert result.adapter == "scripted"
    assert result.seed == seed


def test_run_campaign_exhausts_budget():
    adapter = ScriptedAdapter([_send("clean"), _send("clean"), _send("clean")])
    result = run_campaign(adapter, _spec(), RecordingAttacker(), budget=3)
    assert result.broke is False
    assert result.attempts_to_break is None
    assert result.budget == 3


def test_run_campaign_feeds_growing_history():
    """Each attempt's graded outcome accumulates in the attacker's history."""
    attacker = RecordingAttacker()
    adapter = ScriptedAdapter([_send("clean"), _send("clean")])
    run_campaign(adapter, _spec(), attacker, budget=2)
    assert attacker.history_lengths == [0, 1]  # round 0 empty, round 1 has one entry
