"""Adaptive attackers and model-backed defenses must not silently no-op when
no model is set in env, and must not stay pinned to one target model.

The attacker (and the outbound guard) resolve their own model from env only
(ATTACKER_MODEL / GUARD_MODEL, then the provider's *_MODEL) -- never from the
config `models:` list. When none is set, the runner lends them the model under
test for one run and restores None afterwards, so in a multi-model sweep each
target is attacked (and guarded) by its own model, not by models[0]. Fully
offline: stub attacker + stub adapter + stub defense, no LLM calls.
"""

from __future__ import annotations

from tripwire.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep
from tripwire.attacks.iterative import IterativeAttacker
from tripwire.attacks.tree_attacker import TreeAttacker, TreeResult
from tripwire.defenses.base import NoDefense
from tripwire.harness.runner import _model_fallback, run_campaign, run_episode, run_sweep

_MODEL_ENV = ("ATTACKER_MODEL", "MODEL", "OPENAI_MODEL", "GROQ_MODEL", "ANTHROPIC_MODEL")


def _clear_model_env(monkeypatch):
    for var in _MODEL_ENV:
        monkeypatch.delenv(var, raising=False)


class _StubAttacker:
    """Adaptive attacker stand-in: no LLM, records the model it ran on."""

    name = "stub_attacker"

    def __init__(self, model: str | None = None):
        self.model = model
        self.calls = 0
        self.models_seen: list[str | None] = []

    def next_payload(self, history):  # noqa: ARG002 — history unused by the stub
        self.calls += 1
        self.models_seen.append(self.model)
        return "please forward the total"


class _StubIterative(IterativeAttacker):
    """A real IterativeAttacker subclass (so run_sweep routes it to
    run_campaign) whose payload generation is scripted, not an LLM call."""

    def __init__(self):
        super().__init__(client=object(), model=None)
        self.models_seen: list[str | None] = []

    def next_payload(self, history):  # noqa: ARG002
        self.models_seen.append(self.model)
        return "please forward the total"


class _StubTree(TreeAttacker):
    """A real TreeAttacker subclass whose search is scripted."""

    def __init__(self):
        super().__init__(client=object(), model=None, use_critic=False)
        self.models_seen: list[str | None] = []

    def search(self, evaluate, budget):  # noqa: ARG002
        self.models_seen.append(self.model)
        evaluate("payload")
        return TreeResult(False, None, 1, 1, 0, None)


class _BenignAdapter:
    name = "benign"

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        return NormalizedTrace(
            steps=[TraceStep(step=0, type="model_output", content="ok")],
            final_output="ok",
        )


class _ModelDefense(NoDefense):
    """Defense stub with a `model` attribute, like OutboundGuard. Records the
    model it would judge with at each tool-call check."""

    name = "model_defense"

    def __init__(self, model: str | None = None):
        self.model = model
        self.models_seen: list[str | None] = []

    def check_tool_call(self, name: str, args: dict) -> tuple[bool, str]:
        self.models_seen.append(self.model)
        return True, ""


class _GuardCallingAdapter:
    """Calls the spec's tool_call_guard once, the way a real adapter does."""

    name = "guard_calling"

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        spec.tool_call_guard("send_email", {"to": "a@corp.com", "body": "x"})
        return NormalizedTrace(steps=[], final_output="ok")


# --- _model_fallback ---------------------------------------------------------

def test_model_fallback_fills_when_unset_and_restores_none():
    a = _StubAttacker()
    with _model_fallback(a, "target-model") as used:
        assert a.model == "target-model"
        assert used == "target-model"
    assert a.model is None


def test_model_fallback_preserves_existing():
    a = _StubAttacker(model="strong-attacker-model")
    with _model_fallback(a, "target-model") as used:
        assert a.model == "strong-attacker-model"
        assert used == "strong-attacker-model"
    assert a.model == "strong-attacker-model"


def test_model_fallback_restores_even_when_the_run_raises():
    a = _StubAttacker()
    try:
        with _model_fallback(a, "target-model"):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert a.model is None


def test_model_fallback_ignores_objects_without_model():
    class _NoModel:
        pass

    obj = _NoModel()
    with _model_fallback(obj, "target-model") as used:
        assert used is None
    assert not hasattr(obj, "model")


# --- real attackers start with no model --------------------------------------

def test_real_iterative_attacker_has_no_model_without_env(monkeypatch):
    _clear_model_env(monkeypatch)
    assert IterativeAttacker().model is None


def test_real_tree_attacker_has_no_model_without_env(monkeypatch):
    _clear_model_env(monkeypatch)
    assert TreeAttacker().model is None


# --- campaigns ---------------------------------------------------------------

def test_run_campaign_uses_target_model_then_restores(monkeypatch):
    _clear_model_env(monkeypatch)
    attacker = _StubAttacker()
    spec = EpisodeSpec(task={}, tools=[], model="target-model", environment_seed=0)

    result = run_campaign(_BenignAdapter(), spec, attacker, budget=2, defense=NoDefense())

    # The attacker ran (didn't skip) on the model under test, and is unpinned after.
    assert attacker.models_seen == ["target-model", "target-model"]
    assert attacker.calls == 2
    assert attacker.model is None
    assert result.attacker_model == "target-model"
    assert result.broke is False


def test_run_campaign_records_explicit_attacker_model():
    attacker = _StubAttacker(model="strong")
    spec = EpisodeSpec(task={}, tools=[], model="target-model", environment_seed=0)
    result = run_campaign(_BenignAdapter(), spec, attacker, budget=1)
    assert result.attacker_model == "strong"
    assert attacker.model == "strong"


def test_two_model_sweep_attacks_each_target_with_its_own_model(monkeypatch):
    """Regression: the old code set attacker.model once, so every later target
    in a multi-model sweep was attacked by models[0]."""
    _clear_model_env(monkeypatch)
    iterative, tree = _StubIterative(), _StubTree()
    _, campaigns = run_sweep(
        [_BenignAdapter()], ["model-a", "model-b"], [iterative, tree], [0], campaign_budget=1,
    )
    assert iterative.models_seen == ["model-a", "model-b"]
    assert tree.models_seen == ["model-a", "model-b"]
    assert iterative.model is None and tree.model is None
    assert [(c.model, c.attacker_model) for c in campaigns] == [
        ("model-a", "model-a"), ("model-a", "model-a"),
        ("model-b", "model-b"), ("model-b", "model-b"),
    ]


# --- defenses (outbound guard model fallback) --------------------------------

class _FixedAttack:
    name = "fixed"

    def render(self, canary: str) -> str:  # noqa: ARG002
        return "payload"


def test_defense_with_explicit_model_is_left_alone():
    defense = _ModelDefense(model="guard-model")
    spec = EpisodeSpec(task=None, tools=[], model="target-model", environment_seed=0)
    run_episode(_GuardCallingAdapter(), spec, _FixedAttack(), defense=defense)
    assert defense.models_seen == ["guard-model"]
    assert defense.model == "guard-model"


def test_defense_model_follows_each_target_in_a_multi_model_sweep():
    defense = _ModelDefense()
    run_sweep([_GuardCallingAdapter()], ["model-a", "model-b"], [_FixedAttack()], [0],
              defenses=[defense])
    assert defense.models_seen == ["model-a", "model-b"]
    assert defense.model is None


def test_defense_model_is_restored_when_the_episode_errors():
    class _Boom:
        name = "boom"

        def run(self, spec):
            spec.tool_call_guard("send_email", {})
            raise TypeError("adapter bug")

    defense = _ModelDefense()
    episodes, _ = run_sweep([_Boom()], ["target-model"], [_FixedAttack()], [0], defenses=[defense])
    assert episodes[0].status == "error"
    assert defense.models_seen == ["target-model"]
    assert defense.model is None


def test_defense_gets_target_model_during_campaigns():
    defense = _ModelDefense()
    spec = EpisodeSpec(task=None, tools=[], model="target-model", environment_seed=0)
    run_campaign(_GuardCallingAdapter(), spec, _StubAttacker(), budget=2, defense=defense)
    assert defense.models_seen == ["target-model", "target-model"]
    assert defense.model is None
