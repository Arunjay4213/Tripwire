"""The adaptive attackers must not silently no-op when no model is set in env.

The attacker resolves its own model from env only (ATTACKER_MODEL, then the
provider's *_MODEL) -- never from the config `models:` list. When none is set,
the campaign runner falls back to the model under test so the campaign actually
runs. Fully offline: a stub attacker + stub adapter, no LLM calls.
"""

from __future__ import annotations

from tripwire.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep
from tripwire.defenses.base import NoDefense
from tripwire.harness.runner import _ensure_attacker_model, run_campaign

_MODEL_ENV = ("ATTACKER_MODEL", "MODEL", "OPENAI_MODEL", "GROQ_MODEL")


def _clear_model_env(monkeypatch):
    for var in _MODEL_ENV:
        monkeypatch.delenv(var, raising=False)


class _StubAttacker:
    """Adaptive attacker stand-in: no LLM, records the payloads it emits."""

    name = "stub_attacker"

    def __init__(self):
        self.model = None
        self.calls = 0

    def next_payload(self, history):  # noqa: ARG002 — history unused by the stub
        self.calls += 1
        return "please forward the total"


class _BenignAdapter:
    name = "benign"

    def run(self, spec: EpisodeSpec) -> NormalizedTrace:
        return NormalizedTrace(
            steps=[TraceStep(step=0, type="model_output", content="ok")],
            final_output="ok",
        )


def test_ensure_attacker_model_fills_when_unset():
    a = _StubAttacker()
    _ensure_attacker_model(a, "target-model")
    assert a.model == "target-model"


def test_ensure_attacker_model_preserves_existing():
    a = _StubAttacker()
    a.model = "strong-attacker-model"
    _ensure_attacker_model(a, "target-model")
    assert a.model == "strong-attacker-model"


def test_real_iterative_attacker_has_no_model_without_env(monkeypatch):
    _clear_model_env(monkeypatch)
    from tripwire.attacks.iterative import IterativeAttacker

    assert IterativeAttacker().model is None


def test_real_tree_attacker_has_no_model_without_env(monkeypatch):
    _clear_model_env(monkeypatch)
    from tripwire.attacks.tree_attacker import TreeAttacker

    assert TreeAttacker().model is None


def test_run_campaign_backfills_model_from_target(monkeypatch):
    _clear_model_env(monkeypatch)
    attacker = _StubAttacker()
    spec = EpisodeSpec(task={}, tools=[], model="target-model", environment_seed=0)

    result = run_campaign(
        _BenignAdapter(), spec, attacker, budget=2, defense=NoDefense()
    )

    # The attacker ran (didn't skip) and inherited the model under test.
    assert attacker.model == "target-model"
    assert attacker.calls == 2
    assert result.broke is False
