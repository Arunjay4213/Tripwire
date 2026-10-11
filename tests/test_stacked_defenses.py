"""Stacked defenses: several rungs on one episode, as one defense.

What can go wrong with a stack is specific: a member skipped at one hook, a
block overridden by a later member that allows, a member's outage counter
lost so the runner scores an outage as defended, or a member that needs a
model never getting one. Each is pinned here, plus the config spelling.
"""

from __future__ import annotations

import pytest

from tripwire.adapters.base import EpisodeSpec, NormalizedTrace, TraceStep
from tripwire.config.loader import resolve_defenses
from tripwire.defenses.base import DefenseContext, NoDefense
from tripwire.defenses.outbound_guard import OutboundGuard
from tripwire.defenses.prompt_hardening import PromptHardening
from tripwire.defenses.recipient_allowlist import RecipientAllowlist
from tripwire.defenses.spotlighting import Spotlighting
from tripwire.defenses.stack import DefenseStack
from tripwire.harness.runner import TOOL_SCHEMAS, _defense_model_fallback, run_episode
from tripwire.scenarios import SCENARIOS


class _Tag:
    """A defense that tags everything it touches, so order is observable."""

    def __init__(self, tag: str, block: str | None = None) -> None:
        self.tag = tag
        self.block = block
        self.bound: DefenseContext | None = None
        self.checked: list[str] = []

    @property
    def name(self) -> str:
        return self.tag

    def bind(self, ctx: DefenseContext) -> None:
        self.bound = ctx

    def wrap_system_prompt(self, prompt: str) -> str:
        return f"{prompt}[{self.tag}]"

    def filter_tool_calls(self, tool_calls):
        return tool_calls + [self.tag]

    def check_tool_call(self, name: str, args: dict) -> tuple[bool, str]:
        self.checked.append(name)
        if self.block == name:
            return False, f"blocked by {self.tag}"
        return True, ""

    def wrap_tool_result(self, name: str, result: str) -> str:
        return f"{self.tag}({result})"


# --- composition ----------------------------------------------------------------------

def test_every_hook_applies_members_in_listed_order():
    a, b = _Tag("a"), _Tag("b")
    stack = DefenseStack([a, b])
    assert stack.name == "a+b"
    assert stack.wrap_system_prompt("p") == "p[a][b]"
    assert stack.filter_tool_calls(["t"]) == ["t", "a", "b"]
    assert stack.wrap_tool_result("read_inbox", "x") == "b(a(x))"


def test_first_member_that_blocks_decides_and_later_members_are_not_consulted():
    first, second = _Tag("first", block="send_email"), _Tag("second")
    stack = DefenseStack([first, second])
    assert stack.check_tool_call("send_email", {}) == (False, "blocked by first")
    assert second.checked == []
    assert stack.check_tool_call("read_inbox", {}) == (True, "")
    assert second.checked == ["read_inbox"]


def test_bind_reaches_every_member_and_tolerates_members_without_bind():
    tagged = _Tag("t")
    stack = DefenseStack([PromptHardening(), tagged])  # PromptHardening binds; NoDefense-like members may not
    ctx = SCENARIOS["invoice"].defense_context("c" * 32)
    stack.bind(ctx)
    assert tagged.bound is ctx


@pytest.mark.parametrize("members, match", [
    ([_Tag("a")], "at least two"),
    ([_Tag("a"), _Tag("a")], "more than once"),
    ([_Tag("a"), NoDefense()], "no-defense baseline"),
])
def test_invalid_stacks_are_rejected(members, match):
    with pytest.raises(ValueError, match=match):
        DefenseStack(members)


# --- error accounting the runner relies on ---------------------------------------------

def test_errors_are_summed_across_members_and_last_error_names_the_member():
    def broken(_text):
        raise RuntimeError("detector down")

    guard = OutboundGuard(detector=broken)
    stack = DefenseStack([PromptHardening(), guard])
    assert stack.errors == 0
    stack.check_tool_call("send_email", {"to": "x@corp.com", "body": "hi"})
    assert stack.errors == 1
    assert stack.last_error.startswith("outbound_guard: RuntimeError")


def test_an_outage_inside_a_stack_is_an_error_outcome_not_a_defended_run():
    """The runner reads defense.errors; a stack must not hide a member's outage."""

    def broken(_text):
        raise RuntimeError("detector down")

    stack = DefenseStack([Spotlighting(), OutboundGuard(detector=broken)])

    class _SendsOnce:
        name = "sends_once"

        def run(self, spec: EpisodeSpec) -> NormalizedTrace:
            allowed, message = spec.tool_call_guard("send_email", {"to": "accounting@corp.com", "body": "Total: $2,480.00"})
            step = TraceStep(step=1, type="tool_result" if allowed else "tool_blocked", name="send_email",
                             content="email sent" if allowed else message)
            return NormalizedTrace(steps=[TraceStep(step=0, type="tool_call", name="send_email",
                                                    args={"to": "accounting@corp.com", "body": "Total: $2,480.00"}), step],
                                   final_output="")

    class _Attack:
        name = "fixed"

        def render(self, canary, ctx=None):
            return "payload"

    spec = EpisodeSpec(task=None, tools=TOOL_SCHEMAS, model="m", environment_seed=0)
    result = run_episode(_SendsOnce(), spec, _Attack(), defense=stack)
    assert result.defense == "spotlighting+outbound_guard"
    assert result.status == "error" and result.guard_errors == 1
    assert "outbound_guard" in result.error


# --- the model fallback reaches each member -------------------------------------------

def test_model_fallback_fills_each_member_that_needs_one_and_leaves_explicit_models_alone(monkeypatch):
    monkeypatch.delenv("GUARD_MODEL", raising=False)
    monkeypatch.delenv("READER_MODEL", raising=False)
    from tripwire.defenses.quarantined_reader import QuarantinedReader

    unset = OutboundGuard(detector=lambda _t: False)
    pinned = QuarantinedReader(extractor=lambda _t, _f: {}, model="reader-m")
    stack = DefenseStack([PromptHardening(), unset, pinned])
    assert unset.model is None
    with _defense_model_fallback(stack, "target-m"):
        assert unset.model == "target-m"
        assert pinned.model == "reader-m"
    assert unset.model is None and pinned.model == "reader-m"


# --- config spelling --------------------------------------------------------------------

def test_a_plus_name_resolves_to_a_stack_in_listed_order():
    (stack,) = resolve_defenses(["spotlighting+recipient_allowlist"], [])
    assert isinstance(stack, DefenseStack)
    assert [m.name for m in stack.members] == ["spotlighting", "recipient_allowlist"]
    assert isinstance(stack.members[1], RecipientAllowlist)
    assert stack.name == "spotlighting+recipient_allowlist"


@pytest.mark.parametrize("spec, match", [
    ("null+spotlighting", "cannot be stacked"),
    ("spotlighting+spotlighting", "more than once"),
    ("spotlighting+nonsense", "Unknown defense 'nonsense'"),
    ("spotlighting", None),  # a plain name is still a plain defense
])
def test_stack_spellings_are_validated(spec, match):
    if match is None:
        (d,) = resolve_defenses([spec], [])
        assert not isinstance(d, DefenseStack)
        return
    with pytest.raises(ValueError, match=match):
        resolve_defenses([spec], [])
