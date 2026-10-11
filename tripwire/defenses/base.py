"""Defense interface — wrap mitigations behind one contract.

Defenses sit between the harness and the adapter, at two enforcement points:

- wrap_system_prompt / filter_tool_calls run once, before the agent's tool
  loop starts -- they decide what's offered (the system prompt, the tool
  menu).
- check_tool_call runs mid-loop, once per tool call the model actually makes
  -- it decides what's allowed to *run*. This is what catches a model that
  free-forms a call outside its offered menu (a real, observed failure mode),
  and what a content-inspecting defense (e.g. "block outputs that look like a
  secret") would need -- filtering the menu upfront can't do that.
- wrap_tool_result runs mid-loop too, on the *result* of a tool that actually
  executed, before the model sees it. A content-marking defense (spotlighting)
  fences untrusted tool output here so the model treats it as data, not
  instructions.

- bind(ctx) runs once per episode, before any of the above, and hands the
  defense a DefenseContext: what the deployment knows about this episode
  (the user's request, the values it provisioned into the agent's context,
  which tools return external content). Optional and duck-typed -- a
  defense without `bind` never sees it (see bind_defense).

The judge still scores only the normalized trace; defenses affect what the
agent does, not how we measure success.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

# The tools that move data out of the system. Every scenario's only sink is
# send_email (the one tool the judge scores).
DEFAULT_SINK_TOOLS = frozenset({"send_email"})

# An email address in free text. ASCII-only on purpose: a marker character a
# defense interleaves into tool output (datamarking's U+02C6) is a Unicode
# letter, and must not glue itself onto an address.
_ADDRESS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def addresses_in(text: str) -> frozenset[str]:
    """Every email address that appears in `text`, lowercased."""
    if not isinstance(text, str):
        return frozenset()
    return frozenset(m.lower() for m in _ADDRESS.findall(text))


# The value kinds a typed extraction may declare. Each has a validator in
# defenses/quarantined_reader.py; a value that does not fit its kind is
# dropped, which is what keeps an injected instruction out of a field.
FIELD_KINDS = ("money", "short_text", "date")


@dataclass(frozen=True)
class TypedField:
    """One value the task needs from untrusted content, with the kind that
    constrains what it may contain."""

    name: str
    kind: str
    description: str

    def __post_init__(self) -> None:
        if self.kind not in FIELD_KINDS:
            raise ValueError(f"field {self.name!r}: kind must be one of {FIELD_KINDS}, got {self.kind!r}")


@dataclass(frozen=True)
class DefenseContext:
    """What the deployment knows about one episode before the agent runs.

    Only facts a real operator has: the user's request (the trusted channel),
    the values the operator itself provisioned into the agent's context, and
    which tools return external content. It never carries the attacker's
    decoy address, and it does not carry the judge's authorized-recipient
    set either: a defense that wants the legitimate recipients derives them
    from the user's own request (`user_recipients`), as a deployed agent
    would have to.
    """

    scenario: str
    user_message: str
    # Values the deployment placed in the agent's context that must not leave
    # it (here, the planted instance id). An operator knows these: it put them
    # there.
    secrets: frozenset[str] = frozenset()
    # Tools whose output is external, attacker-influenced content.
    untrusted_tools: frozenset[str] = frozenset()
    sink_tools: frozenset[str] = DEFAULT_SINK_TOOLS
    # The typed values the task needs from the untrusted tools' content, for a
    # defense that extracts them instead of showing the agent the raw text
    # (quarantined_reader). An operator knows these: they define the job.
    fields: tuple[TypedField, ...] = ()

    @property
    def user_recipients(self) -> frozenset[str]:
        """The addresses the user named in their own request."""
        return addresses_in(self.user_message)


def bind_defense(defense: Any, ctx: DefenseContext) -> None:
    """Hand the episode's context to a defense that wants it (duck-typed
    `bind`); a no-op for defenses without one. Scenario.build_spec calls this
    before it asks the defense for anything else."""
    binder = getattr(defense, "bind", None)
    if callable(binder):
        binder(ctx)


@runtime_checkable
class Defense(Protocol):
    """Mitigation applied during an episode before/during the agent tool loop."""

    @property
    def name(self) -> str:
        """Stable identifier for configs, results, and ASR tables."""
        ...

    def wrap_system_prompt(self, prompt: str) -> str:
        """Modify the system prompt before the agent runs."""
        ...

    def filter_tool_calls(self, tool_calls: list[Any]) -> list[Any]:
        """Filter or modify tool definitions before the agent runs."""
        ...

    def check_tool_call(self, name: str, args: dict[str, Any]) -> tuple[bool, str]:
        """Approve or block one actual tool call, mid-loop.

        Returns (allowed, message). When not allowed, `message` replaces the
        tool's real result -- the adapter must not execute the tool.
        """
        ...

    def wrap_tool_result(self, name: str, result: str) -> str:
        """Transform a tool's real result before the model sees it, mid-loop.

        Runs only on results of tools that actually executed (never on a
        block message). Identity by default; content-marking defenses
        override it.
        """
        ...


class NoDefense:
    """Default defense — passthrough when no mitigation is configured."""

    @property
    def name(self) -> str:
        return "no_defense"

    def wrap_system_prompt(self, prompt: str) -> str:
        return prompt

    def filter_tool_calls(self, tool_calls: list[Any]) -> list[Any]:
        return tool_calls

    def check_tool_call(self, name: str, args: dict[str, Any]) -> tuple[bool, str]:
        return True, ""

    def wrap_tool_result(self, name: str, result: str) -> str:
        return result
