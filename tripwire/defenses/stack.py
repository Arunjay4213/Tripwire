"""Stacked defenses: several rungs applied to one episode.

Every rung in the ladder only wraps, appends, filters or blocks, so they
compose. A DefenseStack applies its members in the listed order at each of
the five hooks:

- bind:                every member is bound to the episode's context.
- wrap_system_prompt:  folded left, so the first member's instruction comes
                       first in the prompt.
- filter_tool_calls:   folded left.
- check_tool_call:     the first member that blocks decides, with its own
                       message; later members are not consulted. List the
                       deterministic rungs before a model-based guard and
                       the guard is never paid for a call the allowlist
                       would refuse anyway.
- wrap_tool_result:    folded left (spotlighting fences, then sandwich
                       appends the user's request after the fence).

Its name is the members' names joined with "+", which is also how it is
spelled in a config (`defenses: [spotlighting+recipient_allowlist]`), so the
results file, the ASR table and the CI gate's --defense filter all see one
ordinary defense name.

Error accounting composes too: `errors` is the sum over members, so a guard
or extractor outage inside a stack is still recorded by the runner as an
error outcome rather than a defended run. The runner applies its model
fallback to each member (runner._defense_model_fallback), so a member that
needs a model gets the model under test exactly as it would alone.

The plan expects prompt-level rungs to add little to each other (they share
one failure mode) and different mechanisms to add more; a stack is how that
gets measured rather than assumed.
"""

from __future__ import annotations

from typing import Any, Sequence

from .base import Defense, DefenseContext, bind_defense

SEPARATOR = "+"


class DefenseStack:
    """Several defenses applied in order as one."""

    def __init__(self, members: Sequence[Defense]) -> None:
        members = tuple(members)
        if len(members) < 2:
            raise ValueError("a defense stack needs at least two members")
        names = [m.name for m in members]
        if "no_defense" in names:
            raise ValueError("a defense stack cannot contain the no-defense baseline")
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"a defense stack lists {', '.join(duplicates)} more than once")
        self.members = members

    @property
    def name(self) -> str:
        return SEPARATOR.join(m.name for m in self.members)

    # --- binding ---------------------------------------------------------------

    def bind(self, ctx: DefenseContext) -> None:
        for member in self.members:
            bind_defense(member, ctx)

    # --- the four hooks ----------------------------------------------------------

    def wrap_system_prompt(self, prompt: str) -> str:
        for member in self.members:
            prompt = member.wrap_system_prompt(prompt)
        return prompt

    def filter_tool_calls(self, tool_calls: list[Any]) -> list[Any]:
        for member in self.members:
            tool_calls = member.filter_tool_calls(tool_calls)
        return tool_calls

    def check_tool_call(self, name: str, args: dict[str, Any]) -> tuple[bool, str]:
        for member in self.members:
            allowed, message = member.check_tool_call(name, args)
            if not allowed:
                return False, message
        return True, ""

    def wrap_tool_result(self, name: str, result: str) -> str:
        for member in self.members:
            result = member.wrap_tool_result(name, result)
        return result

    # --- error accounting the runner reads ------------------------------------------

    @property
    def errors(self) -> int:
        total = 0
        for member in self.members:
            count = getattr(member, "errors", 0)
            if isinstance(count, int):
                total += count
        return total

    @property
    def calls(self) -> int:
        return sum(c for m in self.members if isinstance(c := getattr(m, "calls", 0), int))

    @property
    def tokens(self) -> int:
        return sum(t for m in self.members if isinstance(t := getattr(m, "tokens", 0), int))

    @property
    def last_error(self) -> str | None:
        for member in self.members:
            last = getattr(member, "last_error", None)
            if last:
                return f"{member.name}: {last}"
        return None
