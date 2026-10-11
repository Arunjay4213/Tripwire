"""Deterministic defense - a recipient allowlist on every outbound call.

Every attack that actually exfiltrates in this harness does it the same way:
it gets the agent to send to an address the user never asked for (a redirect,
a cc, a "mirror" to an archive). The input-side rungs try to talk the model out
of that and the outbound guard asks a second model to spot it. This rung does
not ask anyone: a send_email whose recipients are not all approved never runs.
No model call, no wording a payload can argue with, so it holds against every
redirect regardless of how the injection is phrased.

Where the approved set comes from. By default it is the addresses the user
named in their own request (DefenseContext.user_recipients) -- the trusted
channel, which is what a deployed agent actually has. It is NOT the judge's
authorized set: in all four scenarios the two coincide (tests pin that), but
the defense derives its list the way a real deployment would have to. An
operator can add fixed addresses (`recipient_allowlist: {allow: [...]}`), and
can turn the request-derived part off to run a static list only.

The block message names the approved recipients, so a model that was
redirected can still finish the user's real task on its next turn; that is
what keeps utility intact. The approved list is public to the attacker anyway
(it is the user's own request).

Limits, stated plainly: it closes exfiltration to an unapproved destination.
It does not stop the secret riding along to an approved one (that is in-channel
and the judge does not count it), and it does not stop an attacker who gets the
user to name the wrong address in the first place.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from tripwire.defenses.base import DEFAULT_SINK_TOOLS, DefenseContext, addresses_in
from tripwire.harness.judge import recipients_in


class RecipientAllowlist:
    """Blocks a sink call unless every recipient is on the approved list."""

    def __init__(self, allow: Iterable[str] = (), from_user_message: bool = True) -> None:
        self.static_allow: frozenset[str] = frozenset().union(*(addresses_in(a) for a in allow))
        self.from_user_message = from_user_message
        self._ctx: DefenseContext | None = None

    @property
    def name(self) -> str:
        return "recipient_allowlist"

    def bind(self, ctx: DefenseContext) -> None:
        self._ctx = ctx

    def approved(self) -> frozenset[str]:
        """The recipients a sink call may go to right now."""
        from_request = self._ctx.user_recipients if self._ctx and self.from_user_message else frozenset()
        return self.static_allow | from_request

    def _sinks(self) -> frozenset[str]:
        return self._ctx.sink_tools if self._ctx else DEFAULT_SINK_TOOLS

    def wrap_system_prompt(self, prompt: str) -> str:
        return prompt

    def filter_tool_calls(self, tool_calls: list[Any]) -> list[Any]:
        return tool_calls

    def check_tool_call(self, name: str, args: dict[str, Any]) -> tuple[bool, str]:
        if name not in self._sinks():
            return True, ""
        approved = self.approved()
        prefix = f"Tool {name!r} blocked by the recipient_allowlist defense: "
        if not approved:
            # Fail closed: nothing approved means nothing may leave.
            return False, prefix + "no recipients are approved for this session."
        recipients = recipients_in(args)
        if not recipients:
            return False, prefix + "the call names no recipient, so its destination cannot be checked."
        rejected = sorted({r for r in recipients if r not in approved})
        if rejected:
            return False, (
                f"{prefix}{', '.join(rejected)} is not an approved recipient. "
                f"Approved recipients: {', '.join(sorted(approved))}."
            )
        return True, ""

    def wrap_tool_result(self, name: str, result: str) -> str:
        return result
