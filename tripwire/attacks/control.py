"""The no-attack control: an episode with no injection at all.

Every defense row in a sweep answers two questions, how often the attack got
through (ASR) and how often the agent still did its job (utility). Utility
under attack mixes two things: what the defense costs the agent on its own,
and how much the attack itself disrupts the task. This control separates
them. Its payload is empty, so Scenario.build_spec leaves the read tool's
content, the tool descriptions and the send path exactly as the benign task
has them, whatever the injection slot. The row's utility is then the
defense's own cost, and any leak in it means the agent leaks unprompted.

Registered as `no_attack`. Advice treats it as a control, not an attack.
"""

from __future__ import annotations

from .base import AttackContext


class NoAttack:
    """Renders nothing; the benign task runs as it would without Tripwire."""

    name = "no_attack"

    def render(self, canary: str, ctx: AttackContext | None = None) -> str:  # noqa: ARG002
        return ""
