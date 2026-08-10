"""Attack interface — wrap AgentDojo attacks behind one interface.

P3 (roadmap Weeks 2-3). Start by reusing AgentDojo's `important_instructions`,
then add the iterative-refinement attacker (reuse PAIR; cite it, don't claim
novelty).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Attack(Protocol):
    name: str

    def render(self, canary: str) -> str:
        """Produce the injected payload string for this episode."""
        ...
