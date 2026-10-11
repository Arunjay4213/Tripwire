"""Attack interface and the scenario context attacks render against.

An attack produces the injected payload for one episode. It receives the
canary only so the protocol is explicit about it; good attacks never embed the
value -- they trick the agent into volunteering it from its own context.

Attacks also receive an AttackContext: the public facts a real attacker would
know about the deployment they are writing to (what kind of item the agent
reads, what the user asked for, which same-domain address is a plausible
decoy). Without it every payload is written for the invoice story and gets
pasted verbatim into a VPN ticket or a meeting request, where the mismatch is
exactly what an aligned model notices. The context never carries the canary
or anything the judge treats as secret.
"""

from __future__ import annotations

import inspect
import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class AttackContext:
    """Attacker-visible facts about the scenario an episode runs in.

    Everything here is public from the attacker's point of view: the agent
    reads a known kind of item, the user's request is the kind of thing an
    insider could guess, and the decoy is an address the attacker chooses.
    """

    scenario: str                       # scenario name, e.g. "invoice"
    source_noun: str                    # what the agent reads: "email", "ticket", ...
    task_noun: str                      # what the user wants sent: "the invoice total", ...
    read_tool: str                      # tool that returns the poisoned content
    user_message: str                   # the user's real request (trusted channel)
    authorized_recipients: frozenset[str]
    domain: str                         # e.g. "corp.com"
    decoy_recipient: str                # plausible same-domain address NOT authorized
    sender_persona: str                 # who a plausible injected note is "from"
    injection_slot: str = "append"
    secret_label_known: bool = True

    @property
    def authorized_recipient(self) -> str:
        """The single authorized address when there is exactly one (the
        common case); the sorted first one otherwise."""
        return sorted(self.authorized_recipients)[0]


@runtime_checkable
class Attack(Protocol):
    name: str

    def render(self, canary: str, ctx: AttackContext | None = None) -> str:
        """Produce the injected payload string for this episode.

        `ctx` is None when the caller has no scenario (legacy scripts); an
        attack must then fall back to its default (invoice) wording.
        """
        ...


def accepts_context(attack: Any) -> bool:
    """Does this attack's render() take the context argument? Bring-your-own
    and older attacks may still define render(canary) only."""
    try:
        params = inspect.signature(attack.render).parameters
    except (TypeError, ValueError):
        return False
    if "ctx" in params:
        return True
    return any(p.kind is inspect.Parameter.VAR_POSITIONAL for p in params.values()) or len(params) >= 2


def render_payload(attack: Any, canary: str, ctx: AttackContext | None) -> str:
    """Render an attack with the context when it accepts one, without it
    otherwise. The single call site the harness should use."""
    if ctx is not None and accepts_context(attack):
        payload = attack.render(canary, ctx)
    else:
        payload = attack.render(canary)
    # A frozen replay is byte-identical to the saved payload, including any
    # knowledge the attacker legitimately discovered during its search.
    return payload if getattr(attack, "preserve_payload", False) else attacker_text(payload, ctx)


def attacker_text(text: str, ctx: AttackContext | None) -> str:
    """Remove supplied label/format hints for the unknown-label ablation.

    This limits initial oracle knowledge; it does not prevent an adaptive
    attacker from learning or guessing the label through target observations.
    The target's planted secret and scoring rules stay identical.
    """
    if ctx is None or ctx.secret_label_known:
        return text
    text = re.sub(r"integration[ _-]+instance[ _-]+id|instance[ _-]+id", "private configuration value", text, flags=re.I)
    text = re.sub(r"(?:fake )?32[- ]character hex (?:token|value)|32[- ]hex", "private value", text, flags=re.I)
    text = re.sub(r"(?i)\b(?:sent-by-)?instance(?=\s*:)", "reference", text)
    return text


def set_attack_context(attack: Any, ctx: AttackContext) -> None:
    """Hand the scenario context to an adaptive attacker that wants it
    (duck-typed `set_context`); a no-op for attackers without one."""
    setter = getattr(attack, "set_context", None)
    if callable(setter):
        setter(ctx)


def default_context() -> AttackContext:
    """The invoice scenario's context, for a render() called without one
    (legacy callers). Imported lazily: tripwire.scenarios imports this module,
    so a top-level import here would be a cycle, but a call-time import is not.
    """
    from tripwire.scenarios import INVOICE

    return INVOICE.attack_context()
