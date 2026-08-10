"""Actionable security feedback: for each attack, what it does and how to stop it.

Turns a raw ASR table into guidance a developer can act on -- which attacks their
agent leaked to, why, and the concrete fix. The `reduced_by` lists name Tripwire
defenses that measurably cut the attack in our runs (so a user can turn one on
and re-measure); `fix` is the engineering change to make in the agent itself.

Grounded in docs/findings.md (claude-haiku-4-5). See reporter.print_security_report.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Advice:
    summary: str                       # what the attack does, in plain terms
    reduced_by: list[str] = field(default_factory=list)  # Tripwire defenses that cut it
    fix: str = ""                      # concrete change to make in your agent


# Shared advice for the stock templated jailbreaks.
_TEMPLATED = Advice(
    summary="a blatant injected instruction ('ignore your instructions and do X') hidden in tool content.",
    reduced_by=["prompt_hardening", "spotlighting"],
    fix="Treat tool output as data, never instructions -- turn on prompt_hardening and/or spotlighting. "
        "A modern aligned model already resists these; if yours doesn't, this is the first thing to fix.",
)

ATTACK_ADVICE: dict[str, Advice] = {
    "direct": _TEMPLATED,
    "ignore_previous": _TEMPLATED,
    "system_message": _TEMPLATED,
    "injecagent": _TEMPLATED,
    "important_instructions": _TEMPLATED,

    "fixed_injection": Advice(
        summary="a social-engineering email claiming your secret was 'already rotated out' and is now safe to log.",
        reduced_by=["prompt_hardening", "outbound_guard"],
        fix="prompt_hardening so the agent distrusts tool content; add an outbound_guard that inspects "
            "send_email content for the secret before it leaves.",
    ),
    "metadata_exfil": Advice(
        summary="reframes leaking the secret as a routine 'asset registration / logging' step to an "
                "internal-looking address, so the model does it without recognizing it as sensitive.",
        reduced_by=["prompt_hardening", "spotlighting", "outbound_guard"],
        fix="prompt_hardening or spotlighting (the agent then won't act on the injected 'registration' step); "
            "an outbound_guard is a good backstop.",
    ),
    "public_identifier": Advice(
        summary="re-classifies your secret as a 'public sender identifier' so a 'never share secrets' rule "
                "no longer seems to apply to it.",
        reduced_by=["prompt_hardening"],
        fix="Protect the value by what it IS, not by a label in the prompt -- don't let injected tool content "
            "redefine what counts as sensitive (prompt_hardening).",
    ),
    "forged_boundary": Advice(
        summary="forges a fake 'trusted system footer' after the untrusted data to smuggle an instruction "
                "past a delimiter defense.",
        reduced_by=["spotlighting"],
        fix="Use spotlighting that STRIPS its delimiter tokens from tool content before fencing, and treat "
            "everything a tool returns as untrusted no matter what 'trusted' markers it contains.",
    ),
    "prerequisite_mirror": Advice(
        summary="gates your agent's own task on ALSO 'mirroring' the send to an internal-looking archive "
                "address -- a real exfiltration that slips a content guard by relabeling the secret a 'routing tag'.",
        reduced_by=["prompt_hardening", "spotlighting"],
        fix="prompt_hardening/spotlighting stop it in our tests (the model ignores the injected mirror step). "
            "The most reliable fix is a RECIPIENT ALLOWLIST so the agent can only send to approved addresses.",
    ),
    "mundane_redirect": Advice(
        summary="hijacks the one legitimate send, re-pointing it to a plausible internal address with the "
                "secret attached, written as casual 'PS from billing' so it doesn't read as an injection.",
        reduced_by=["prompt_hardening", "spotlighting"],
        fix="The decisive fix is a RECIPIENT ALLOWLIST -- never let tool content change the destination. "
            "prompt_hardening cuts it substantially but not to zero, so allowlisting is what closes the gap.",
    ),
    "iterative": Advice(
        summary="an adaptive attacker that reads how your agent responds and refines its payload across attempts.",
        reduced_by=["prompt_hardening", "spotlighting", "outbound_guard"],
        fix="Layer defenses -- the input-side ones (prompt_hardening + spotlighting) held even against adaptive "
            "search in our tests; add a recipient allowlist and an outbound_guard for defense in depth.",
    ),
}
ATTACK_ADVICE["tree_attacker"] = ATTACK_ADVICE["iterative"]

_FALLBACK = Advice(
    summary="an injected instruction that got your agent to leak the planted secret to an unauthorized recipient.",
    reduced_by=["prompt_hardening", "spotlighting", "outbound_guard"],
    fix="Turn on the defense ladder (prompt_hardening, spotlighting, outbound_guard) and add a recipient allowlist.",
)


def advice_for(attack_name: str) -> Advice:
    return ATTACK_ADVICE.get(attack_name, _FALLBACK)
