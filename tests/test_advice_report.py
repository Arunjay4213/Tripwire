"""Tests for the security-feedback advice + report.

Offline: builds EpisodeResult objects directly (no LLM) and checks that the
report names the attacks that leaked and prints an actionable fix.
"""

from __future__ import annotations

from tripwire.config.loader import _ATTACK_REGISTRY
from tripwire.harness.advice import advice_for
from tripwire.harness.reporter import print_security_report
from tripwire.harness.runner import EpisodeResult


def test_every_registered_attack_has_specific_advice():
    """No registered attack should fall back to the generic advice -- each has a
    tailored summary + fix."""
    for name in _ATTACK_REGISTRY:
        a = advice_for(name)
        assert a.summary and a.fix
        assert a.summary != advice_for("__definitely_unknown__").summary, name


def _ep(attack, succeeded, defense="no_defense"):
    return EpisodeResult(adapter="my_agent", model="m", attack=attack, seed=0,
                         succeeded=succeeded, defense=defense, task_completed=True,
                         scenario="invoice")


def test_report_flags_leaked_attacks_with_fix(capsys):
    episodes = [
        _ep("mundane_redirect", True), _ep("mundane_redirect", True),
        _ep("metadata_exfil", True),
        _ep("direct", False),  # resisted -> should NOT be listed as a vulnerability
    ]
    print_security_report(episodes)
    out = capsys.readouterr().out
    assert "SECURITY FEEDBACK" in out
    assert "mundane_redirect" in out and "metadata_exfil" in out
    assert "• direct" not in out  # resisted attack is not listed as a vulnerability
    assert "fix:" in out
    assert "allowlist" in out.lower()  # redirect attack triggers the allowlist recommendation


def test_report_congratulates_when_nothing_leaks(capsys):
    episodes = [_ep("metadata_exfil", False, defense="prompt_hardening")]
    print_security_report(episodes)
    out = capsys.readouterr().out
    assert "No exfiltration observed" in out
