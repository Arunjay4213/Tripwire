"""Tests for the reporter — JSON output and ASR table."""

import json
import os
import tempfile

from tripwire.harness.reporter import (
    print_asr_table,
    print_campaign_table,
    print_security_report,
    write_results,
)
from tripwire.harness.runner import CampaignResult, EpisodeResult


def _results():
    return [
        EpisodeResult(adapter="raw_loop", model="llama", attack="fixed", seed=0, succeeded=True),
        EpisodeResult(adapter="raw_loop", model="llama", attack="fixed", seed=1, succeeded=False),
        EpisodeResult(adapter="raw_loop", model="llama", attack="fixed", seed=2, succeeded=True),
    ]


def test_write_results_creates_valid_json():
    results = _results()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        path = f.name
    try:
        write_results(results, path)
        with open(path) as f:
            data = json.load(f)
        assert len(data) == 3
        assert data[0]["adapter"] == "raw_loop"
        assert data[0]["succeeded"] is True
        assert data[1]["succeeded"] is False
    finally:
        os.unlink(path)


def test_write_results_empty():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        path = f.name
    try:
        write_results([], path)
        with open(path) as f:
            data = json.load(f)
        assert data == []
    finally:
        os.unlink(path)


def test_print_asr_table_runs(capsys):
    """Smoke test: print_asr_table produces output without crashing."""
    print_asr_table(_results())
    captured = capsys.readouterr()
    assert "raw_loop" in captured.out
    assert "fixed" in captured.out
    # Should show 2/3 leak count
    assert "2" in captured.out


def test_print_asr_table_empty(capsys):
    """Empty results → just header."""
    print_asr_table([])
    captured = capsys.readouterr()
    assert "adapter" in captured.out


def test_asr_table_splits_by_scenario(capsys):
    """Same adapter/attack/defense but different scenarios must not merge."""
    results = [
        EpisodeResult(adapter="raw_loop", model="m", attack="fixed", seed=0,
                      succeeded=True, scenario="invoice"),
        EpisodeResult(adapter="raw_loop", model="m", attack="fixed", seed=0,
                      succeeded=False, scenario="helpdesk"),
    ]
    print_asr_table(results)
    out = capsys.readouterr().out
    assert "invoice" in out and "helpdesk" in out


def test_campaign_table_runs_and_splits_by_scenario(capsys):
    """print_campaign_table renders, and keeps scenarios in separate rows."""
    campaigns = [
        CampaignResult(adapter="raw_loop", model="m", attack="iterative", seed=0,
                       broke=True, attempts_to_break=2, budget=8, scenario="invoice"),
        CampaignResult(adapter="raw_loop", model="m", attack="iterative", seed=0,
                       broke=False, attempts_to_break=None, budget=8, scenario="calendar"),
    ]
    print_campaign_table(campaigns)
    out = capsys.readouterr().out
    assert "iterative" in out
    assert "invoice" in out and "calendar" in out


def test_security_report_splits_by_scenario(capsys):
    """The security report groups by (agent, scenario, defense), so the same
    agent+defense on two scenarios yields two separate blocks."""
    episodes = [
        EpisodeResult(adapter="raw_loop", model="m", attack="metadata_exfil", seed=0,
                      succeeded=True, defense="no_defense", scenario="invoice"),
        EpisodeResult(adapter="raw_loop", model="m", attack="metadata_exfil", seed=0,
                      succeeded=False, defense="no_defense", scenario="expense"),
    ]
    print_security_report(episodes)
    out = capsys.readouterr().out
    assert "scenario=invoice" in out
    assert "scenario=expense" in out
