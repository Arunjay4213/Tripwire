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


def _rows(out: str) -> list[list[str]]:
    """Parse table rows into cells: skip the header, the dashed rule, and any
    trailing note lines; re-join the '[lo%, hi%]' CI which contains a space."""
    lines = out.strip().splitlines()
    rows = []
    for line in lines[2:]:
        if line.startswith("note:"):
            continue
        toks = line.split()
        merged: list[str] = []
        for t in toks:
            if merged and merged[-1].startswith("[") and not merged[-1].endswith("]"):
                merged[-1] += " " + t
            else:
                merged.append(t)
        rows.append(merged)
    return rows


def test_print_asr_table_exact_row(capsys):
    """One cell: n, leak, ASR, CI, utility, err and max_turns are exact."""
    print_asr_table(_results())
    out = capsys.readouterr().out
    assert out.splitlines()[0].split() == [
        "adapter", "model", "scenario", "attack", "defense", "n", "leak", "ASR",
        "95%", "CI", "utility", "err", "max_turns", "tokens"]
    assert _rows(out) == [
        ["raw_loop", "llama", "invoice", "fixed", "no_defense", "3", "2", "67%",
         "[21%, 94%]", "0%", "0", "0", "0"],
    ]


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


# --- model in every grouping key --------------------------------------------

def _two_models():
    return [
        EpisodeResult(adapter="raw_loop", model="haiku", attack="fixed", seed=0, succeeded=True),
        EpisodeResult(adapter="raw_loop", model="haiku", attack="fixed", seed=1, succeeded=True),
        EpisodeResult(adapter="raw_loop", model="gpt-4o", attack="fixed", seed=0, succeeded=False),
        EpisodeResult(adapter="raw_loop", model="gpt-4o", attack="fixed", seed=1, succeeded=False),
    ]


def test_asr_table_splits_by_model(capsys):
    """Two models on the same adapter/scenario/attack/defense must be two rows,
    not one pooled row with doubled n and an averaged ASR."""
    print_asr_table(_two_models())
    rows = _rows(capsys.readouterr().out)
    assert [(r[1], r[5], r[6], r[7]) for r in rows] == [
        ("gpt-4o", "2", "0", "0%"),
        ("haiku", "2", "2", "100%"),
    ]


def test_campaign_table_splits_by_model_and_budget(capsys):
    def c(model, budget, broke):
        return CampaignResult(adapter="raw_loop", model=model, attack="iterative", seed=0,
                              broke=broke, attempts_to_break=1 if broke else None, budget=budget)
    print_campaign_table([c("haiku", 8, True), c("gpt-4o", 8, False), c("haiku", 4, False)])
    rows = _rows(capsys.readouterr().out)
    assert [(r[1], r[5], r[6], r[7]) for r in rows] == [
        ("gpt-4o", "8", "1", "0"),
        ("haiku", "4", "1", "0"),
        ("haiku", "8", "1", "1"),
    ]


def test_security_report_splits_by_model(capsys):
    print_security_report(_two_models())
    out = capsys.readouterr().out
    assert "model=haiku" in out and "model=gpt-4o" in out
    haiku_block = out.split("model=haiku")[1]
    gpt_block = out.split("model=gpt-4o")[1].split("agent=")[0]
    assert "leaked 2/2" in haiku_block
    assert "No exfiltration observed" in gpt_block and "0/2 leaked" in gpt_block


# --- errored episodes and max_turns ------------------------------------------

def _err(model="m", attack="fixed"):
    return EpisodeResult(adapter="raw_loop", model=model, attack=attack, seed=9,
                         succeeded=False, status="error", error="RuntimeError: boom",
                         stop_reason="error")


def test_asr_table_excludes_errors_from_n_and_counts_them(capsys):
    results = [
        EpisodeResult(adapter="raw_loop", model="m", attack="fixed", seed=0, succeeded=True,
                      task_completed=True),
        EpisodeResult(adapter="raw_loop", model="m", attack="fixed", seed=1, succeeded=False,
                      stop_reason="max_turns"),
        _err(), _err(), _err(),
    ]
    print_asr_table(results)
    out = capsys.readouterr().out
    (row,) = _rows(out)
    # n=2 scored (not 5), 1 leak -> 50%, utility 1/2, 3 errors, 1 hit max_turns.
    assert row[5:] == ["2", "1", "50%", "[9%, 91%]", "50%", "3", "1", "0"]  # tokens: none recorded
    assert "3 episode(s) errored" in out
    assert "1 episode(s) hit the max_turns budget" in out


def test_asr_table_cell_with_only_errors_shows_dashes(capsys):
    print_asr_table([_err()])
    (row,) = _rows(capsys.readouterr().out)
    assert row[5:] == ["0", "0", "-", "-", "-", "1", "0", "-"]


def test_security_report_skips_errored_runs(capsys):
    episodes = [
        EpisodeResult(adapter="raw_loop", model="m", attack="fixed", seed=0, succeeded=False),
        _err(), _err(),
        _err(model="other"),
    ]
    print_security_report(episodes)
    out = capsys.readouterr().out
    m_block = out.split("model=m ")[1].split("agent=")[0]
    assert "2 run(s) errored" in m_block
    assert "0/1 leaked" in m_block  # errored runs are not in the denominator
    other_block = out.split("model=other")[1]
    assert "No scored runs" in other_block
    assert "No exfiltration observed" not in other_block


def test_write_results_serializes_status_fields(tmp_path):
    path = tmp_path / "r.json"
    write_results([_err()], str(path))
    (row,) = json.loads(path.read_text())
    assert row["status"] == "error"
    assert row["error"] == "RuntimeError: boom"
    assert row["stop_reason"] == "error"


def test_campaign_table_excludes_aborted_campaigns_and_shows_eval_errors(capsys):
    def c(broke, status="ok", errors=0):
        return CampaignResult(adapter="raw_loop", model="m", attack="iterative", seed=0,
                              broke=broke, attempts_to_break=2 if broke else None, budget=8,
                              status=status, errors=errors)
    print_campaign_table([c(True), c(False, errors=3), c(False, status="error")])
    (row,) = _rows(capsys.readouterr().out)
    # n=2 scored (aborted one excluded), 1 broke, 1 aborted, 3 evaluation errors.
    assert row[6:9] == ["2", "1", "50%"]
    assert row[-3:-1] == ["1", "3"]  # err, eval_err; the last column is tokens
