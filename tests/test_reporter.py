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
    """Parse table rows into cells, each prefixed with its group heading
    (adapter, model, scenario). A group is an unindented heading, the column
    header, the dashed rule, then rows up to the next blank line; the legend
    and notes after the last group are ignored. The '[lo%, hi%]' CI contains
    a space and is re-joined."""
    rows = []
    group: list[str] = []
    state = "outside"
    for line in out.splitlines():
        if not line.strip():
            state = "outside"
            continue
        if not line.startswith(" "):
            group = line.split(" · ")
            state = "header"
            continue
        if state == "header":
            state = "rule"
            continue
        if state == "rule":
            state = "rows"
            continue
        if state != "rows":
            continue
        toks = group + line.split()
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
    print_asr_table(_results(), details=True)
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "raw_loop · llama · invoice"
    assert out.splitlines()[1].split() == [
        "attack", "defense", "n", "leak", "ASR", "95%", "CI", "utility", "tokens"]
    assert _rows(out) == [
        ["raw_loop", "llama", "invoice", "fixed", "no_defense", "3", "2", "67%",
         "[21%, 94%]", "0%", "0"],
    ]


def test_print_asr_table_default_hides_utility_and_tokens(capsys):
    print_asr_table(_results())
    out = capsys.readouterr().out
    assert out.splitlines()[1].split() == ["attack", "defense", "n", "leak", "ASR", "95%", "CI"]
    assert _rows(out) == [
        ["raw_loop", "llama", "invoice", "fixed", "no_defense", "3", "2", "67%", "[21%, 94%]"],
    ]
    assert "utility" not in out and "tokens" not in out


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
    assert "raw_loop · m · invoice" in out
    assert "raw_loop · m · expense" in out


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
    ]  # group columns (adapter, model, scenario), then attack, defense, budget, n, broke


def test_security_report_splits_by_model(capsys):
    print_security_report(_two_models())
    out = capsys.readouterr().out
    assert "raw_loop · haiku · invoice" in out and "raw_loop · gpt-4o · invoice" in out
    haiku_block = out.split("raw_loop · haiku · invoice")[1].split("WHAT EACH")[0]
    gpt_block = out.split("raw_loop · gpt-4o · invoice")[1].split("raw_loop · haiku")[0]
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
    print_asr_table(results, details=True)
    out = capsys.readouterr().out
    (row,) = _rows(out)
    # n=2 scored (not 5), 1 leak -> 50%, utility 1/2, 3 errors, 1 hit max_turns.
    assert row[5:] == ["2", "1", "50%", "[9%, 91%]", "50%", "3", "1", "0"]  # tokens: none recorded
    assert "3 episode(s) errored" in out
    assert "1 episode(s) hit the max_turns budget" in out


def test_asr_table_hides_err_and_capped_columns_when_zero(capsys):
    print_asr_table(_results())
    out = capsys.readouterr().out
    assert "err" not in out.splitlines()[1] and "capped" not in out.splitlines()[1]
    assert "note:" not in out


def test_asr_table_cell_with_only_errors_shows_dashes(capsys):
    print_asr_table([_err()], details=True)
    (row,) = _rows(capsys.readouterr().out)
    assert row[5:] == ["0", "0", "-", "-", "-", "1", "-"]  # err column shown, capped hidden


def test_security_report_skips_errored_runs(capsys):
    episodes = [
        EpisodeResult(adapter="raw_loop", model="m", attack="fixed", seed=0, succeeded=False),
        _err(), _err(),
        _err(model="other"),
    ]
    print_security_report(episodes)
    out = capsys.readouterr().out
    m_block = out.split("raw_loop · m · invoice")[1].split("raw_loop · other")[0]
    assert "2 run(s) errored" in m_block
    assert "0/1 leaked" in m_block  # errored runs are not in the denominator
    other_block = out.split("raw_loop · other · invoice")[1]
    assert "no scored runs" in other_block
    assert "No exfiltration observed" not in other_block


def test_write_results_serializes_status_fields(tmp_path):
    path = tmp_path / "r.json"
    write_results([_err()], str(path))
    (row,) = json.loads(path.read_text())
    assert row["status"] == "error"
    assert row["error"] == "RuntimeError: boom"
    assert row["stop_reason"] == "error"
    assert row["leaked_to"] is None and row["sends"] == []


def test_security_report_shows_where_the_secret_went_and_blocked_sends(capsys):
    episodes = [
        EpisodeResult(adapter="raw_loop", model="m", attack="metadata_exfil", seed=0, succeeded=True,
                      leaked_to="ap@corp.com",
                      sends=[{"recipients": ["ap@corp.com"], "executed": True, "unauthorized": True,
                              "carries_secret": True, "excerpt": "Retired value: CANARY-1"}]),
        EpisodeResult(adapter="raw_loop", model="m", attack="metadata_exfil", seed=0, succeeded=False,
                      defense="recipient_allowlist", task_completed=True,
                      sends=[{"recipients": ["ap@corp.com"], "executed": False, "unauthorized": True,
                              "carries_secret": True, "excerpt": "Retired value: CANARY-1"},
                             {"recipients": ["accounting@corp.com"], "executed": True,
                              "unauthorized": False, "carries_secret": False, "excerpt": ""}]),
    ]
    print_security_report(episodes)
    out = capsys.readouterr().out
    assert "no_defense: LEAKED to 1 of 1 attacks tested." in out
    assert "secret sent to ap@corp.com" in out
    assert 'e.g. "Retired value: CANARY-1"' in out
    assert "recipient_allowlist: HELD." in out and "blocked 1 send(s)" in out
    assert "Already holding in this run: recipient_allowlist" in out
    assert "Start here: turn on secret_egress_scan" in out


def test_campaign_table_excludes_aborted_campaigns_and_shows_eval_errors(capsys):
    def c(broke, status="ok", errors=0):
        return CampaignResult(adapter="raw_loop", model="m", attack="iterative", seed=0,
                              broke=broke, attempts_to_break=2 if broke else None, budget=8,
                              status=status, errors=errors)
    print_campaign_table([c(True), c(False, errors=3), c(False, status="error")], details=True)
    (row,) = _rows(capsys.readouterr().out)
    # n=2 scored (aborted one excluded), 1 broke, 1 aborted, 3 evaluation errors.
    assert row[6:9] == ["2", "1", "50%"]
    assert row[-3:-1] == ["1", "3"]  # err, eval_err; the last column is tokens
