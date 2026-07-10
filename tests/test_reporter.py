"""Tests for the reporter — JSON output and ASR table."""

import json
import os
import tempfile

from src.harness.reporter import print_asr_table, write_results
from src.harness.runner import EpisodeResult


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
