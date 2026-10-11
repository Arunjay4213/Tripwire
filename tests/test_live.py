"""Opt-in live smoke test: the real CLI against the real provider.

Skipped unless TRIPWIRE_LIVE=1 and a provider key is present (environment or
.env). Runs the starter config `tripwire init` writes, or the file named by
TRIPWIRE_LIVE_CONFIG (MODEL in the environment overrides the
starter config's model id), with --smoke: one seed, the first scenario, attack and
defense, one adapter. It proves the provider serves the configured model,
the adapter loop and judge work on real model output, and the results file
the CI gate reads gets written. Set TRIPWIRE_LIVE_OUTPUT to keep that file
(CI points the gate at it).

    TRIPWIRE_LIVE=1 python -m pytest tests/test_live.py -q
"""

from __future__ import annotations

import json
import os

import pytest

import tripwire.__main__ as cli

pytestmark = pytest.mark.live


def test_smoke_sweep_scores_one_episode_against_the_live_provider(
    tmp_path, monkeypatch, capsys, live_provider_env,
):
    cfg_path = os.environ.get("TRIPWIRE_LIVE_CONFIG")
    if not cfg_path:
        # The starter config names Anthropic's default model; a provider that
        # serves a different id says so through MODEL (the same variable the
        # harness honours), so the test runs what the environment can run.
        config = cli.STARTER_CONFIG
        if os.environ.get("MODEL"):
            config = config.replace("  - claude-haiku-4-5", f"  - {os.environ['MODEL']}", 1)
        cfg_path = str(tmp_path / "threat_model.yaml")
        with open(cfg_path, "w") as f:
            f.write(config)
    out_path = os.environ.get("TRIPWIRE_LIVE_OUTPUT") or str(tmp_path / "results.json")
    monkeypatch.setattr("sys.argv", ["tripwire", "--config", cfg_path, "--output", out_path,
                                     "--smoke", "--preflight", "--strict"])

    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()

    assert code == 0, captured.err
    rows = json.loads(open(out_path).read())
    rows = rows if isinstance(rows, list) else rows["episodes"] + rows["campaigns"]
    assert len(rows) >= 1
    assert all(r["status"] == "ok" for r in rows), rows
    assert "Preflight ok" in captured.out
    assert "SECURITY FEEDBACK" in captured.out
    print(json.dumps(rows, indent=2))  # the scored row(s), for the CI log
