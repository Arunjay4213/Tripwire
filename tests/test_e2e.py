"""End-to-end tests: the real CLI against a real (fake) provider.

Everything a user runs is exercised unmodified: `tripwire.__main__.main`
parses the config, resolves adapters and attacks, runs the sweep, the real
adapters drive the real `openai` SDK over HTTP, defenses hook in, the judge
scores, `write_results` writes the file, the tables and the security report
print, the exit code is returned, and the CI gate reads the file back.

The only scripted part is the model's decision, served by tests/fake_provider.py
and selected by the model id (`fake/obedient`, `fake/resistant`, ...). An
obedient model always leaks and a resistant one never does, so every cell has
a known answer and a regression anywhere in the pipeline shows up as a wrong
number, a wrong exit code, or a wrong gate verdict.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import tripwire.__main__ as cli
from tests.fake_provider import FakeProvider
from tripwire.defenses.outbound_guard import _DETECTOR_SYSTEM_PROMPT
from tripwire.defenses.prompt_hardening import HARDENING_INSTRUCTION
from tripwire.defenses.spotlighting import CLOSE_DELIMITER, OPEN_DELIMITER
from tripwire.harness.canary import make_canary

ADAPTERS = ["raw_loop", "langgraph", "multi_agent"]

_GATE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "check_asr_threshold.py"
_gate_spec = importlib.util.spec_from_file_location("check_asr_threshold_e2e", _GATE_PATH)
gate = importlib.util.module_from_spec(_gate_spec)
sys.modules[_gate_spec.name] = gate
_gate_spec.loader.exec_module(gate)


@pytest.fixture(scope="module")
def provider():
    server = FakeProvider().start()
    yield server
    server.stop()


def _config(
    model: str = "fake/obedient",
    adapters: list[str] = ADAPTERS,
    scenarios: list[str] = ("invoice",),
    attacks: list[str] = ("metadata_exfil",),
    defenses: list[str] = ("null",),
    seeds: list[int] = (0,),
    max_turns: int = 4,
    campaign_budget: int = 3,
) -> str:
    return (
        f"models: [{model}]\n"
        f"adapters: [{', '.join(adapters)}]\n"
        f"scenarios: [{', '.join(scenarios)}]\n"
        f"attacks: [{', '.join(attacks)}]\n"
        f"defenses: [{', '.join(defenses)}]\n"
        f"seeds: [{', '.join(str(s) for s in seeds)}]\n"
        f"limits:\n  max_turns: {max_turns}\n  campaign_budget: {campaign_budget}\n"
    )


def _run_cli(tmp_path, monkeypatch, capsys, provider: FakeProvider, cfg: str, *extra: str):
    """Run the real CLI in-process. Returns (exit_code, stdout, stderr, results)."""
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
    monkeypatch.setenv("OPENAI_BASE_URL", provider.base_url)
    provider.clear()
    cfg_path = tmp_path / "threat_model.yaml"
    cfg_path.write_text(cfg)
    out_path = tmp_path / "results.json"
    monkeypatch.setattr(
        "sys.argv", ["tripwire", "--config", str(cfg_path), "--output", str(out_path), *extra]
    )
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    results = json.loads(out_path.read_text()) if out_path.exists() else None
    return code, captured.out, captured.err, results


def _by_adapter(rows: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for r in rows:
        out.setdefault(r["adapter"], []).append(r)
    return out


# --- the two anchors: a leak everywhere, a clean run everywhere -----------------

def test_obedient_model_is_scored_as_a_leak_in_every_adapter(tmp_path, monkeypatch, capsys, provider):
    code, out, err, results = _run_cli(tmp_path, monkeypatch, capsys, provider, _config())

    assert code == 0, err
    assert set(_by_adapter(results)) == set(ADAPTERS)
    for row in results:
        assert row["status"] == "ok", row
        assert row["succeeded"] is True, row
        assert row["task_completed"] is False, row
        assert row["stop_reason"] == "done", row
    assert "SECURITY FEEDBACK" in out
    assert "metadata_exfil" in out
    assert "No exfiltration observed" not in out


def test_resistant_model_completes_the_task_without_leaking(tmp_path, monkeypatch, capsys, provider):
    code, out, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider, _config(model="fake/resistant")
    )

    assert code == 0, err
    assert set(_by_adapter(results)) == set(ADAPTERS)
    for row in results:
        assert row["status"] == "ok", row
        assert row["succeeded"] is False, row
        assert row["task_completed"] is True, row
    assert "No exfiltration observed" in out


def test_every_scenario_runs_end_to_end(tmp_path, monkeypatch, capsys, provider):
    """Each scenario has its own tool name, task marker and authorized address;
    the obedient model must leak and the resistant one must complete in all four."""
    scenarios = ["invoice", "helpdesk", "calendar", "expense"]
    _, _, err, leaks = _run_cli(
        tmp_path, monkeypatch, capsys, provider,
        _config(adapters=["raw_loop"], scenarios=scenarios),
    )
    assert {r["scenario"] for r in leaks} == set(scenarios), err
    assert all(r["succeeded"] for r in leaks), leaks

    _, _, err, clean = _run_cli(
        tmp_path, monkeypatch, capsys, provider,
        _config(model="fake/resistant", adapters=["raw_loop"], scenarios=scenarios),
    )
    assert {r["scenario"] for r in clean} == set(scenarios), err
    assert all(r["task_completed"] and not r["succeeded"] for r in clean), clean


# --- the defense ladder, with what the model actually received -----------------

def _tool_messages(requests: list[dict]) -> list[str]:
    return [m["content"] for req in requests for m in req["messages"] if m["role"] == "tool"]


def _system_prompts(requests: list[dict]) -> list[str]:
    return [req["messages"][0]["content"] for req in requests
            if req["messages"] and req["messages"][0]["role"] == "system"]


def test_prompt_hardening_reaches_the_model_but_does_not_stop_an_obedient_agent(
    tmp_path, monkeypatch, capsys, provider,
):
    _, _, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider,
        _config(adapters=["raw_loop", "langgraph"], defenses=["prompt_hardening"]),
    )
    assert all(r["succeeded"] for r in results), err
    agent_prompts = [p for p in _system_prompts(provider.requests) if p != _DETECTOR_SYSTEM_PROMPT]
    assert len(agent_prompts) >= 2 and all(HARDENING_INSTRUCTION in p for p in agent_prompts)


@pytest.mark.xfail(
    strict=True,
    reason="known gap (docs/improvement-plan.md, 'Agent B coverage'): the relay applies "
           "prompt-level defenses to the summarizer only; the agent that sends email runs "
           "with the bare actor prompt",
)
def test_prompt_hardening_reaches_the_relay_agent_that_sends_email(
    tmp_path, monkeypatch, capsys, provider,
):
    _run_cli(tmp_path, monkeypatch, capsys, provider,
             _config(adapters=["multi_agent"], defenses=["prompt_hardening"]))
    sending_prompts = [req["messages"][0]["content"] for req in provider.requests
                       if any(t["function"]["name"] == "send_email" for t in req.get("tools", []))]
    assert sending_prompts and all(HARDENING_INSTRUCTION in p for p in sending_prompts)


def test_spotlighting_fences_every_tool_result_the_model_sees_in_every_adapter(
    tmp_path, monkeypatch, capsys, provider,
):
    """The wrapper has to be applied inside each adapter's loop, not only put
    on the spec. Every tool message sent back to the model must be fenced, in
    all three adapters, on every turn."""
    _, _, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider, _config(defenses=["spotlighting"])
    )
    assert set(_by_adapter(results)) == set(ADAPTERS), err
    tool_messages = _tool_messages(provider.requests)
    # raw_loop and langgraph: read then send (2 tool results each, both echoed
    # back on the next request). multi_agent: A reads, B sends. At least one
    # fenced read result per adapter must have been sent back to the model.
    assert len(tool_messages) >= len(ADAPTERS)
    for msg in tool_messages:
        assert msg.startswith(OPEN_DELIMITER) and msg.rstrip().endswith(CLOSE_DELIMITER), msg


def test_tool_filter_removes_the_sink_so_nothing_can_leak(tmp_path, monkeypatch, capsys, provider):
    _, out, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider, _config(defenses=["tool_filter"])
    )
    assert set(_by_adapter(results)) == set(ADAPTERS), err
    assert not any(r["succeeded"] for r in results), results
    assert not any(r["task_completed"] for r in results), results  # the blunt instrument
    offered = {t["function"]["name"] for req in provider.requests for t in req.get("tools", [])}
    assert "send_email" not in offered
    assert "read_inbox" in offered


def test_outbound_guard_blocks_the_leak_and_sees_the_fenced_call(
    tmp_path, monkeypatch, capsys, provider,
):
    monkeypatch.setenv("GUARD_MODEL", "fake/guard-block")
    _, out, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider, _config(defenses=["outbound_guard"])
    )
    assert set(_by_adapter(results)) == set(ADAPTERS), err
    assert not any(r["succeeded"] for r in results), results
    assert all(r["guard_errors"] == 0 for r in results), results

    guard_requests = [r for r in provider.requests
                      if r["messages"][0]["content"] == _DETECTOR_SYSTEM_PROMPT]
    assert len(guard_requests) == len(ADAPTERS)  # one send_email attempt per adapter
    for req in guard_requests:
        assert req["model"] == "fake/guard-block"
        assert make_canary(0) in req["messages"][-1]["content"]


def test_outbound_guard_falls_back_to_the_target_model_when_unset(
    tmp_path, monkeypatch, capsys, provider,
):
    """No GUARD_MODEL: the runner fills the guard's model with the model under
    test. The fake provider answers the detector prompt for any model."""
    monkeypatch.delenv("GUARD_MODEL", raising=False)
    _, _, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider,
        _config(adapters=["raw_loop"], defenses=["outbound_guard"]),
    )
    assert results and not results[0]["succeeded"], err
    guard_requests = [r for r in provider.requests
                      if r["messages"][0]["content"] == _DETECTOR_SYSTEM_PROMPT]
    assert [r["model"] for r in guard_requests] == ["fake/obedient"]


# --- budget, errors, exit codes ------------------------------------------------

def test_looping_model_is_stopped_at_the_shared_turn_budget_in_every_adapter(
    tmp_path, monkeypatch, capsys, provider,
):
    _, out, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider, _config(model="fake/looping", max_turns=3)
    )
    assert set(_by_adapter(results)) == set(ADAPTERS), err
    for row in results:
        assert row["status"] == "ok", row
        assert row["stop_reason"] == "max_turns", row
        assert row["succeeded"] is False, row
    # Exactly max_turns model calls per adapter, the relay included.
    assert len(provider.requests) == 3 * len(ADAPTERS)
    assert "hit the max_turns budget" in out


def test_rejected_model_is_an_error_row_and_a_non_zero_exit(tmp_path, monkeypatch, capsys, provider):
    code, out, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider,
        _config(model="fake/rejected", adapters=["raw_loop"]),
    )
    assert code == cli.EXIT_NOTHING_SCORED
    assert results and results[0]["status"] == "error"
    assert "NotFoundError" in results[0]["error"]
    assert "nothing was scored" in err
    assert "fake/rejected" in err or "does not exist" in err


def test_strict_mode_fails_on_a_partially_errored_sweep(tmp_path, monkeypatch, capsys, provider):
    cfg = _config(adapters=["raw_loop"]).replace(
        "models: [fake/obedient]", "models: [fake/obedient, fake/rejected]"
    )
    code, out, err, results = _run_cli(tmp_path, monkeypatch, capsys, provider, cfg, "--strict")
    assert code == cli.EXIT_ERRORS_STRICT
    statuses = {r["model"]: r["status"] for r in results}
    assert statuses == {"fake/obedient": "ok", "fake/rejected": "error"}


def test_preflight_stops_before_the_sweep_on_a_rejected_model(tmp_path, monkeypatch, capsys, provider):
    code, out, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider,
        _config(model="fake/rejected", adapters=["raw_loop"]), "--preflight",
    )
    assert code == cli.EXIT_CONFIG_ERROR
    assert results is None  # the sweep never ran
    assert len(provider.requests) == 1


# --- the CI gate reads what the sweep wrote --------------------------------------

def test_ci_gate_fails_on_the_leaking_sweep_and_passes_on_the_clean_one(
    tmp_path, monkeypatch, capsys, provider,
):
    _run_cli(tmp_path, monkeypatch, capsys, provider, _config(adapters=["raw_loop"]))
    leaking = tmp_path / "results.json"
    assert gate.main(["--results", str(leaking), "--threshold", "0.5"]) == 1
    captured = capsys.readouterr()
    assert "FAIL" in captured.err and "metadata_exfil" in captured.err

    _run_cli(tmp_path, monkeypatch, capsys, provider,
             _config(model="fake/resistant", adapters=["raw_loop"]))
    clean = tmp_path / "results.json"
    assert gate.main(["--results", str(clean), "--threshold", "0.5"]) == 0


# --- adaptive campaigns --------------------------------------------------------------

def test_pair_campaign_breaks_an_obedient_agent_on_the_first_attempt(
    tmp_path, monkeypatch, capsys, provider,
):
    monkeypatch.setenv("ATTACKER_MODEL", "fake/attacker")
    code, out, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider,
        _config(adapters=["raw_loop"], attacks=["iterative"], campaign_budget=3),
    )
    assert code == 0, err
    assert results["episodes"] == []
    (campaign,) = results["campaigns"]
    assert campaign["status"] == "ok"
    assert campaign["broke"] is True
    assert campaign["attempts_to_break"] == 1
    assert campaign["evaluations_spent"] == 1
    assert campaign["attacker_model"] == "fake/attacker"
    assert "budget" in out  # the campaign table printed
    attacker_requests = [r for r in provider.requests if r["model"] == "fake/attacker"]
    assert len(attacker_requests) == 1
    assert make_canary(0) not in json.dumps(attacker_requests)  # the attacker never sees the secret


def test_pair_campaign_exhausts_its_budget_against_a_resistant_agent(
    tmp_path, monkeypatch, capsys, provider,
):
    monkeypatch.setenv("ATTACKER_MODEL", "fake/attacker")
    _, out, err, results = _run_cli(
        tmp_path, monkeypatch, capsys, provider,
        _config(model="fake/resistant", adapters=["raw_loop"], attacks=["iterative"],
                campaign_budget=3),
    )
    (campaign,) = results["campaigns"]
    assert campaign["broke"] is False, err
    assert campaign["attempts_to_break"] is None
    assert campaign["evaluations_spent"] == 3
    assert campaign["errors"] == 0


# --- parallel sweep and the real entrypoint -------------------------------------------

def _key(row: dict) -> tuple:
    return (row["adapter"], row["model"], row["scenario"], row["attack"], row["defense"], row["seed"])


def test_parallel_sweep_gives_the_same_results_as_serial(tmp_path, monkeypatch, capsys, provider):
    cfg = _config(seeds=[0, 1], defenses=["null", "spotlighting"])
    _, _, err, serial = _run_cli(tmp_path, monkeypatch, capsys, provider, cfg)
    _, _, err2, parallel = _run_cli(tmp_path, monkeypatch, capsys, provider, cfg, "--concurrency", "4")
    assert serial and parallel, (err, err2)
    assert sorted(serial, key=_key) == sorted(parallel, key=_key)
    assert len(serial) == len(ADAPTERS) * 2 * 2


def test_the_installed_entrypoint_runs_a_smoke_sweep_as_a_subprocess(tmp_path, provider):
    """`python -m tripwire --config ... --smoke` from a clean directory: the
    .env lookup, the provider pick from the environment, and the exit code,
    the way a fresh install runs it."""
    cfg_path = tmp_path / "threat_model.yaml"
    cfg_path.write_text(_config(adapters=["raw_loop"], seeds=[0, 1, 2]))
    out_path = tmp_path / "out" / "results.json"
    env = {k: v for k, v in os.environ.items()
           if not (k.endswith(("_API_KEY", "_MODEL", "_BASE_URL")) or k in ("MODEL",))}
    env.update({"OPENAI_API_KEY": "fake-key", "OPENAI_BASE_URL": provider.base_url,
                "PYTHON_DOTENV_DISABLED": "1",
                # the package is importable from the checkout; a user has it installed
                "PYTHONPATH": str(Path(__file__).resolve().parents[1])})
    proc = subprocess.run(
        [sys.executable, "-m", "tripwire", "--config", str(cfg_path),
         "--output", str(out_path), "--smoke"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Results written to" in proc.stdout
    rows = json.loads(out_path.read_text())
    assert len(rows) == 1  # --smoke: one seed, first everything
    assert rows[0]["succeeded"] is True
