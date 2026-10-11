"""Tests for `tripwire init` -- writes a starter config a fresh install can run."""

from __future__ import annotations

import os

import dotenv.main
import pytest
import yaml

import tripwire.__main__ as cli
from tripwire.__main__ import STARTER_CONFIG, _init_command
from tripwire.harness.runner import CampaignResult, EpisodeResult


def test_init_writes_a_config_that_loads(tmp_path, monkeypatch):
    dest = tmp_path / "threat_model.yaml"
    _init_command([str(dest)])
    assert dest.exists()

    data = yaml.safe_load(dest.read_text())
    for key in ("models", "adapters", "scenarios", "attacks", "defenses", "seeds"):
        assert key in data, key

    # and it resolves through the real config loader
    monkeypatch.setenv("OPENAI_API_KEY", "dummy")
    from tripwire.config.loader import load_config
    cfg = load_config(str(dest))
    assert [s.name for s in cfg.scenarios] == ["invoice", "helpdesk", "calendar", "expense"]
    assert "mundane_redirect" in cfg.attacks
    # --smoke runs the first attack, so the starter must lead with a strong one
    # (not the weak `direct` baseline) to show a real signal.
    assert cfg.attacks[0] == "metadata_exfil"


def test_init_refuses_overwrite_without_force(tmp_path):
    dest = tmp_path / "c.yaml"
    _init_command([str(dest)])
    with pytest.raises(SystemExit):
        _init_command([str(dest)])          # exists -> error
    _init_command([str(dest), "--force"])   # --force overwrites
    assert dest.read_text() == STARTER_CONFIG


# --- the sweep CLI (main) --------------------------------------------------------

_CFG = "models: [m]\nattacks: [direct]\nadapters: [raw_loop]\nseeds: [0, 1]\n"


def _ok(seed: int = 0) -> EpisodeResult:
    return EpisodeResult(adapter="raw_loop", model="m", attack="direct", seed=seed, succeeded=False)


def _err(seed: int = 0) -> EpisodeResult:
    return EpisodeResult(
        adapter="raw_loop", model="m", attack="direct", seed=seed, succeeded=False,
        status="error", error="NotFoundError: model 'm' does not exist",
    )


def _run_main(tmp_path, monkeypatch, sweep_result, *extra_args: str) -> int:
    """Run main() on a valid config with run_sweep replaced; return the exit code."""
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(_CFG)
    monkeypatch.setattr(cli, "run_sweep", lambda *a, **k: sweep_result)
    monkeypatch.setattr(
        "sys.argv",
        ["tripwire", "--config", str(cfg), "--output", str(tmp_path / "r.json"), *extra_args],
    )
    try:
        cli.main()
    except SystemExit as e:
        return int(e.code or 0)
    return 0


def test_zero_episodes_exits_2(tmp_path, monkeypatch, capsys):
    """Regression: an empty sweep wrote [] and exited 0, a green run that measured nothing."""
    assert _run_main(tmp_path, monkeypatch, ([], [])) == cli.EXIT_NOTHING_SCORED
    assert "nothing was scored" in capsys.readouterr().err


def test_all_episodes_errored_exits_2_and_shows_the_error(tmp_path, monkeypatch, capsys):
    code = _run_main(tmp_path, monkeypatch, ([_err(0), _err(1)], []))
    assert code == cli.EXIT_NOTHING_SCORED
    err = capsys.readouterr().err
    assert "does not exist" in err
    assert (tmp_path / "r.json").exists()  # errors are still written for inspection


def test_all_campaigns_errored_exits_2(tmp_path, monkeypatch):
    campaign = CampaignResult(
        adapter="raw_loop", model="m", attack="iterative", seed=0, broke=False,
        attempts_to_break=None, budget=8, status="error", error="boom",
    )
    assert _run_main(tmp_path, monkeypatch, ([], [campaign])) == cli.EXIT_NOTHING_SCORED


def test_partial_errors_warn_and_exit_0(tmp_path, monkeypatch, capsys):
    assert _run_main(tmp_path, monkeypatch, ([_ok(0), _err(1)], [])) == 0
    assert "WARNING: 1 of 2" in capsys.readouterr().err


def test_partial_errors_exit_3_under_strict(tmp_path, monkeypatch):
    code = _run_main(tmp_path, monkeypatch, ([_ok(0), _err(1)], []), "--strict")
    assert code == cli.EXIT_ERRORS_STRICT


def test_clean_sweep_exits_0_even_under_strict(tmp_path, monkeypatch):
    assert _run_main(tmp_path, monkeypatch, ([_ok(0), _ok(1)], []), "--strict") == 0


def test_max_turns_from_config_reaches_run_sweep(tmp_path, monkeypatch):
    seen = {}

    def fake_sweep(*args, **kwargs):
        seen.update(kwargs)
        return [_ok()], []

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(_CFG + "limits:\n  max_turns: 9\n")
    monkeypatch.setattr(cli, "run_sweep", fake_sweep)
    monkeypatch.setattr("sys.argv", ["tripwire", "--config", str(cfg), "--output", str(tmp_path / "r.json")])
    cli.main()
    assert seen["max_turns"] == 9


@pytest.mark.parametrize("exc", [TypeError("bad shape"), AttributeError("no attr")])
def test_unexpected_config_shape_is_a_one_line_error(tmp_path, monkeypatch, capsys, exc):
    def boom(_path):
        raise exc

    monkeypatch.setattr(cli, "load_config", boom)
    code = _run_main(tmp_path, monkeypatch, ([], []))
    assert code == cli.EXIT_CONFIG_ERROR
    err = capsys.readouterr().err
    assert err.startswith("Error: ") and "Traceback" not in err


def test_config_warnings_are_printed(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(_CFG + "allowed_tools: [read_inbox]\n")
    monkeypatch.setattr(cli, "run_sweep", lambda *a, **k: ([_ok()], []))
    monkeypatch.setattr("sys.argv", ["tripwire", "--config", str(cfg), "--output", str(tmp_path / "r.json")])
    cli.main()
    assert "Warning: allowed_tools is set but" in capsys.readouterr().err


# --- preflight -------------------------------------------------------------------

class _FakeCompletions:
    def __init__(self, fail_on: str | None) -> None:
        self.fail_on = fail_on
        self.models: list[str] = []

    def create(self, *, model, messages, **_kw):
        self.models.append(model)
        if model == self.fail_on:
            raise RuntimeError(f"The model `{model}` does not exist")
        return object()


class _FakeClient:
    def __init__(self, fail_on: str | None = None) -> None:
        self.chat = type("Chat", (), {})()
        self.chat.completions = _FakeCompletions(fail_on)


def test_preflight_fails_fast_on_unknown_model(tmp_path, monkeypatch, capsys):
    client = _FakeClient(fail_on="m")
    monkeypatch.setattr(cli, "make_client", lambda: client)
    swept = []
    monkeypatch.setattr(cli, "run_sweep", lambda *a, **k: swept.append(1) or ([_ok()], []))
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(_CFG)
    monkeypatch.setattr(
        "sys.argv", ["tripwire", "--config", str(cfg), "--output", str(tmp_path / "r.json"), "--preflight"]
    )
    with pytest.raises(SystemExit) as info:
        cli.main()
    assert info.value.code == cli.EXIT_CONFIG_ERROR
    assert swept == []  # the sweep never started
    assert "preflight call to model 'm' failed" in capsys.readouterr().err


def test_preflight_calls_each_model_once_then_sweeps(tmp_path, monkeypatch):
    client = _FakeClient()
    monkeypatch.setattr(cli, "make_client", lambda: client)
    code = _run_main(tmp_path, monkeypatch, ([_ok()], []), "--preflight")
    assert code == 0
    assert client.chat.completions.models == ["m"]


def test_no_preflight_by_default(tmp_path, monkeypatch):
    def no_client():
        raise AssertionError("preflight must be opt-in")

    monkeypatch.setattr(cli, "make_client", no_client)
    assert _run_main(tmp_path, monkeypatch, ([_ok()], [])) == 0


# --- .env discovery --------------------------------------------------------------

def test_env_file_is_found_from_the_working_directory(tmp_path, monkeypatch):
    """Regression: plain load_dotenv() searched upward from the package
    directory, so a pip-installed tripwire never saw the user's ./.env."""
    (tmp_path / ".env").write_text("TRIPWIRE_TEST_DOTENV_MARKER=found\n")
    workdir = tmp_path / "sub"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    monkeypatch.delenv("PYTHON_DOTENV_DISABLED", raising=False)
    monkeypatch.setattr(cli, "load_dotenv", dotenv.main.load_dotenv)  # undo conftest's no-op
    try:
        cli._load_env_file()
        assert os.environ.get("TRIPWIRE_TEST_DOTENV_MARKER") == "found"
    finally:
        os.environ.pop("TRIPWIRE_TEST_DOTENV_MARKER", None)
