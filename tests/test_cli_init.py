"""Tests for `tripwire init` -- writes a starter config a fresh install can run."""

from __future__ import annotations

import pytest
import yaml

from tripwire.__main__ import STARTER_CONFIG, _init_command


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
