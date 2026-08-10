"""Tests for load_config error handling — the mistakes a fresh user makes.

Each bad config should raise ValueError with an actionable message (the CLI
turns these into a clean one-line error, not a traceback), and a valid config
should still load. Fully offline; a dummy provider key lets resolve_adapters
construct its client without a network call.
"""

import pytest

from tripwire.config.loader import load_config

_VALID = "models: [m]\nsuites: [x]\nattacks: [direct]\nadapters: [raw_loop]\nseeds: [0]\n"


def _write(tmp_path, text: str) -> str:
    p = tmp_path / "cfg.yaml"
    p.write_text(text)
    return str(p)


def test_missing_config_file_raises_clear_error():
    with pytest.raises(ValueError, match="not found"):
        load_config("/no/such/config.yaml")


def test_empty_config_file_raises_clear_error(tmp_path):
    with pytest.raises(ValueError, match="empty"):
        load_config(_write(tmp_path, ""))


def test_comment_only_config_is_treated_as_empty(tmp_path):
    with pytest.raises(ValueError, match="empty"):
        load_config(_write(tmp_path, "# just a comment\n"))


def test_non_mapping_top_level_raises_clear_error(tmp_path):
    with pytest.raises(ValueError, match="mapping"):
        load_config(_write(tmp_path, "- just\n- a\n- list\n"))


@pytest.mark.parametrize("missing", ["models", "suites", "attacks", "adapters", "seeds"])
def test_missing_required_key_names_the_key(tmp_path, missing):
    lines = [ln for ln in _VALID.splitlines() if not ln.startswith(f"{missing}:")]
    with pytest.raises(ValueError, match=missing):
        load_config(_write(tmp_path, "\n".join(lines) + "\n"))


def test_unknown_adapter_name_raises_value_error(tmp_path):
    text = _VALID.replace("adapters: [raw_loop]", "adapters: [nope]")
    with pytest.raises(ValueError, match="Unknown adapter"):
        load_config(_write(tmp_path, text))


def test_valid_config_loads(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "dummy")
    cfg = load_config(_write(tmp_path, _VALID))
    assert cfg.models == ["m"]
    assert cfg.attacks == ["direct"]
    assert [a.name for a in cfg.adapters] == ["raw_loop"]
