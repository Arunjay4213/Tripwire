"""Tests for load_config error handling — the mistakes a fresh user makes.

Each bad config should raise ValueError with an actionable message (the CLI
turns these into a clean one-line error, not a traceback), and a valid config
should still load. Fully offline; a dummy provider key lets resolve_adapters
construct its client without a network call.
"""

import pytest

from tripwire.config.loader import load_config

_VALID = "models: [m]\nattacks: [direct]\nadapters: [raw_loop]\nseeds: [0]\n"


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


def test_non_mapping_top_level_raises_clear_error(tmp_path):
    with pytest.raises(ValueError, match="mapping"):
        load_config(_write(tmp_path, "- just\n- a\n- list\n"))


@pytest.mark.parametrize("missing", ["models", "attacks", "adapters", "seeds"])
def test_missing_required_key_names_the_key(tmp_path, missing):
    lines = [ln for ln in _VALID.splitlines() if not ln.startswith(f"{missing}:")]
    with pytest.raises(ValueError, match=missing):
        load_config(_write(tmp_path, "\n".join(lines) + "\n"))


@pytest.mark.parametrize("scalar_line", ["seeds: 5", "models: gpt-4o-mini"])
def test_scalar_where_list_expected_raises_clear_error(tmp_path, scalar_line):
    """A scalar where a list is required (e.g. `seeds: 5`) must fail at load
    with a clear message, not a cryptic TypeError deep in run_sweep."""
    key = scalar_line.split(":")[0]
    lines = [ln for ln in _VALID.splitlines() if not ln.startswith(f"{key}:")]
    text = "\n".join(lines) + f"\n{scalar_line}\n"
    with pytest.raises(ValueError, match="non-empty list"):
        load_config(_write(tmp_path, text))


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


# --- unknown keys --------------------------------------------------------------

@pytest.mark.parametrize(
    "line, suggestion",
    [("defense: [spotlighting]", "defenses"), ("scenario: [helpdesk]", "scenarios")],
)
def test_misspelled_top_level_key_raises_with_suggestion(tmp_path, line, suggestion):
    """Regression: `defense:` was silently ignored and the run measured the
    undefended baseline while being read as spotlighting results."""
    with pytest.raises(ValueError, match=f"Did you mean '{suggestion}'"):
        load_config(_write(tmp_path, _VALID + line + "\n"))


def test_misspelled_limits_key_raises_with_suggestion(tmp_path):
    text = _VALID + "limits:\n  campain_budget: 4\n"
    with pytest.raises(ValueError, match="Did you mean 'campaign_budget'"):
        load_config(_write(tmp_path, text))


def test_misspelled_defense_name_raises_with_suggestion(tmp_path):
    text = _VALID + "defenses: [spotlightng]\n"
    with pytest.raises(ValueError, match="Did you mean 'spotlighting'"):
        load_config(_write(tmp_path, text))


def test_misspelled_attack_is_caught_at_load_not_after_smoke(tmp_path):
    """The 2nd attack is dropped by --smoke, so it must be validated at load."""
    text = _VALID.replace("attacks: [direct]", "attacks: [direct, mundane_redirct]")
    with pytest.raises(ValueError, match="Did you mean 'mundane_redirect'"):
        load_config(_write(tmp_path, text))


# --- optional keys are type-checked ----------------------------------------------

@pytest.mark.parametrize(
    "extra, match",
    [
        ("limits: 5\n", "'limits' must be a mapping"),
        ("limits:\n  smoke: \"false\"\n", "smoke must be true or false"),
        ("limits:\n  campaign_budget: \"8\"\n", "campaign_budget must be an integer"),
        ("limits:\n  campaign_budget: 0\n", "campaign_budget must be an integer >= 1"),
        ("limits:\n  max_turns: 0\n", "max_turns must be an integer >= 1"),
        ("limits:\n  max_turns: true\n", "max_turns must be an integer"),
        ("defenses:\n", "'defenses' must be a non-empty list"),
        ("defenses: []\n", "'defenses' must be a non-empty list"),
        ("scenarios:\n", "'scenarios' must be a non-empty list"),
        ("scenarios: [invoice, 3]\n", "must list names as strings"),
        ("allowed_tools: send_email\n", "'allowed_tools' must be a non-empty list"),
        ("allowed_tools: [read_inbx]\n", "Did you mean 'read_inbox'"),
    ],
)
def test_bad_optional_values_raise_clear_errors(tmp_path, extra, match):
    with pytest.raises(ValueError, match=match):
        load_config(_write(tmp_path, _VALID + extra))


@pytest.mark.parametrize("seeds", ["['0']", "[-1]", "[true]", "[0, 0]", "[1.5]"])
def test_bad_seeds_raise(tmp_path, seeds):
    text = _VALID.replace("seeds: [0]", f"seeds: {seeds}")
    with pytest.raises(ValueError, match="seeds"):
        load_config(_write(tmp_path, text))


def test_limits_are_parsed_with_defaults(tmp_path):
    cfg = load_config(_write(tmp_path, _VALID))
    assert (cfg.smoke, cfg.campaign_budget, cfg.max_turns, cfg.max_tokens_per_run) == (
        False, 8, 5, None,
    )
    cfg = load_config(_write(tmp_path, _VALID + "limits:\n  max_turns: 7\n  smoke: true\n"))
    assert cfg.max_turns == 7
    assert cfg.smoke is True


def test_null_defense_entry_is_no_defense(tmp_path):
    cfg = load_config(_write(tmp_path, _VALID + "defenses: [null, spotlighting]\n"))
    assert [d.name for d in cfg.defenses] == ["no_defense", "spotlighting"]


# --- tool_filter is scenario-relative ------------------------------------------

_ALL_SCENARIOS = "scenarios: [invoice, helpdesk, calendar, expense]\n"


def _tool_filter(cfg):
    return next(d for d in cfg.defenses if d.name == "tool_filter")


def test_tool_filter_keeps_every_scenario_read_tool_and_drops_the_sink(tmp_path):
    cfg = load_config(_write(tmp_path, _VALID + _ALL_SCENARIOS + "defenses: [tool_filter]\n"))
    tf = _tool_filter(cfg)
    assert isinstance(tf.allowed_tools, frozenset)
    for scenario in cfg.scenarios:
        names = [t["function"]["name"] for t in tf.filter_tool_calls(scenario.tool_schemas())]
        assert names == [scenario.read_tool]
        assert tf.check_tool_call(scenario.read_tool, {})[0] is True
        assert tf.check_tool_call("send_email", {"to": "x", "body": "y"})[0] is False
    assert cfg.warnings == []


def test_explicit_allowlist_missing_a_read_tool_warns_but_keeps_it(tmp_path):
    text = _VALID + _ALL_SCENARIOS + "defenses: [tool_filter]\nallowed_tools: [read_inbox]\n"
    cfg = load_config(_write(tmp_path, text))
    tf = _tool_filter(cfg)
    assert tf.check_tool_call("read_ticket", {})[0] is True
    joined = "\n".join(cfg.warnings)
    for tool in ("read_ticket", "read_calendar", "read_document"):
        assert tool in joined
    assert "'read_inbox'" not in joined


def test_allowlisting_the_sink_warns(tmp_path):
    text = _VALID + "defenses: [tool_filter]\nallowed_tools: [read_inbox, send_email]\n"
    cfg = load_config(_write(tmp_path, text))
    assert any("leak-capable" in w for w in cfg.warnings)


def test_allowed_tools_without_tool_filter_warns(tmp_path):
    cfg = load_config(_write(tmp_path, _VALID + "allowed_tools: [read_inbox]\n"))
    assert any("no effect" in w for w in cfg.warnings)


@pytest.mark.parametrize(
    "path", ["tripwire/config/threat_model.example.yaml", "tripwire/config/ci.example.yaml"]
)
def test_example_configs_keep_the_read_tool_under_tool_filter(path):
    """Regression: allowed_tools: [read_inbox] stripped the read tool from
    helpdesk/calendar/expense, so those rows measured an agent that could not
    read the injection at all."""
    cfg = load_config(path)
    assert cfg.warnings == []
    tf = _tool_filter(cfg)
    for scenario in cfg.scenarios:
        offered = [t["function"]["name"] for t in tf.filter_tool_calls(scenario.tool_schemas())]
        assert scenario.read_tool in offered
        assert "send_email" not in offered
        assert tf.check_tool_call(scenario.read_tool, {})[0] is True


def test_max_concurrency_parsed_and_validated(tmp_path):
    from tripwire.config.loader import load_config

    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "models: [m]\nattacks: [direct]\nadapters: [raw_loop]\nseeds: [0]\n"
        "limits: {max_concurrency: 8}\n"
    )
    assert load_config(str(cfg)).max_concurrency == 8

    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "models: [m]\nattacks: [direct]\nadapters: [raw_loop]\nseeds: [0]\n"
        "limits: {max_concurrency: 0}\n"
    )
    import pytest
    with pytest.raises(ValueError, match="max_concurrency"):
        load_config(str(bad))


# --- outbound_guard options -------------------------------------------------------

def test_outbound_guard_fail_closed_is_the_default_and_configurable(tmp_path):
    base = "models: [m]\nattacks: [direct]\nadapters: [raw_loop]\nseeds: [0]\ndefenses: [outbound_guard]\n"
    cfg = tmp_path / "default.yaml"
    cfg.write_text(base)
    assert load_config(str(cfg)).defenses[0].fail_closed is True

    cfg.write_text(base + "outbound_guard:\n  fail_closed: false\n")
    config = load_config(str(cfg))
    assert config.guard_fail_closed is False
    assert config.defenses[0].fail_closed is False


@pytest.mark.parametrize("block, match", [
    ("outbound_guard: yes\n", "must be a mapping"),
    ("outbound_guard:\n  fail_closed: \"false\"\n", "must be true or false"),
    ("outbound_guard:\n  fail_open: true\n", "Unknown outbound_guard key"),
])
def test_bad_outbound_guard_options_raise_clear_errors(tmp_path, block, match):
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("models: [m]\nattacks: [direct]\nadapters: [raw_loop]\nseeds: [0]\n" + block)
    with pytest.raises(ValueError, match=match):
        load_config(str(cfg))


@pytest.mark.parametrize("key, line", [
    ("models", "models: [m, m]\nattacks: [direct]\nadapters: [raw_loop]\nseeds: [0]\n"),
    ("attacks", "models: [m]\nattacks: [direct, direct]\nadapters: [raw_loop]\nseeds: [0]\n"),
    ("adapters", "models: [m]\nattacks: [direct]\nadapters: [raw_loop, raw_loop]\nseeds: [0]\n"),
    ("scenarios", "models: [m]\nattacks: [direct]\nadapters: [raw_loop]\nseeds: [0]\nscenarios: [invoice, invoice]\n"),
    ("defenses", "models: [m]\nattacks: [direct]\nadapters: [raw_loop]\nseeds: [0]\ndefenses: [spotlighting, spotlighting]\n"),
])
def test_duplicate_entries_are_rejected_like_duplicate_seeds(tmp_path, key, line):
    """A repeated entry runs the same cell twice and doubles its n, which
    halves the Wilson interval for free."""
    cfg = tmp_path / "dup.yaml"
    cfg.write_text(line)
    with pytest.raises(ValueError, match=f"{key}.*more than once"):
        load_config(str(cfg))
