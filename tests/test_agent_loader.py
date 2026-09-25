"""Tests for load_agent_module() -- the `--agent path/to/agent.py` BYO loader.

Writes real, minimal .py files to a tmp_path and loads them for real via
importlib (that's the actual behavior under test), rather than mocking the
import machinery.
"""

from __future__ import annotations

import sys

import pytest

from tripwire.adapters.base import Adapter, EpisodeSpec, NormalizedTrace, TraceStep
from tripwire.adapters.loader import HookAuditingAdapter, load_agent_module
from tripwire.defenses.base import NoDefense
from tripwire.defenses.spotlighting import Spotlighting
from tripwire.defenses.tool_filter import ToolFilter


def _spec(defense=None) -> EpisodeSpec:
    """A minimal real EpisodeSpec. With a defense, its hooks are bound methods,
    exactly as Scenario.build_spec passes them."""
    return EpisodeSpec(
        task={}, tools=[], model="m", environment_seed=0,
        tool_call_guard=defense.check_tool_call if defense else None,
        tool_result_wrapper=defense.wrap_tool_result if defense else None,
    )


def test_missing_path_raises():
    with pytest.raises(ValueError, match="not found"):
        load_agent_module("/nonexistent/path/agent.py")


def test_loads_bare_run_function(tmp_path):
    agent_file = tmp_path / "my_agent.py"
    agent_file.write_text(
        "from tripwire.adapters.base import NormalizedTrace\n"
        "def run(spec):\n"
        "    return NormalizedTrace(steps=[], final_output='ok')\n"
    )

    adapter = load_agent_module(str(agent_file))

    assert isinstance(adapter, Adapter)
    assert adapter.name == "my_agent"  # derived from the file stem
    trace = adapter.run(spec=_spec())
    assert trace.final_output == "ok"


def test_loads_adapter_object(tmp_path):
    agent_file = tmp_path / "my_object_agent.py"
    agent_file.write_text(
        "from tripwire.adapters.base import NormalizedTrace\n"
        "class MyAdapter:\n"
        "    name = 'custom-name'\n"
        "    def run(self, spec):\n"
        "        return NormalizedTrace(steps=[], final_output='from object')\n"
        "adapter = MyAdapter()\n"
    )

    adapter = load_agent_module(str(agent_file))

    assert isinstance(adapter, Adapter)
    assert adapter.name == "custom-name"  # the object's own name, not the filename
    trace = adapter.run(spec=_spec())
    assert trace.final_output == "from object"


def test_adapter_object_not_satisfying_protocol_raises(tmp_path):
    agent_file = tmp_path / "bad_agent.py"
    agent_file.write_text(
        "class NotAnAdapter:\n"
        "    pass\n"
        "adapter = NotAnAdapter()\n"
    )

    with pytest.raises(ValueError, match="does not satisfy the Adapter protocol"):
        load_agent_module(str(agent_file))


def test_module_with_neither_adapter_nor_run_raises(tmp_path):
    agent_file = tmp_path / "empty_agent.py"
    agent_file.write_text("x = 1\n")

    with pytest.raises(ValueError, match="must define either"):
        load_agent_module(str(agent_file))


def test_adapter_object_takes_priority_over_run(tmp_path):
    """If a module defines both, `adapter` wins -- it's the more specific form."""
    agent_file = tmp_path / "both.py"
    agent_file.write_text(
        "from tripwire.adapters.base import NormalizedTrace\n"
        "def run(spec):\n"
        "    return NormalizedTrace(steps=[], final_output='from function')\n"
        "class MyAdapter:\n"
        "    name = 'object-wins'\n"
        "    def run(self, spec):\n"
        "        return NormalizedTrace(steps=[], final_output='from object')\n"
        "adapter = MyAdapter()\n"
    )

    adapter = load_agent_module(str(agent_file))

    assert adapter.name == "object-wins"
    assert adapter.run(spec=_spec()).final_output == "from object"


def test_example_file_loads_and_satisfies_protocol(monkeypatch):
    """The documented example (examples/byo_agent_example.py) must actually
    load -- this is what a new user copies as a starting point."""
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("GROQ_BASE_URL", "https://example.invalid/v1")

    adapter = load_agent_module("examples/byo_agent_example.py")

    assert isinstance(adapter, Adapter)
    assert adapter.name == "byo_agent_example"


def test_my_agent_example_loads_and_satisfies_protocol(monkeypatch):
    """The other documented example (examples/my_agent.py) uses the `adapter`
    object form over a LangGraph loop. Construction makes no LLM call, so this
    stays offline; a dummy provider key satisfies the client constructor."""
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("GROQ_BASE_URL", "https://example.invalid/v1")

    adapter = load_agent_module("examples/my_agent.py")

    assert isinstance(adapter, Adapter)
    assert isinstance(adapter.name, str) and adapter.name


def test_dataclass_with_future_annotations_loads(tmp_path):
    """Regression: the module was never put in sys.modules, so dataclasses'
    string-annotation lookup (sys.modules[cls.__module__].__dict__) crashed
    with AttributeError for this repo's own style of file."""
    agent_file = tmp_path / "dc_agent.py"
    agent_file.write_text(
        "from __future__ import annotations\n"
        "from dataclasses import dataclass\n"
        "from tripwire.adapters.base import NormalizedTrace\n"
        "@dataclass\n"
        "class Config:\n"
        "    a: int = 1\n"
        "def run(spec):\n"
        "    return NormalizedTrace(steps=[], final_output=str(Config().a))\n"
    )

    adapter = load_agent_module(str(agent_file))

    assert adapter.name == "dc_agent"
    assert adapter.run(_spec()).final_output == "1"
    assert "tripwire_byo_dc_agent" in sys.modules


def test_failed_import_is_removed_from_sys_modules(tmp_path):
    agent_file = tmp_path / "broken_agent.py"
    agent_file.write_text("raise RuntimeError('boom')\n")

    with pytest.raises(RuntimeError, match="boom"):
        load_agent_module(str(agent_file))
    assert "tripwire_byo_broken_agent" not in sys.modules


def test_adapter_class_instead_of_instance_raises(tmp_path):
    agent_file = tmp_path / "class_agent.py"
    agent_file.write_text(
        "class MyAdapter:\n"
        "    name = 'x'\n"
        "    def run(self, spec):\n"
        "        return None\n"
        "adapter = MyAdapter\n"
    )
    with pytest.raises(ValueError, match="instantiate it"):
        load_agent_module(str(agent_file))


def test_non_callable_run_raises(tmp_path):
    agent_file = tmp_path / "run_int.py"
    agent_file.write_text("run = 5\n")
    with pytest.raises(ValueError, match="must be a function"):
        load_agent_module(str(agent_file))


# --- defense-hook auditing ----------------------------------------------------

_TOOL_TRACE = NormalizedTrace(
    steps=[
        TraceStep(step=0, type="tool_call", name="send_email", args={"to": "a@b.c", "body": "x"}),
        TraceStep(step=1, type="tool_result", name="send_email", content="email sent"),
    ],
    final_output="done",
)


class _IgnoresHooks:
    name = "ignores_hooks"

    def run(self, spec):
        return _TOOL_TRACE


class _HonorsHooks:
    name = "honors_hooks"

    def run(self, spec):
        allowed, _ = spec.tool_call_guard("send_email", {"to": "a@b.c", "body": "x"})
        spec.tool_result_wrapper("read_inbox", "content")
        return _TOOL_TRACE


def test_hook_audit_records_calls_and_stays_silent_when_honored(capsys):
    adapter = HookAuditingAdapter(_HonorsHooks())
    adapter.run(_spec(Spotlighting()))
    assert adapter.last_hooks_called == {"guard": True, "wrapper": True}
    assert "Warning" not in capsys.readouterr().err


def test_hook_audit_warns_once_when_guard_ignored(capsys):
    adapter = HookAuditingAdapter(_IgnoresHooks())
    adapter.run(_spec(ToolFilter(frozenset({"read_inbox"}))))
    adapter.run(_spec(ToolFilter(frozenset({"read_inbox"}))))

    assert adapter.last_hooks_called == {"guard": False, "wrapper": False}
    err = capsys.readouterr().err
    assert err.count("never called spec.tool_call_guard") == 1
    assert "tool_filter" in err


def test_hook_audit_quiet_under_no_defense(capsys):
    adapter = HookAuditingAdapter(_IgnoresHooks())
    adapter.run(_spec(NoDefense()))
    assert adapter.last_hooks_called == {"guard": False, "wrapper": False}
    assert capsys.readouterr().err == ""


def test_loaded_agent_is_audited_and_keeps_its_name(tmp_path):
    agent_file = tmp_path / "plain.py"
    agent_file.write_text(
        "from tripwire.adapters.base import NormalizedTrace\n"
        "def run(spec):\n"
        "    spec.tool_call_guard('send_email', {})\n"
        "    return NormalizedTrace(steps=[], final_output='ok')\n"
    )
    adapter = load_agent_module(str(agent_file))
    assert isinstance(adapter, HookAuditingAdapter)
    assert isinstance(adapter, Adapter)
    assert adapter.name == "plain"
    adapter.run(_spec(Spotlighting()))
    assert adapter.last_hooks_called["guard"] is True
