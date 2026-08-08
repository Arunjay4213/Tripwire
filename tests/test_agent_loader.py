"""Tests for load_agent_module() -- the `--agent path/to/agent.py` BYO loader.

Writes real, minimal .py files to a tmp_path and loads them for real via
importlib (that's the actual behavior under test), rather than mocking the
import machinery.
"""

from __future__ import annotations

import pytest

from src.adapters.base import Adapter
from src.adapters.loader import load_agent_module


def test_missing_path_raises():
    with pytest.raises(ValueError, match="not found"):
        load_agent_module("/nonexistent/path/agent.py")


def test_loads_bare_run_function(tmp_path):
    agent_file = tmp_path / "my_agent.py"
    agent_file.write_text(
        "from src.adapters.base import NormalizedTrace\n"
        "def run(spec):\n"
        "    return NormalizedTrace(steps=[], final_output='ok')\n"
    )

    adapter = load_agent_module(str(agent_file))

    assert isinstance(adapter, Adapter)
    assert adapter.name == "my_agent"  # derived from the file stem
    trace = adapter.run(spec=None)
    assert trace.final_output == "ok"


def test_loads_adapter_object(tmp_path):
    agent_file = tmp_path / "my_object_agent.py"
    agent_file.write_text(
        "from src.adapters.base import NormalizedTrace\n"
        "class MyAdapter:\n"
        "    name = 'custom-name'\n"
        "    def run(self, spec):\n"
        "        return NormalizedTrace(steps=[], final_output='from object')\n"
        "adapter = MyAdapter()\n"
    )

    adapter = load_agent_module(str(agent_file))

    assert isinstance(adapter, Adapter)
    assert adapter.name == "custom-name"  # the object's own name, not the filename
    trace = adapter.run(spec=None)
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
        "from src.adapters.base import NormalizedTrace\n"
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
    assert adapter.run(spec=None).final_output == "from object"


def test_example_file_loads_and_satisfies_protocol(monkeypatch):
    """The documented example (examples/byo_agent_example.py) must actually
    load -- this is what a new user copies as a starting point."""
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("GROQ_BASE_URL", "https://example.invalid/v1")

    adapter = load_agent_module("examples/byo_agent_example.py")

    assert isinstance(adapter, Adapter)
    assert adapter.name == "byo_agent_example"
