"""Isolate the test suite from the developer's real environment and .env.

The suite is meant to be fully offline and deterministic, but the harness reads
provider keys, base URLs and model ids from the environment (tripwire/harness/
llm.py) and several modules call load_dotenv(). Without this file a developer
with ANTHROPIC_MODEL or OPENAI_BASE_URL in their shell or .env gets different
results than CI. So:

  - At import time (before any test module imports tripwire) .env loading is
    disabled and dotenv.load_dotenv becomes a no-op, so import-time
    load_dotenv() calls in adapters and examples cannot pull a real .env in.
  - Before every test, every *_API_KEY / *_MODEL / *_BASE_URL variable plus
    MODEL / ATTACKER_MODEL / GUARD_MODEL is removed and a dummy
    OPENAI_API_KEY is set, so client construction works without a network.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import dotenv
import pytest

_SUFFIXES = ("_API_KEY", "_MODEL", "_BASE_URL")
_EXACT = ("MODEL", "ATTACKER_MODEL", "GUARD_MODEL")
_DUMMY_KEY = "test-key-not-real"


def _noop_load_dotenv(*_args: Any, **_kwargs: Any) -> bool:
    return False


def _is_provider_var(name: str) -> bool:
    return name in _EXACT or name.endswith(_SUFFIXES)


# python-dotenv honors this switch in load_dotenv itself (a second safety net
# for any copy of the function bound before this file ran).
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
dotenv.load_dotenv = _noop_load_dotenv  # type: ignore[assignment]
for _name in [n for n in os.environ if _is_provider_var(n)]:
    del os.environ[_name]
os.environ["OPENAI_API_KEY"] = _DUMMY_KEY


@pytest.fixture(autouse=True)
def _isolated_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in [n for n in os.environ if _is_provider_var(n)]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", _DUMMY_KEY)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")

    # Modules that did `from dotenv import load_dotenv` hold their own
    # reference; replace it wherever a tripwire (or example) module has one.
    monkeypatch.setattr(dotenv, "load_dotenv", _noop_load_dotenv)
    for module_name, module in list(sys.modules.items()):
        if module is None or not module_name.startswith(("tripwire", "examples")):
            continue
        if getattr(module, "load_dotenv", None) is not None:
            monkeypatch.setattr(module, "load_dotenv", _noop_load_dotenv)
