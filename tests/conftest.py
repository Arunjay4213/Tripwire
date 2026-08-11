"""Test-session setup.

The suite is fully offline: adapters are driven with stub clients and the judge
runs on hand-built traces, so no test makes a network call. But the OpenAI SDK
rejects a *missing* key at construction time, and several adapters build their
client in __init__ (LangGraphAdapter, MultiAgentAdapter) -- so a machine with no
provider key in the environment fails those tests for a reason that has nothing
to do with the code under test.

Plant a dummy key when the environment has none. It is never used for a real
request. A real key already in the environment (or in a .env) is left alone, so
this never shadows a working provider config.
"""

from __future__ import annotations

import os

_PROVIDER_KEYS = ("OPENAI_API_KEY", "GROQ_API_KEY")

if not any(os.environ.get(k) for k in _PROVIDER_KEYS):
    os.environ["GROQ_API_KEY"] = "test-dummy-key-offline-suite-only"