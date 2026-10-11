"""One scripted stand-in for ``openai.OpenAI``, shared by every adapter test.

The adapters read exactly two things off a chat completion: the message's
``content`` and its ``tool_calls`` (each with an ``id`` and a
``function.name`` / ``function.arguments`` string). ``message()`` and
``tool_call()`` build that shape, and ``ScriptedClient`` serves a list of such
messages in order, so one scripted transcript can be replayed through any
adapter (``RawLoopAdapter(client)``, ``LangGraphAdapter(client=client)``,
``MultiAgentAdapter(client=client)``).

The client is strict on purpose:

- every request is deep-copied as it arrives, so a test can inspect what the
  model saw on call N (``client.requests[N]``) even though raw_loop keeps
  appending to one messages list;
- running past the end of the script raises, which catches an adapter that
  makes more model calls than the test budgeted for;
- ``repeat_last=True`` keeps serving the final message forever, which is how
  a model stuck in a tool loop is scripted.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any


def tool_call(call_id: str, name: str, arguments: str | None) -> SimpleNamespace:
    """One tool call as the OpenAI SDK exposes it on an assistant message."""
    return SimpleNamespace(id=call_id, type="function", function=SimpleNamespace(name=name, arguments=arguments))


def message(content: str | None = None, tool_calls: list[SimpleNamespace] | None = None) -> SimpleNamespace:
    """One assistant message: text, tool calls, or both."""
    return SimpleNamespace(content=content, tool_calls=tool_calls)


@dataclass
class ScriptedClient:
    """Stands in for openai.OpenAI: returns the scripted assistant messages in
    order and records every request. With ``repeat_last`` it keeps returning
    the final message forever (an agent stuck in a tool loop)."""

    script: list[SimpleNamespace]
    repeat_last: bool = False
    requests: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs: Any) -> SimpleNamespace:
        # Snapshot: raw_loop keeps appending to the same messages list.
        self.requests.append(copy.deepcopy(kwargs))
        index = len(self.requests) - 1
        if index >= len(self.script):
            if not self.repeat_last:
                raise AssertionError("adapter made more model calls than the script has")
            index = len(self.script) - 1
        return SimpleNamespace(choices=[SimpleNamespace(message=self.script[index])])
