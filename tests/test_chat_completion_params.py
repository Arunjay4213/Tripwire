"""chat_completion drops or renames the sampling parameters a model rejects,
learning it once per model from the provider's 400 (tripwire/harness/llm.py).
The GPT-5 family on Azure rejects any temperature but the default and wants
max_completion_tokens instead of max_tokens."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import openai
import pytest

from tripwire.harness import llm
from tripwire.harness.llm import chat_completion


def _bad_request(param: str) -> openai.BadRequestError:
    msg = f"Unsupported value: '{param}' is not supported with this model."
    return openai.BadRequestError(
        msg,
        response=httpx.Response(400, request=httpx.Request("POST", "http://test/chat/completions")),
        body={"error": {"message": msg, "type": "invalid_request_error", "param": param}},
    )


class _Gpt5Like:
    """Rejects temperature != 1 and max_tokens, like gpt-5.6-sol; records calls."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.calls.append(kw)
        if kw.get("temperature", 1) != 1:
            raise _bad_request("temperature")
        if "max_tokens" in kw:
            raise _bad_request("max_tokens")
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))], usage=None)


@pytest.fixture(autouse=True)
def _fresh_memory(monkeypatch):
    monkeypatch.setattr(llm, "_REJECTED_PARAMS", {})


def test_learns_each_rejected_parameter_once_per_model():
    client = _Gpt5Like()
    msgs = [{"role": "user", "content": "hi"}]
    resp = chat_completion(client, model="gpt-5.6-sol", messages=msgs, temperature=0.9, max_tokens=50)
    assert resp.choices[0].message.content == "ok"
    # temperature rejected, then max_tokens rejected, then success: three calls.
    assert [sorted(c) for c in client.calls] == [
        ["max_tokens", "messages", "model", "temperature"],
        ["max_tokens", "messages", "model"],
        ["max_completion_tokens", "messages", "model"],
    ]
    assert client.calls[-1]["max_completion_tokens"] == 50
    # Second call: no retries, the model's rejections are remembered.
    chat_completion(client, model="gpt-5.6-sol", messages=msgs, temperature=0.0, max_tokens=20)
    assert len(client.calls) == 4
    assert client.calls[-1] == {"model": "gpt-5.6-sol", "messages": msgs, "max_completion_tokens": 20}


def test_memory_is_per_model():
    client = _Gpt5Like()
    msgs = [{"role": "user", "content": "hi"}]
    chat_completion(client, model="a", messages=msgs, temperature=0.9)
    chat_completion(client, model="b", messages=msgs, temperature=0.9)
    assert [c["model"] for c in client.calls] == ["a", "a", "b", "b"]


def test_a_model_that_accepts_everything_is_called_once():
    calls = []

    def create(**kw):
        calls.append(kw)
        return SimpleNamespace(choices=[], usage=None)

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    chat_completion(client, model="DeepSeek-V4-Pro", messages=[], temperature=0.9, max_tokens=10)
    assert calls == [{"model": "DeepSeek-V4-Pro", "messages": [], "temperature": 0.9, "max_tokens": 10}]


def test_other_bad_requests_propagate():
    def create(**kw):
        raise _bad_request("messages")

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    with pytest.raises(openai.BadRequestError):
        chat_completion(client, model="m", messages=[], temperature=0.9)


def test_a_rejection_already_recorded_by_a_concurrent_call_is_still_retried():
    """Two calls in flight both get the temperature 400 before either records
    it; the second must retry without temperature, not re-raise because the
    shared set already lists it."""
    client = _Gpt5Like()
    llm._REJECTED_PARAMS["gpt-5.6-sol"] = {"temperature"}   # recorded by another thread...
    # ...but this client was built with the parameter and gets the 400 anyway:
    first = {"done": False}

    def create(**kw):
        client.calls.append(kw)
        if not first["done"]:
            first["done"] = True
            raise _bad_request("temperature")
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))], usage=None)

    client.chat.completions.create = create
    resp = chat_completion(client, model="gpt-5.6-sol", messages=[], temperature=0.9)
    assert resp.choices[0].message.content == "ok"
    assert len(client.calls) == 2 and "temperature" not in client.calls[-1]
