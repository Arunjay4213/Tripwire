"""Provider-agnostic LLM client + model resolution.

The whole harness talks to an OpenAI-*compatible* endpoint (the `openai` SDK).
OpenAI, Anthropic, OpenRouter, and Groq all speak that same wire format, so
which provider actually runs is purely an env-var choice -- nothing else in the
codebase needs to know.

Each provider is one entry in `_PROVIDERS`: the API-key env var that selects it,
a default base URL (overridable with `<PREFIX>_BASE_URL`), and the model env var
its default model comes from. The first provider whose key is set wins, so you
can keep a Groq config and override it just by adding an Anthropic key:

  OPENAI_API_KEY      -> OpenAI      (default api.openai.com)
  ANTHROPIC_API_KEY   -> Anthropic   (default api.anthropic.com/v1, OpenAI-compat)
  OPENROUTER_API_KEY  -> OpenRouter  (default openrouter.ai/api/v1)
  GROQ_API_KEY        -> Groq        (default api.groq.com/openai/v1)

Model precedence: MODEL > the active provider's <PREFIX>_MODEL. Set MODEL to
force one id regardless of provider; otherwise the provider's own default is used.
"""

from __future__ import annotations

import os

from openai import OpenAI


class _Provider:
    """One OpenAI-compatible provider: how to detect it and where to point it."""

    def __init__(self, key_env: str, base_url_env: str, default_base_url: str | None, model_env: str) -> None:
        self.key_env = key_env
        self.base_url_env = base_url_env
        self.default_base_url = default_base_url
        self.model_env = model_env

    def api_key(self) -> str | None:
        return os.getenv(self.key_env)

    def base_url(self) -> str | None:
        # An explicit <PREFIX>_BASE_URL always wins; otherwise the built-in
        # default (None for OpenAI means the SDK's own api.openai.com).
        return os.getenv(self.base_url_env) or self.default_base_url

    def model(self) -> str | None:
        return os.getenv(self.model_env)


# First match wins. OpenAI leads so an explicit OPENAI_API_KEY + OPENAI_BASE_URL
# still routes anywhere (it is the generic OpenAI-compatible escape hatch).
_PROVIDERS = [
    _Provider("OPENAI_API_KEY", "OPENAI_BASE_URL", None, "OPENAI_MODEL"),
    _Provider("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1/", "ANTHROPIC_MODEL"),
    _Provider("OPENROUTER_API_KEY", "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1", "OPENROUTER_MODEL"),
    _Provider("GROQ_API_KEY", "GROQ_BASE_URL", "https://api.groq.com/openai/v1", "GROQ_MODEL"),
]


def active_provider() -> _Provider | None:
    """The first provider whose API key is present, or None if no key is set."""
    for provider in _PROVIDERS:
        if provider.api_key():
            return provider
    return None


def has_provider_key() -> bool:
    """True if any supported provider's API key is set (in env or a loaded .env)."""
    return active_provider() is not None


def provider_key_names() -> list[str]:
    """The env-var names the harness looks for, for error messages."""
    return [p.key_env for p in _PROVIDERS]


def make_client() -> OpenAI:
    """Build an OpenAI-compatible client for whichever provider is configured.

    Constructing the client does not make a network call -- it only needs a
    key present. Tests that never hit the network still need *some* key so the
    constructor doesn't raise; a dummy value is fine there (see CI config).
    """
    provider = active_provider()
    if provider is None:
        # No key at all: hand the SDK None and let its own constructor raise the
        # canonical "no api_key" error. The CLI preflight normally catches this
        # first with a friendlier message.
        return OpenAI(api_key=None)
    return OpenAI(api_key=provider.api_key(), base_url=provider.base_url())


def resolve_model() -> str | None:
    """The model id to run, provider-agnostic. `MODEL` overrides everything so a
    sweep can pin one id; otherwise the active provider's own <PREFIX>_MODEL is used."""
    if os.getenv("MODEL"):
        return os.getenv("MODEL")
    provider = active_provider()
    return provider.model() if provider is not None else None
