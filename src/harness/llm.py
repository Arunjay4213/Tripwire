"""Provider-agnostic LLM client + model resolution.

The whole harness talks to an OpenAI-*compatible* endpoint (the `openai` SDK).
Groq, OpenAI, and Anthropic's compat endpoint all speak that same wire format,
so which provider actually runs is purely an env-var choice -- nothing else in
the codebase needs to know.

Provider precedence (first match wins), so you can keep a Groq config and
override it just by adding an OpenAI key:

  OPENAI_API_KEY  -> OpenAI      (OPENAI_BASE_URL optional; default openai.com)
  GROQ_API_KEY    -> Groq        (GROQ_BASE_URL required for Groq's endpoint)

Model precedence: MODEL > OPENAI_MODEL > GROQ_MODEL. Set MODEL to force one id
regardless of provider; otherwise the provider's own *_MODEL is used.
"""

from __future__ import annotations

import os

from openai import OpenAI


def make_client() -> OpenAI:
    """Build an OpenAI-compatible client for whichever provider is configured.

    Constructing the client does not make a network call -- it only needs a
    key present. Tests that never hit the network still need *some* key so the
    constructor doesn't raise; a dummy value is fine there (see CI config).
    """
    if os.getenv("OPENAI_API_KEY"):
        return OpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_BASE_URL") or None,  # None -> api.openai.com
        )
    return OpenAI(
        api_key=os.getenv("GROQ_API_KEY"),
        base_url=os.getenv("GROQ_BASE_URL") or None,
    )


def resolve_model() -> str | None:
    """The model id to run, provider-agnostic. `MODEL` overrides everything so a
    sweep can pin one id; otherwise the active provider's own *_MODEL is used."""
    return os.getenv("MODEL") or os.getenv("OPENAI_MODEL") or os.getenv("GROQ_MODEL")
