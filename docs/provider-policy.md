# Provider policy - adversarial / security testing (roadmap §0.3)

ToS gate. **Do not run attacks at volume until the relevant row is filled in.**
Read each provider's CURRENT usage policy for adversarial/injection testing,
confirm which account type to use, record below. If a provider prohibits it on
standard accounts, use open models via a self-hosted or permissive endpoint.

## Provider support in the harness

The harness is provider-agnostic.
It talks to any OpenAI-compatible endpoint, chosen by environment variables (see `tripwire/harness/llm.py`).
`OPENAI_API_KEY` with `OPENAI_BASE_URL` points it at any such endpoint.
Built-in presets exist for Anthropic (`ANTHROPIC_API_KEY`), OpenRouter (`OPENROUTER_API_KEY`) and Groq (`GROQ_API_KEY`).
Each preset also has `_BASE_URL` and `_MODEL` overrides, and `MODEL` pins one model id for a whole sweep.
Azure AI Foundry's OpenAI-compatible endpoint works through `OPENAI_BASE_URL` with no code change.
The starter config from `tripwire init` defaults to `claude-haiku-4-5`.
Groq retired `llama-3.3-70b-versatile`, so the example configs now use `openai/gpt-oss-20b`.
The table below is about each provider's terms, not about what the harness can technically call.

## Summary table

| Provider  | Adversarial testing allowed?                      | Account type needed | Required steps                        | Source URL (date read)                                              |
|-----------|---------------------------------------------------|---------------------|---------------------------------------|---------------------------------------------------------------------|
| Groq      | Not by default. Exception available on request.   | Standard + exception| Contact Groq, describe safeguards     | [AI Policy](https://console.groq.com/docs/legal/ai-policy) (2026-06-29) |
| OpenAI    | Enterprise only (Red Teaming product).            | Enterprise          | Use OpenAI Red Teaming managed offering | [Red Teaming guide](https://developers.openai.com/api/docs/guides/red-teaming) (2026-06-29) |
| Anthropic | Requires prior authorization from Anthropic.      | Any + authorization | Contact Anthropic for authorization   | [AUP](https://www.anthropic.com/legal/aup) (2026-06-29)            |
| Google    | Not explicitly addressed. Case-by-case review.    | Unknown             | Review Prohibited Use Policy; contact Google | [Usage Policies](https://ai.google.dev/gemini-api/docs/usage-policies) (2026-06-29) |

## Detailed notes

### Groq

Policy prohibits "gain unauthorized access to, attack, abuse, interfere with,
intercept, disrupt, or exploit any users, systems, or services" and
"intentionally circumvent any aspect of the Cloud Services or AI Model Services,
including abuse protections or safety mechanisms."

However: "Customers who have implemented adequate safeguards and require
additional flexibility for lawful business or research purposes, may contact Groq
to request an exception."

**Action item**: Contact Groq support describing our use case (evaluating agent
robustness to prompt injection, testing our own agent, not attacking Groq
infrastructure) and request an exception before scaling beyond smoke runs.

### OpenAI

Red teaming is an enterprise-only managed offering. Standard API accounts cannot
use OpenAI's red teaming tools. OpenAI recommends promptfoo (open-source) for
developers without enterprise access.

Restriction: "Only submit code or other assets that you own or are expressly
authorized to test."

**Action item**: For OpenAI models, either get enterprise access or run via a
self-hosted compatible endpoint. Alternatively, use promptfoo for OpenAI-model
testing.

### Anthropic

AUP prohibits jailbreaking / prompt injection "without prior authorization from
Anthropic." Also prohibits unauthorized vulnerability discovery.

Supports cybersecurity use cases that "strengthen cybersecurity, such as
discovering vulnerabilities with the system owner's consent."

**Action item**: Request authorization from Anthropic before running injection
benchmarks against Claude models. We are the system owner (testing our own
agent), which helps the case.

### Google (Gemini)

No explicit provision for or against adversarial testing in public docs. Abuse
monitoring is automated + manual. Google may "reach out to understand your use
case" if flagged.

**Action item**: Review the full Generative AI Prohibited Use Policy and
Additional Terms of Service before testing. Consider contacting Google support
proactively.

## Safe defaults

Until exceptions/authorizations are obtained:

1. **Groq + open models** (for example openai/gpt-oss-20b) - safest.
   Open model weights, we test our own agent, not Groq's infrastructure.
   Still request exception for volume.
2. **Self-hosted open models** - no ToS concern at all.
   Slower, costs more.
3. **Closed-model APIs** - do not run until authorized. 

## Models that refuse the attacker role outright

Measured 2026-10-12: `gpt-5.6-sol` on Azure AI Foundry rejects the PAIR attacker's first request with HTTP 400, code `cyber_policy` ("This content was flagged for possible cybersecurity risk ... To get authorized for security work, join the Trusted Access for Cyber program").
The block is on the request content, not on a parameter, so it applies to any attacker prompt that asks the model to craft an injection.
Tripwire records each such campaign as an error, never as a defense holding.
Do not rephrase the attacker prompt to get past the classifier; that is the provider's authorization gate for exactly this kind of work.
The sanctioned routes are the provider's program for security work, or an attacker model from a vendor whose terms you have checked (DeepSeek-V4-Pro is what the 2026-10-11 baseline used).

