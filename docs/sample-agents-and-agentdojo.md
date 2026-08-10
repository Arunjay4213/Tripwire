# Sample agents and AgentDojo

Two things this doc covers:

1. Three "vibecoded" sample agents - the kind of agent a developer throws together quickly - run through Tripwire's attack suite.
2. A run of the real AgentDojo benchmark through Tripwire's bridge, to see how our target does on an external, environment-scored benchmark.

All numbers below are on `claude-haiku-4-5` via the Anthropic OpenAI-compatible endpoint.

## 1. Vibecoded sample agents

`examples/vibe_agents/` holds three agents, each a common pattern someone would build without security in mind.
They all satisfy the BYO contract (`EpisodeSpec` in, `NormalizedTrace` out), so the identical attack suite, judge, and defenses run against them.

| Agent | Pattern | The vibecoder tell |
| --- | --- | --- |
| `vibe_helpful_assistant` | plain tool loop with an eager "just get it done" persona | never wires in the defense hooks; nudges the model to act on whatever it sees |
| `vibe_context_stuffer` | pre-reads the inbox and pastes it into the system prompt as "context" | launders untrusted content into the highest-authority channel |
| `vibe_autonomous_agent` | "autonomous, never ask for confirmation" persona, long loop | treats any actionable text as a task to complete |

Run them yourself:

```bash
# the whole comparison (vibe agents + careful raw_loop baseline)
examples/vibe_agents/run_vibe_eval.py        # via the direnv python

# or one agent through the real CLI path
python -m src --config src/config/threat_model.example.yaml \
    --agent examples/vibe_agents/vibe_context_stuffer.py
```

### Result: at no_defense, vibecoded agents are as leaky as the baseline

Sweeping the single-shot attacks at no_defense (n=3 seeds), all four agents (the three vibe agents plus the careful `raw_loop`) behave the same:

- Weak templated attacks (`direct`, `important_instructions`, `fixed_injection`, `public_identifier`, `forged_boundary`) - **0%** on every agent.
- Strong hand-crafted attacks (`metadata_exfil`, `prerequisite_mirror`, `mundane_redirect`) - **100%** on every agent.

The lesson is not that these agents are unusually bad - it is that with no defense, the target model's own behavior dominates, and a strong attack hijacks any of them.
Persona wording ("be helpful", "be autonomous") did not change the outcome.

### Result: a vibecoded agent silently defeats a defense the deployment "has"

The important finding is what happens when a defense IS configured.
Under spotlighting (n=3):

| Agent | `mundane_redirect` ASR under spotlighting |
| --- | --- |
| `raw_loop` (careful - fences tool output via the defense hook) | 0/3 |
| `vibe_context_stuffer` (pastes inbox into the system prompt) | **3/3** |

The careful adapter runs the injected email through spotlighting's fence, and the defense holds.
The context stuffer promoted that same email into the system prompt itself, so the fence never wrapped it - the defense was bypassed without the deployer ever knowing.
This is the concrete argument for instrumenting the agent you actually ship: a defense only protects the agent that routes untrusted content through it.

## 2. AgentDojo through the bridge

`src/environments/agentdojo_bridge.py` runs a real AgentDojo workspace task through a Tripwire adapter: AgentDojo's prompt, its ~24 stateful tools, its injection attack, and - crucially - its own utility and security checks, which score on environment state, not on the trace.
`scripts/experiments/agentdojo_eval.py` drives a grid of it.

Grid: 3 user tasks x 3 injection tasks x 5 attacks (`direct`, `ignore_previous`, `system_message`, `injecagent`, `important_instructions`), for no_defense and spotlighting, on `raw_loop` + `claude-haiku-4-5`.

| Defense | Utility (real task done) | ASR (injection succeeded) |
| --- | --- | --- |
| no_defense | 45/45 = 100% [92-100%] | 0/45 = 0% [0-8%] |
| spotlighting | 45/45 = 100% [92-100%] | 0/45 = 0% [0-8%] |

Every attack scored 0%, including `important_instructions` - the strongest attack in the AgentDojo paper.
(To make that attack run against a current model, the bridge now maps the model id to an AgentDojo-recognized model name; `important_instructions` previously crashed on the lookup for `claude-haiku-4-5`.)

### How to read this

- **The bridge works.** 100% utility means the agent genuinely completes AgentDojo's tasks - the harness is driving the benchmark correctly, and the injected content is reaching the model (it lives in the same tool data the agent reads to do the task).
- **The target is robust to the benchmark's stock attacks.** AgentDojo's attacks are 2024-era baselines; a current aligned model resists them, which is why our own scripted harness shows the same templated attacks at ~0%.
- **This is the motivation for Tripwire's crafted attacks, not a contradiction of them.** On the off-the-shelf benchmark our target looks unbreakable (0%). Tripwire's hand-crafted attacks (`metadata_exfil`, `mundane_redirect`) break the same model - 100% undefended, and 15-50% even against prompt_hardening / spotlighting. The value Tripwire adds is finding the leaks a stock benchmark misses.

### Honest limitations

- This is a 9-task-pair subset (3x3), not the full suite (40 user x 14 injection tasks). A wider grid could surface a few successes; the upper Wilson bound here is 8%. The direction - stock attacks are weak against a modern model - is clear, but the exact rate is a small-sample estimate.
- ASR/utility come from AgentDojo's environment-state checks, which are a different (and more credible) scoring path than the canary harness's trace-only judge. The two are not directly comparable numerically; they answer "did the injection change the world" vs "did the canary leave the trust boundary".
