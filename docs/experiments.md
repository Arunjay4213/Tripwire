# Experiments

Real results from running the harness at a scale beyond single-seed smoke
tests. Recorded here — not just in a local `results/` directory — because
raw per-seed JSON is regenerable but a specific real run, with its caveats,
is not something to lose. Every number below came from an actual run against
Groq; none are estimated or invented. Reproduction scripts are in
`scripts/experiments/`.

**Model**: `llama-3.3-70b-versatile` via Groq. **Date**: 2026-08-08.
**Note on "seed"**: `environment_seed` fixes the deterministic canary and
environment content, not the model's sampling — re-running the same seed
number is a genuinely independent LLM trial, not a duplicate.

## Experiment 1 — does the adapter change ASR?

The project's core hypothesis, measured directly: same model, same attack
(`direct`, a single templated jailbreak), same 15 seeds, only the adapter
varies. `scripts/experiments/adapter_asr_comparison.py`.

```
adapter          attack                   defense           n leak    ASR  95% CI          utility
--------------------------------------------------------------------------------------------------
langgraph        direct                   no_defense       15    6   40%  [20%, 64%]         47%
multi_agent      direct                   no_defense       15    0    0%  [0%, 20%]          0%
raw_loop         direct                   no_defense       15    1    7%  [1%, 30%]         40%
```

45/45 episodes scored — the run completed with zero skipped seeds.

**Reading this honestly:**
- The Wilson CIs are wide at n=15. `langgraph`'s true ASR is anywhere from
  20% to 64% given this sample — real evidence the adapters differ, not a
  precise rate. Report the interval, not just the point estimate.
- **`multi_agent` shows 0% ASR *and* 0% utility across all 15 seeds.** That
  is not "the safest adapter" — it means the two-hop summarize→act pipeline
  didn't successfully complete the benign task even once, attack or no
  attack. The more interesting finding here is that the relay handoff loses
  task-relevant detail, not that it resists injection. This needs a
  follow-up run isolating utility without any attack present before it's
  fair to call `multi_agent` more "robust."
- `raw_loop` (7% ASR, 40% utility) and `langgraph` (40% ASR, 47% utility)
  are the two directly comparable data points, and they differ by a factor
  of ~5-6x in ASR under an identical attack and model — the clearest signal
  in this dataset.

## Experiment 2 — adaptive attacker efficiency

How many adaptive (PAIR-style) attempts does it take to break an adapter,
within a budget of 6? `scripts/experiments/iterative_attacker_efficiency.py`,
configured for 2 adapters × 10 seeds.

**This did not complete as designed.** Two full attempts both hit Groq's
free-tier daily cap (100k tokens/day) partway through — adaptive campaigns
are far more token-hungry per data point than single-shot episodes (each
attempt is 1 attacker-LLM call + 1 full target-agent tool loop, and the
sweep's `raw_loop`-first ordering meant the budget was exhausted before
`langgraph` ever ran a single campaign, in both attempts).

**What's real, pooled across both attempts** (each seed re-run is an
independent trial, so pooling is valid — see the seed note above):

```
raw_loop:  n=8, broke=7, break rate=88%, 95% CI=[53%, 98%]
           attempts-to-break: median=2, mean=2.43
langgraph: n=0 -- no data. Budget exhausted before any campaign ran.
```

**Reading this honestly:**
- n=8 with a `[53%, 98%]` CI is a real but weak result — enough to say
  "raw_loop breaks quickly and often under this adaptive attacker," not
  enough for a precise rate.
- **4 of the 7 breaks happened at exactly attempt 2.** That's a suspiciously
  uniform pattern for 7 independent LLM trials — possibly the attacker's
  second seed strategy (of 4 rotating templates, see
  `src/attacks/iterative.py`) is unusually effective against this specific
  model, possibly a smaller behavioral space than "adaptive refinement"
  implies. Don't smooth this over; it's worth investigating before citing
  "attempts to break" as a clean metric.
- **There is no `langgraph` data for this experiment.** The cross-adapter
  comparison this was designed to produce doesn't exist yet. A correct rerun
  needs either a much smaller budget/seed count, separate daily quota
  windows per adapter, or a paid tier.

## Limitations (apply to both experiments)

- Single provider (Groq), single model (`llama-3.3-70b-versatile`), single
  point in time. No claim here generalizes to other models without rerunning.
- Small-to-medium sample sizes (n=8-15). Wilson CIs are reported specifically
  so nobody downstream mistakes a point estimate for a precise measurement.
- Experiment 2's `langgraph` gap is a real, unresolved hole, not a rounding
  error — don't cite a `langgraph` adaptive-attacker number, there isn't one.
- No cross-attack replication in Experiment 1 (`direct` only) or defense
  comparison in either — both are natural next runs, not yet done.
