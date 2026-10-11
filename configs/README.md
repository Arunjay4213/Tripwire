# Sweep configs (first pass, 2026-10-11)

Two models, DeepSeek-V4-Pro and gpt-5.6-luna, each run as its own process so each uses its own 1000K tokens/min quota.
Attacker, guard and reader roles are always DeepSeek-V4-Pro: the GPT-5 family rejects the temperature the guard and the PAIR attacker send.
Run on the devbox inside tmux; a laptop sleep kills a multi-hour run.

Every command assumes the repo root, the Azure `.env`, and this prefix:

    export ATTACKER_MODEL=DeepSeek-V4-Pro GUARD_MODEL=DeepSeek-V4-Pro READER_MODEL=DeepSeek-V4-Pro

## 0. Pilot (run first, ~10 minutes)

    python -m tripwire --config configs/pilot.yaml --output results/pilot.json --concurrency 8

Read the err column and the wall time; divide by the episode count for seconds per episode, then size the rest.

## 1. Single-shot baseline, one tmux window per model

    python -m tripwire --config configs/single_deepseek.yaml --output results/single_deepseek.json
    python -m tripwire --config configs/single_luna.yaml     --output results/single_luna.json

## 1b. LangGraph sanity row (any window, a few minutes)

    python -m tripwire --config configs/langgraph_sanity.yaml --output results/langgraph_sanity.json

Compare its rows with the raw_loop rows for the same cells; the parity tests say they should agree up to sampling noise.

## 2. Adaptive discovery, one window per model

    python -m tripwire --config configs/adaptive_deepseek.yaml --output results/adaptive_deepseek.json --save-replay-library results/replay_deepseek.json
    python -m tripwire --config configs/adaptive_luna.yaml     --output results/adaptive_luna.json     --save-replay-library results/replay_luna.json

## 3. Held-out replay of the discovered payloads on the single-shot seeds

    python -m tripwire --config configs/single_deepseek.yaml --replay-library results/replay_deepseek.json --output results/replay_deepseek_heldout.json
    python -m tripwire --config configs/single_luna.yaml     --replay-library results/replay_luna.json     --output results/replay_luna_heldout.json

Record the deployment versions with the results: DeepSeek-V4-Pro 2026-04-23, gpt-5.6-luna 2026-07-09, both GlobalStandard in eastus2.
