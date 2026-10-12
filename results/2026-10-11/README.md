# Baseline sweep, 2026-10-11

Single-shot stage of the first-pass baseline (`configs/single_deepseek.yaml`, `configs/single_luna.yaml`), run on the devbox with concurrency 16.
Models: DeepSeek-V4-Pro (deployment version 2026-04-23) and gpt-5.6-luna (2026-07-09), both GlobalStandard on Azure AI Foundry, eastus2.
Attacker, guard and reader roles: DeepSeek-V4-Pro.
Code: commit 078c158 (main).

| | DeepSeek-V4-Pro | gpt-5.6-luna |
|---|---|---|
| Episodes | 13,440 | 13,440 |
| Errors | 91, all Azure content filter on the guard's input | 0 |
| Wall time | 84 min | 69 min |
| Tokens | 41.7M | 22.4M |

`single_<model>.json.gz` is the full results file as written by `tripwire` (`gunzip` to use with `scripts/experiments/`), `single_<model>.log` the console output, `single_tables.md` the output of `scripts/experiments/summarize_results.py --markdown`, and `pareto_<model>.png` the security-utility plot.
