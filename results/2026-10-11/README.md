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

## Added after stage 1

- `single_luna.json.gz` is now the spliced file: the calendar cells re-run under the case-insensitive task-marker fix (`single_luna_calendar.json.gz`, 3,360 rows, spliced with `scripts/experiments/splice_results.py`). Numbers moved within a point; luna was not affected by the bug.
- `adaptive_<model>.json.gz`: the adaptive stage (PAIR on both models, TAP on DeepSeek), 10 discovery seeds (100..109) per cell, budget 8. `adaptive_tables.md` has the break rates. DeepSeek: 640 campaigns, 58 min, 27.8M tokens, 156 errored attempts (Azure content filter on the guard's input). Luna: 320 campaigns, 28 min.
- `replay_<model>.json`: the winning payloads the adaptive stage saved (DeepSeek 150, luna 5). `replay_deepseek_defended.json` (the 32 found against a defended cell) and `replay_deepseek_sample.json` (24 of the 118 undefended wins, 3 per scenario and attacker) are the subsets replayed on held-out seeds 0..29.
- `langgraph_sanity.json.gz`: 280 episodes, the dropped adapter on one scenario at 5 seeds; agrees with raw_loop in 52 of 56 cells (10% vs 11% overall), as the parity tests predict.
- `single_deepseek.json.gz` is now the spliced file too: calendar cells re-run under the fixed judge (`single_deepseek_calendar.json.gz`, 3,360 rows, 24 min). DeepSeek's no-attack control utility is 100% on every defense after the splice; the guard's content-filter errors are 77 of 1,680 (4.6%). `single_tables.md` and `pareto_deepseek.png` are regenerated from the spliced files.
