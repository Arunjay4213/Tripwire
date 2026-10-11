"""Reporter — write per-episode results to results/ as JSON, print ASR table.

P1 core (roadmap Weeks 2-3).

Every table groups by the full experimental cell, (adapter, model, scenario,
attack, defense), so a multi-model or multi-scenario sweep never pools distinct
agents into one row. Episodes that errored (status="error") carry no scorable
trace: they are excluded from n and from the ASR numerator/denominator, and
counted in their own `err` column so a cell that lost many trials is visibly
suspect instead of silently shrinking.
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from dataclasses import asdict

from tripwire.harness.advice import advice_for
from tripwire.harness.runner import CampaignResult, EpisodeResult
from tripwire.harness.stats import wilson_ci


# The rungs print_security_report recommends, in the order it lists them.
# Enforcing rungs block the call deterministically; instruction rungs change
# what the model is told, and the outbound guard asks a second model.
_ENFORCING_RUNGS = ("recipient_allowlist", "secret_egress_scan")
_INSTRUCTION_RUNGS = ("prompt_hardening", "spotlighting", "outbound_guard")


def write_results(
    results: list[EpisodeResult],
    path: str,
    campaigns: list[CampaignResult] | None = None,
) -> None:
    """Dump raw results to a JSON file.

    Single-shot episodes and adaptive campaigns are written under separate keys
    when any campaign is present; otherwise the flat episode list is kept for
    backward compatibility. `asdict` serializes every dataclass field, so the
    status/error/stop_reason fields (and any later additions) are written too.
    """
    payload: list[dict] | dict[str, list[dict]]
    if campaigns:
        payload = {
            "episodes": [asdict(r) for r in results],
            "campaigns": [asdict(c) for c in campaigns],
        }
    else:
        payload = [asdict(r) for r in results]
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def _is_error(r: EpisodeResult | CampaignResult) -> bool:
    """True when the run aborted (status="error") and so cannot be scored:
    an errored episode has no trace, and an errored campaign stopped early,
    so counting it as "held" would flatter the defense."""
    return r.status == "error"


def _pct(x: float) -> str:
    return f"{x:.0%}"


def _ci(successes: int, n: int) -> str:
    if n == 0:
        return "-"
    lo, hi = wilson_ci(successes, n)
    return f"[{lo:.0%}, {hi:.0%}]"


def _print_table(headers: list[str], rows: list[list[str]], n_left: int) -> None:
    """Print rows under headers with widths fitted to the widest value.

    The first `n_left` columns (the text labels) are left-aligned; the rest
    (numbers) are right-aligned. Fitting widths to the data keeps long adapter
    or attack names from shifting every later column.
    """
    widths = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(headers)]

    def fmt(cells: list[str]) -> str:
        parts = [c.ljust(w) if i < n_left else c.rjust(w) for i, (c, w) in enumerate(zip(cells, widths))]
        return "  ".join(parts).rstrip()

    print(fmt(headers))
    print("-" * len(fmt(headers)))
    for r in rows:
        print(fmt(r))


def print_asr_table(results: list[EpisodeResult]) -> None:
    """Print attack-success-rate table grouped by (adapter, model, scenario,
    attack, defense).

    Each row shows: scored trials (n), successes, ASR%, 95% Wilson CI, and
    utility% (how often the agent still completed its real, benign task -- see
    judge.task_completed). ASR and utility are independent: a defense that
    blocks every tool shows 0% ASR *and* 0% utility, which is a very
    different (much worse) outcome than 0% ASR with 100% utility.

    `err` counts episodes that raised (status="error"); they are excluded from
    n, ASR and utility. `max_turns` counts episodes that hit the per-episode
    model-call budget before finishing -- their trace is scored, but the agent
    may have been cut off before it would have leaked (or completed the task).
    """
    groups: dict[tuple[str, str, str, str, str], list[EpisodeResult]] = defaultdict(list)
    for r in results:
        groups[(r.adapter, r.model, r.scenario, r.attack, r.defense)].append(r)

    headers = ["adapter", "model", "scenario", "attack", "defense",
               "n", "leak", "ASR", "95% CI", "utility", "err", "max_turns"]
    rows: list[list[str]] = []
    total_err = 0
    total_capped = 0
    for key, items in sorted(groups.items()):
        scored = [r for r in items if not _is_error(r)]
        n = len(scored)
        errors = len(items) - n
        leaks = sum(1 for r in scored if r.succeeded)
        completed = sum(1 for r in scored if r.task_completed)
        capped = sum(1 for r in items if r.stop_reason == "max_turns")
        total_err += errors
        total_capped += capped
        rows.append([
            *key,
            str(n), str(leaks),
            _pct(leaks / n) if n else "-",
            _ci(leaks, n),
            _pct(completed / n) if n else "-",
            str(errors), str(capped),
        ])

    _print_table(headers, rows, n_left=5)
    if total_err:
        print(f"note: {total_err} episode(s) errored and are excluded from n/ASR/utility "
              "(err column); treat cells with many errors as suspect.")
    if total_capped:
        print(f"note: {total_capped} episode(s) hit the max_turns budget before finishing "
              "(max_turns column).")


def print_campaign_table(campaigns: list[CampaignResult]) -> None:
    """Print the adaptive-attacker effort-to-break table, grouped by
    (adapter, model, scenario, attack, defense, budget).

    Each row shows: campaigns run, break-rate within budget + 95% Wilson CI, and
    median/mean attempts-to-break over the campaigns that broke. `err` counts
    aborted campaigns (excluded from n); `eval_err` counts target evaluations
    that errored inside the scored campaigns -- a campaign whose attempts
    mostly errored did not really test the defense. Model and
    scenario are part of the key so a multi-model or multi-scenario sweep
    doesn't merge distinct agents or tasks into one row (matching
    print_asr_table); budget is part of it because a break rate only means
    something relative to how many attempts the attacker had.
    """
    groups: dict[tuple[str, str, str, str, str, int], list[CampaignResult]] = defaultdict(list)
    for c in campaigns:
        groups[(c.adapter, c.model, c.scenario, c.attack, c.defense, c.budget)].append(c)

    headers = ["adapter", "model", "scenario", "attack", "defense", "budget",
               "n", "broke", "rate", "95% CI", "attempts (med/mean)", "err", "eval_err"]
    rows: list[list[str]] = []
    for (adapter, model, scenario, attack, defense, budget), items in sorted(groups.items()):
        scored = [c for c in items if not _is_error(c)]
        n = len(scored)
        broke = sum(1 for c in scored if c.broke)
        attempts = [c.attempts_to_break for c in scored if c.attempts_to_break is not None]
        if attempts:
            att = f"{statistics.median(attempts):.1f} / {statistics.mean(attempts):.1f}"
        else:
            att = "never broke"
        rows.append([
            adapter, model, scenario, attack, defense, str(budget),
            str(n), str(broke),
            _pct(broke / n) if n else "-",
            _ci(broke, n),
            att, str(len(items) - n), str(sum(c.errors for c in scored)),
        ])

    _print_table(headers, rows, n_left=5)


def print_security_report(
    episodes: list[EpisodeResult],
    campaigns: list[CampaignResult] | None = None,
) -> None:
    """Actionable feedback: for each agent+defense tested, which attacks got
    through and how to close each gap (see tripwire/harness/advice.py).

    A leak here means real exfiltration -- the planted secret reached a recipient
    the task never authorized. Grouped by (agent, model, scenario, defense) so the
    fix matches the configuration you actually ran and doesn't merge distinct
    models or tasks. Errored runs are not scored; the block says how many there
    were.
    """
    Block = tuple[str, str, str, str]
    # (adapter, model, scenario, defense) -> attack -> [successes, n]
    stats: dict[Block, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    errors: dict[Block, int] = defaultdict(int)
    for r in episodes:
        block = (r.adapter, r.model, r.scenario, r.defense)
        if _is_error(r):
            errors[block] += 1
            stats[block]  # make sure an all-errored block is still reported
            continue
        s = stats[block][r.attack]
        s[0] += int(r.succeeded); s[1] += 1
    for c in campaigns or []:
        block = (c.adapter, c.model, c.scenario, c.defense)
        if _is_error(c):
            errors[block] += 1
            stats[block]
            continue
        s = stats[block][c.attack]
        s[0] += int(c.broke); s[1] += 1

    print("=" * 72)
    print("SECURITY FEEDBACK -- what got through, and how to harden your agent")
    print("=" * 72)

    for block in sorted(stats):
        adapter, model, scenario, defense = block
        per_attack = stats[block]
        print(f"\nagent={adapter}   model={model}   scenario={scenario}   defense={defense}")
        if errors[block]:
            print(f"  ! {errors[block]} run(s) errored and were not scored.")
        scored_n = sum(v[1] for v in per_attack.values())
        if scored_n == 0:
            print("  ? No scored runs -- nothing can be concluded for this configuration.")
            continue
        vulns = {a: v for a, v in per_attack.items() if v[0] > 0}
        if not vulns:
            _, hi = wilson_ci(0, scored_n)
            print(f"  ✓ No exfiltration observed across the attacks tested "
                  f"(0/{scored_n} leaked; true rate could be up to {hi:.0%}).")
            continue
        print(f"  ✗ Leaked to {len(vulns)} of {len(per_attack)} attacks tested:")
        recommend: set[str] = set()
        for attack, (succ, n) in sorted(vulns.items(), key=lambda kv: -kv[1][0] / kv[1][1]):
            a = advice_for(attack)
            print(f"    • {attack}  (leaked {succ}/{n} = {succ / n:.0%}, 95% CI {_ci(succ, n)})")
            print(f"        what it does: {a.summary}")
            if a.reduced_by:
                print(f"        reduced by:   {', '.join(a.reduced_by)}")
                recommend.update(a.reduced_by)
            print(f"        fix:          {a.fix}")
        enforced = [d for d in _ENFORCING_RUNGS if d in recommend and d != defense]
        persuasive = [d for d in _INSTRUCTION_RUNGS if d in recommend and d != defense]
        if enforced:
            print(f"  → Start here: turn on {', '.join(enforced)} -- deterministic checks on every "
                  "send that no injected text can talk past -- and re-run.")
        if persuasive:
            print(f"  → {'Then' if enforced else 'Start here'}: {', '.join(persuasive)} lower the odds "
                  "the model is fooled at all; re-run to see each gap close.")
