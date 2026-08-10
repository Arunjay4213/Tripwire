"""Statistical helpers for the metrics harness."""

from __future__ import annotations


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson confidence interval for a proportion.

    Honest for small sample sizes, unlike the naive p +/- z*sqrt(p(1-p)/n).
    Returns (lower, upper) bounds clamped to [0, 1].
    """
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def cohen_kappa(labels_a: list[bool], labels_b: list[bool]) -> float:
    """Cohen's kappa for two raters on the same binary items.

    Used to validate the deterministic judge against human labels: how much do
    the two agree *beyond chance*? kappa = (po - pe) / (1 - pe), where po is
    observed agreement and pe is agreement expected if each rater labeled
    independently at their own base rate.

    Returns 1.0 for perfect agreement, 0.0 for chance-level, negative for
    worse-than-chance. When both raters give a single constant label to every
    item (no variance), agreement is total but pe == 1, leaving kappa
    undefined (0/0); by convention we return 1.0 if they fully agree and 0.0
    if they don't -- kappa can't credit discrimination that wasn't exercised.
    """
    if len(labels_a) != len(labels_b):
        raise ValueError("raters must label the same number of items")
    n = len(labels_a)
    if n == 0:
        raise ValueError("need at least one item")

    agree = sum(1 for a, b in zip(labels_a, labels_b) if a == b)
    po = agree / n

    # Expected agreement by chance: sum over each class of (rate_a * rate_b).
    pa_true = sum(labels_a) / n
    pb_true = sum(labels_b) / n
    pe = pa_true * pb_true + (1 - pa_true) * (1 - pb_true)

    if pe == 1.0:  # both raters constant -> kappa is 0/0; see docstring
        return 1.0 if po == 1.0 else 0.0
    return (po - pe) / (1 - pe)
