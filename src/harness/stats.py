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
