"""Tests for wilson_ci — the Wilson score confidence interval helper."""

import pytest

from src.harness.stats import wilson_ci


def test_zero_trials():
    assert wilson_ci(0, 0) == (0.0, 0.0)


def test_all_successes():
    lo, hi = wilson_ci(10, 10)
    assert hi <= 1.0
    assert lo > 0.5  # 10/10 should have lower bound well above 50%


def test_zero_successes():
    lo, hi = wilson_ci(0, 10)
    assert lo >= 0.0
    assert hi < 0.5  # 0/10 should have upper bound well below 50%


def test_half_successes():
    lo, hi = wilson_ci(5, 10)
    assert lo < 0.5
    assert hi > 0.5  # interval should straddle 50%


def test_bounds_clamped():
    """Results always in [0, 1]."""
    for s, n in [(0, 1), (1, 1), (0, 100), (100, 100), (50, 100)]:
        lo, hi = wilson_ci(s, n)
        assert 0.0 <= lo <= hi <= 1.0


def test_interval_contains_true_proportion():
    """For common cases the true p falls inside the 95% CI."""
    for s, n in [(3, 20), (10, 20), (1, 5), (0, 5), (5, 5)]:
        lo, hi = wilson_ci(s, n)
        p = s / n
        assert lo <= p <= hi


def test_wider_at_small_n():
    """With fewer observations the interval should be wider."""
    _, hi_small = wilson_ci(1, 2)
    _, hi_large = wilson_ci(50, 100)
    width_small = hi_small - wilson_ci(1, 2)[0]
    width_large = hi_large - wilson_ci(50, 100)[0]
    assert width_small > width_large


def test_single_trial_success():
    lo, hi = wilson_ci(1, 1)
    assert lo > 0.0
    assert hi == 1.0  # Wilson caps at 1.0 for 1/1


def test_single_trial_failure():
    lo, hi = wilson_ci(0, 1)
    assert lo == 0.0  # Wilson floors at 0.0 for 0/1
    assert hi < 1.0


def test_known_value():
    """Spot-check against hand-computed Wilson CI for 3/20 at z=1.96."""
    lo, hi = wilson_ci(3, 20)
    assert abs(lo - 0.0524) < 0.005
    assert abs(hi - 0.3604) < 0.005


def test_custom_z():
    """Narrower z → narrower interval."""
    lo_95, hi_95 = wilson_ci(5, 20, z=1.96)
    lo_90, hi_90 = wilson_ci(5, 20, z=1.645)
    width_95 = hi_95 - lo_95
    width_90 = hi_90 - lo_90
    assert width_90 < width_95
