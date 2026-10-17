use std::time::Duration;

use super::{Stats, assert_latency_stats};

fn stats(median: u64, p90: u64, max: u64) -> Stats {
    Stats {
        min: Duration::ZERO,
        avg: Duration::ZERO,
        median: Duration::from_secs(median),
        p90: Duration::from_secs(p90),
        max: Duration::from_secs(max),
        sum: Duration::ZERO,
    }
}

#[test]
fn latency_distribution_below_limits_passes() {
    assert_latency_stats(&stats(1, 9, 89), Duration::from_secs(10));
}

#[test]
#[should_panic(expected = "stats.median < median_limit")]
fn latency_median_limit_is_strict() {
    assert_latency_stats(&stats(10, 11, 12), Duration::from_secs(10));
}

#[test]
#[should_panic(expected = "stats.p90 < stats.median * 10")]
fn latency_p90_factor_is_strict() {
    assert_latency_stats(&stats(1, 10, 11), Duration::from_secs(10));
}

#[test]
#[should_panic(expected = "stats.max.as_secs_f64() < stats.p90.as_secs_f64() * 10.0")]
fn latency_max_factor_is_strict() {
    assert_latency_stats(&stats(1, 2, 20), Duration::from_secs(10));
}

#[test]
fn internal_payments_keep_their_larger_median_allowance() {
    assert_latency_stats(&stats(14, 15, 16), Duration::from_secs(15));
}
