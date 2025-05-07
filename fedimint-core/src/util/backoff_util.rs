use std::time::Duration;

pub use backon::{Backoff, FibonacciBackoff};
use backon::{BackoffBuilder, FibonacciBuilder};

/// Backoff strategy for background tasks.
///
/// Starts at 1s and increases to 60s, never giving up.
pub fn background_backoff() -> FibonacciBackoff {
    custom_backoff(Duration::from_secs(1), Duration::from_secs(60), None)
}

/// A backoff strategy for relatively quick foreground operations.
pub fn aggressive_backoff() -> FibonacciBackoff {
    custom_backoff(Duration::from_millis(200), Duration::from_secs(5), Some(14))
}

pub fn aggressive_backoff_long() -> FibonacciBackoff {
    custom_backoff(Duration::from_millis(200), Duration::from_secs(5), Some(25))
}

#[cfg(test)]
pub fn immediate_backoff(max_retries_or: Option<usize>) -> FibonacciBackoff {
    custom_backoff(Duration::ZERO, Duration::ZERO, max_retries_or)
}

pub fn custom_backoff(
    min_delay: Duration,
    max_delay: Duration,
    max_retries_or: Option<usize>,
) -> FibonacciBackoff {
    FibonacciBuilder::default()
        .with_jitter()
        .with_min_delay(min_delay)
        .with_max_delay(max_delay)
        .with_max_times(max_retries_or.unwrap_or(usize::MAX))
        .build()
}

/// Retry every max 10s for up to one hour, with a more aggressive fibonacci
/// backoff in the beginning to reduce expected latency.
///
/// Starts at 200ms increasing to 10s. Retries 360 times before giving up, with
/// a maximum total delay between 3527.6s (58m 47.6s) and 3599.6s (59m 59.6s)
/// depending on jitter.
pub fn fibonacci_max_one_hour() -> FibonacciBackoff {
    // Not accounting for jitter, the delays are:
    // 0.2, 0.2, 0.4, 0.6, 1.0, 1.6, 2.6, 4.2, 6.8, 10.0...
    //
    // Jitter adds a random value between 0 and `min_delay` to each delay.
    // Total jitter is between 0 and (360 * 0.2) = 72.0.
    //
    // Maximum possible delay including jitter is 3599.6s seconds.
    custom_backoff(
        Duration::from_millis(200),
        Duration::from_secs(10),
        Some(360),
    )
}

pub fn api_networking_backoff() -> FibonacciBackoff {
    custom_backoff(Duration::from_millis(250), Duration::from_secs(10), None)
}
