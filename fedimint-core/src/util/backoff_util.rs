use std::time::Duration;

pub use backon::{Backoff, ConstantBackoff, FibonacciBackoff};
use backon::{BackoffBuilder, ConstantBuilder, FibonacciBuilder};

/// Backoff strategy for background tasks.
///
/// Starts at 1s and increases to 60s, never giving up.
pub fn background_backoff() -> FibonacciBackoff {
    custom_backoff(Duration::from_secs(1), Duration::from_secs(60), None)
}

/// A backoff strategy for relatively quick foreground operations.
///
/// Starts at 200ms and increases to 5s. Will retry 10 times before giving up,
/// with a maximum total delay between 20.8s and 22.8s depending on jitter.
pub fn aggressive_backoff() -> FibonacciBackoff {
    // Not accounting for jitter, the delays are:
    // 0.2, 0.2, 0.4, 0.6, 1.0, 1.6, 2.6, 4.2, 5.0, 5.0.
    //
    // Jitter adds a random value between 0 and `min_delay` to each delay.
    // Total jitter is between 0 and (10 * 0.2) = 2.0.
    //
    // Maximum possible delay including jitter is 22.8 seconds.
    custom_backoff(Duration::from_millis(200), Duration::from_secs(5), Some(10))
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

pub fn custom_constant_backoff(delay: Duration, max_times: Option<usize>) -> ConstantBackoff {
    ConstantBuilder::default()
        .with_delay(delay)
        .with_max_times(max_times.unwrap_or(usize::MAX))
        .build()
}
