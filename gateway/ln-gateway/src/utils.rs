use std::future::Future;
use std::result::Result;
use std::time::Duration;

use tokio::time::sleep;
use tracing::info;

/// Run the supplied closure `op_fn` up to `max_attempts` times. Wait for the
/// supplied `Duration` `interval` between attempts
///
/// # Returns
///
/// - If the closure runs successfully, the result is immediately returned
/// - If the closure did not run successfully for `max_attempts` times, the
///   error of the closure is returned
pub async fn retry<F, Fut, T>(
    op_name: String,
    op_fn: F,
    interval: Duration,
    max_attempts: u32,
) -> Result<T, anyhow::Error>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, anyhow::Error>>,
{
    assert_ne!(max_attempts, 0, "max_attempts must be greater than 0");
    let mut attempts = 0;
    loop {
        attempts += 1;
        match op_fn().await {
            Ok(result) => return Ok(result),
            Err(err) if attempts < max_attempts => {
                // run closure op_fn again
                info!(
                    "{} failed with error: {}. Retrying in {} seconds",
                    op_name,
                    err,
                    interval.as_secs()
                );
                sleep(interval).await;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::time::Duration;

    use anyhow::anyhow;

    use super::retry;

    #[tokio::test]
    async fn retry_succeed_with_one_attempt() {
        let counter = AtomicU8::new(0);
        let closure = || async {
            counter.fetch_add(1, Ordering::SeqCst);
            // always return a success
            Ok(42)
        };

        let _ = retry("Run once".to_string(), closure, Duration::ZERO, 3).await;

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retry_fail_with_three_attempts() {
        let counter = AtomicU8::new(0);
        let closure = || async {
            counter.fetch_add(1, Ordering::SeqCst);
            // always fail
            Err::<(), anyhow::Error>(anyhow!("42"))
        };

        let _ = retry("Run 3 times".to_string(), closure, Duration::ZERO, 3).await;

        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }
}
