use std::{future::Future, result::Result, time::Duration};

use tokio::time::sleep;
use tracing::info;

/// Run the given closure up to `max_attempts` times while waiting for
/// the specified `Duration` between attempts
///
/// # Returns
///
/// - If the closure is run succesfully, the result is immediately
///   returned.
/// - The closure is run at most `max_attempts` times after which the
///   error of the closure is returned.
pub async fn retry<F, Fut, T>(
    op_name: String,
    op_fn: F,
    wait: Duration,
    max_attempts: u32,
) -> Result<T, anyhow::Error>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, anyhow::Error>>,
{
    let mut counter = 1;
    loop {
        match op_fn().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                if counter == max_attempts {
                    return Err(err);
                }
                info!(
                    "{} failed with error: {}. Retrying in {} seconds",
                    op_name,
                    err,
                    wait.as_secs()
                );
                sleep(wait).await;
                counter += 1;
            }
        }
    }
}
