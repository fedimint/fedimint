use std::{future::Future, result::Result, time::Duration};

use tokio::time::sleep;
use tracing::info;

/// Retry an operation util the operation succeeds, OR
/// The maximum number of attempts are made without success
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
                    wait.as_secs()
                );
                sleep(wait).await;
            }
            Err(err) => return Err(err),
        }
    }
}
