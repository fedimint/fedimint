use std::{future::Future, result::Result, time::Duration};

use tokio::time::sleep;
use tracing::info;

/// Retry an operation util the operation succeeds, OR
/// The maximum number of attempts are made without success
pub async fn retry<F, R, T>(
    op_name: String,
    op_fn: F,
    wait: Duration,
    max_retries: u32,
) -> Result<T, anyhow::Error>
where
    F: Fn() -> R,
    R: Future<Output = Result<T, anyhow::Error>>,
{
    let mut att = 0;
    loop {
        match op_fn().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                att += 1;
                if att > max_retries {
                    return Err(e);
                }
                info!(
                    "{} failed with error: {}. Retrying in {} seconds",
                    op_name,
                    e,
                    wait.as_secs()
                );
                sleep(wait).await;
            }
        }
    }
}
