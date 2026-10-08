use std::cell::Cell;

use anyhow::{Result, bail};

use super::poll_simple;

/// Regression test for the race where a file becomes readable before its
/// writer has finished writing a valid value: `poll_simple` must retry an
/// `Err` returned by the parse step itself, not just an `Err` from the read.
#[tokio::test]
async fn poll_simple_retries_transient_parse_failure() -> Result<()> {
    let attempts = Cell::new(0u32);

    let result = poll_simple("test-transient-parse-failure", || async {
        let attempt = attempts.get() + 1;
        attempts.set(attempt);

        if attempt < 3 {
            bail!("simulated partially-written value on attempt {attempt}");
        }

        Ok(attempt)
    })
    .await?;

    assert_eq!(result, 3);
    assert_eq!(attempts.get(), 3);

    Ok(())
}
