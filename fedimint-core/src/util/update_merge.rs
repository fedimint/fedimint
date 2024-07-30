use futures::Future;
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct UpdateMerge {
    last_failed: Mutex<bool>,
}

impl Default for UpdateMerge {
    fn default() -> Self {
        Self {
            last_failed: Mutex::new(false),
        }
    }
}
impl UpdateMerge {
    /// Merges concurrent futures execution.
    ///
    /// If two `merge` are called concurrently, the calls are merged.
    /// But if the first call fails, the second call is still run again.
    ///
    /// The future `fut` is never executed concurrently.
    pub async fn merge<E>(&self, fut: impl Future<Output = Result<(), E>>) -> Result<(), E> {
        let mut guard = if let Ok(guard) = self.last_failed.try_lock() {
            // not running => run now
            guard
        } else {
            // already running concurrently
            // wait for other call to return
            let guard = self.last_failed.lock().await;
            if *guard {
                // Last call failed. Run again.
                guard
            } else {
                // Last call completed successfully. Merge the call.
                return Ok(());
            }
        };
        // future may panic, use mark as failed initially
        *guard = true;
        // run the future and save last call status
        let result = fut.await;
        *guard = result.is_err();
        result
    }
}

#[cfg(test)]
mod tests {
    use futures::future;
    use tokio::test;

    use super::*;

    #[test]
    async fn test_merge_successful() {
        let update_merge = UpdateMerge::default();

        let result: Result<(), ()> = update_merge
            .merge(async {
                let _ = future::ready(Ok::<(), ()>(())).await;
                Ok::<(), ()>(())
            })
            .await;

        assert!(result.is_ok(), "Merge should be successful");
    }

    #[test]
    async fn test_merge_failed() {
        let update_merge = UpdateMerge::default();

        let result: Result<(), ()> = update_merge
            .merge(async {
                let _ = future::ready(Ok::<(), ()>(())).await;
                Err::<(), ()>(())
            })
            .await;

        assert!(result.is_err(), "Merge should fail");
    }

    #[tokio::test]
    async fn test_concurrent_merge() {
        let update_merge = UpdateMerge::default();

        let fut1 = async {
            let _ = future::ready(Ok::<(), ()>(())).await;
            update_merge
                .merge(async {
                    let _ = future::ready(Ok::<(), ()>(())).await;
                    Ok::<(), ()>(())
                })
                .await
        };
        let fut2 = async {
            let _ = future::ready(Ok::<(), ()>(())).await;
            update_merge
                .merge(async {
                    let _ = future::ready(Ok::<(), ()>(())).await;
                    Ok::<(), ()>(())
                })
                .await
        };

        let (result1, result2) = tokio::join!(fut1, fut2);

        assert!(
            result1.is_ok() && result2.is_ok(),
            "Both merges should be successful"
        );
    }
}
