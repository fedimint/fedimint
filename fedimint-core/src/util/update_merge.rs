use futures::Future;
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct UpdateMerge {
    last_failed: Mutex<bool>,
}

impl Default for UpdateMerge {
    fn default() -> Self {
        UpdateMerge {
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
            match *guard {
                // last call completed successfully
                // => merge the call
                false => return Ok(()),
                // last call failed
                // => run again
                true => guard,
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
