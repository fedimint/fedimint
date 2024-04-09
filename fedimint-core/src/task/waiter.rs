//! Wait for a task to finish.

use tokio::sync::Semaphore;

/// Helper to wait for actions to be [`Self::done`]
#[derive(Debug)]
pub struct Waiter {
    done_semaphore: Semaphore,
}

impl Default for Waiter {
    fn default() -> Self {
        Self::new()
    }
}

impl Waiter {
    pub fn new() -> Self {
        Self {
            // semaphore never has permits.
            done_semaphore: Semaphore::new(0),
        }
    }

    /// Mark this waiter as done.
    ///
    /// NOTE: Calling this twice is ignored.
    pub fn done(&self) {
        // close the semaphore and notify all waiters.
        self.done_semaphore.close();
    }

    /// Wait for [`Self::done`] call.
    pub async fn wait(&self) {
        // wait for semaphore to be closed.
        self.done_semaphore
            .acquire()
            .await
            .expect_err("done semaphore is only closed, never has permits");
    }

    /// Check if Waiter was marked as done.
    pub fn is_done(&self) -> bool {
        self.done_semaphore.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn test_simple() {
        let waiter = Waiter::new();
        assert!(!waiter.is_done());
        waiter.done();
        assert!(waiter.is_done());
    }

    #[tokio::test]
    async fn test_async() {
        let waiter = Waiter::new();
        assert!(!waiter.is_done());
        tokio::join!(
            async {
                waiter.done();
            },
            async {
                waiter.wait().await;
            }
        );
        assert!(waiter.is_done());
        waiter.wait().await;
        assert!(waiter.is_done());
    }
    #[tokio::test]
    async fn test_async_multi() {
        let waiter = Waiter::new();
        assert!(!waiter.is_done());
        tokio::join!(
            async {
                waiter.done();
            },
            async {
                waiter.done();
            },
            async {
                waiter.done();
            },
        );
        assert!(waiter.is_done());
        waiter.wait().await;
        assert!(waiter.is_done());
    }
    #[tokio::test]
    async fn test_async_sleep() {
        let waiter = Waiter::new();
        assert!(!waiter.is_done());
        tokio::join!(
            async {
                fedimint_core::runtime::sleep(Duration::from_millis(10)).await;
                waiter.done();
            },
            waiter.wait(),
        );
        assert!(waiter.is_done());
        waiter.wait().await;
        assert!(waiter.is_done());
    }
}
