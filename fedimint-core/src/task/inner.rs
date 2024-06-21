use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use fedimint_core::time::now;
use fedimint_logging::LOG_TASK;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{watch, Mutex};
use tracing::{debug, error, info, warn};

use super::{TaskGroup, TaskShutdownToken};
use crate::runtime::{JoinError, JoinHandle};

#[derive(Debug)]
pub struct TaskGroupInner {
    on_shutdown_tx: watch::Sender<bool>,
    // It is necessary to keep at least one `Receiver` around,
    // otherwise shutdown writes are lost.
    on_shutdown_rx: watch::Receiver<bool>,
    join_handle_sender: UnboundedSender<(String, JoinHandle<()>)>,
    join_handle_receiver: Mutex<UnboundedReceiver<(String, JoinHandle<()>)>>,
    // using blocking Mutex to avoid `async` in `shutdown` and `add_subgroup`
    // it's OK as we don't ever need to yield
    subgroups: std::sync::Mutex<Vec<TaskGroup>>,
}

impl Default for TaskGroupInner {
    fn default() -> Self {
        let (on_shutdown_tx, on_shutdown_rx) = watch::channel(false);
        let (join_handle_sender, join_handle_receiver) = unbounded_channel();
        Self {
            on_shutdown_tx,
            on_shutdown_rx,
            join_handle_sender,
            join_handle_receiver: Mutex::new(join_handle_receiver),
            subgroups: std::sync::Mutex::new(vec![]),
        }
    }
}

impl TaskGroupInner {
    pub fn shutdown(&self) {
        // Note: set the flag before starting to call shutdown handlers
        // to avoid confusion.
        self.on_shutdown_tx
            .send(true)
            .expect("We must have on_shutdown_rx around so this never fails");

        let subgroups = self.subgroups.lock().expect("locking failed").clone();
        for subgroup in subgroups {
            subgroup.inner.shutdown();
        }
    }

    #[inline]
    pub fn is_shutting_down(&self) -> bool {
        *self.on_shutdown_tx.borrow()
    }

    #[inline]
    pub fn make_shutdown_rx(&self) -> TaskShutdownToken {
        TaskShutdownToken::new(self.on_shutdown_rx.clone())
    }

    #[inline]
    pub fn add_subgroup(&self, tg: TaskGroup) {
        self.subgroups.lock().expect("locking failed").push(tg);
    }

    #[inline]
    pub async fn join_all(&self, deadline: Option<SystemTime>, errors: &mut Vec<JoinError>) {
        let subgroups = self.subgroups.lock().expect("locking failed").clone();
        for subgroup in subgroups {
            info!(target: LOG_TASK, "Waiting for subgroup to finish");
            subgroup.join_all_inner(deadline, errors).await;
            info!(target: LOG_TASK, "Subgroup finished");
        }

        // drop lock early
        while let Ok((name, join)) = {
            let mut lock = self.join_handle_receiver.lock().await;
            lock.try_recv()
        } {
            debug!(target: LOG_TASK, task=%name, "Waiting for task to finish");

            let timeout = deadline.map(|deadline| {
                deadline
                    .duration_since(now())
                    .unwrap_or(Duration::from_millis(10))
            });

            #[cfg(not(target_family = "wasm"))]
            let join_future: Pin<Box<dyn Future<Output = _> + Send>> =
                if let Some(timeout) = timeout {
                    Box::pin(crate::runtime::timeout(timeout, join))
                } else {
                    Box::pin(async { Ok(join.await) })
                };

            #[cfg(target_family = "wasm")]
            let join_future: Pin<Box<dyn Future<Output = _>>> = if let Some(timeout) = timeout {
                Box::pin(crate::runtime::timeout(timeout, join))
            } else {
                Box::pin(async { Ok(join.await) })
            };

            match join_future.await {
                Ok(Ok(())) => {
                    debug!(target: LOG_TASK, task=%name, "Task finished");
                }
                Ok(Err(e)) => {
                    error!(target: LOG_TASK, task=%name, error=%e, "Task panicked");
                    errors.push(e);
                }
                Err(_) => {
                    warn!(
                        target: LOG_TASK, task=%name,
                        "Timeout waiting for task to shut down"
                    );
                }
            }
        }
    }

    #[inline]
    pub fn add_join_handle(&self, name: String, handle: JoinHandle<()>) {
        self.join_handle_sender
            .send((name, handle))
            .expect("We must have join_handle_receiver around so this never fails");
    }
}
