use fedimint_core::task::TaskGroup;
use fedimint_logging::LOG_CONSENSUS;
use tracing::warn;

#[derive(Clone)]
pub struct Spawner {
    task_group: TaskGroup,
}

impl Spawner {
    pub fn new(task_group: TaskGroup) -> Self {
        Self { task_group }
    }
}

impl aleph_bft::SpawnHandle for Spawner {
    fn spawn(&self, name: &str, task: impl futures::Future<Output = ()> + Send + 'static) {
        self.task_group.spawn_silent(name, |_| task);
    }

    fn spawn_essential(
        &self,
        name: &str,
        task: impl futures::Future<Output = ()> + Send + 'static,
    ) -> aleph_bft::TaskHandle {
        let (sender, receiver) = futures::channel::oneshot::channel();

        self.task_group.spawn_silent(name, |_| async {
            task.await;

            if sender.send(()).is_err() {
                warn!(target: LOG_CONSENSUS, "Unable to send essential spawned task completion. Are we shutting down?");
            }
        });

        Box::pin(async { receiver.await.map_err(|_| ()) })
    }
}
