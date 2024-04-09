use fedimint_logging::LOG_CONSENSUS;
use tracing::warn;

#[derive(Clone)]
pub struct Spawner;

impl Spawner {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Spawner {
    fn default() -> Self {
        Self::new()
    }
}

impl aleph_bft::SpawnHandle for Spawner {
    fn spawn(&self, name: &str, task: impl futures::Future<Output = ()> + Send + 'static) {
        fedimint_core::runtime::spawn(name, task);
    }

    fn spawn_essential(
        &self,
        name: &str,
        task: impl futures::Future<Output = ()> + Send + 'static,
    ) -> aleph_bft::TaskHandle {
        let (res_tx, res_rx) = futures::channel::oneshot::channel();

        fedimint_core::runtime::spawn(name, async move {
            task.await;
            if let Err(_err) = res_tx.send(()) {
                warn!(target: LOG_CONSENSUS, "Unable to send essential spawned task completion. Are we shutting down?");
            }
        });

        Box::pin(async move { res_rx.await.map_err(|_| ()) })
    }
}
