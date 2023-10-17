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
        fedimint_core::task::spawn(name, task);
    }

    fn spawn_essential(
        &self,
        name: &str,
        task: impl futures::Future<Output = ()> + Send + 'static,
    ) -> aleph_bft::TaskHandle {
        let (res_tx, res_rx) = futures::channel::oneshot::channel();

        fedimint_core::task::spawn(name, async move {
            task.await;
            res_tx.send(()).expect("We own the rx.");
        });

        Box::pin(async move { res_rx.await.map_err(|_| ()) })
    }
}
