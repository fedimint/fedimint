#[derive(Clone)]
pub struct Spawner;

impl Spawner {
    pub fn new() -> Self {
        Self {}
    }
}

impl aleph_bft::SpawnHandle for Spawner {
    fn spawn(&self, _name: &str, task: impl futures::Future<Output = ()> + Send + 'static) {
        tokio::spawn(task);
    }

    fn spawn_essential(
        &self,
        _: &str,
        task: impl futures::Future<Output = ()> + Send + 'static,
    ) -> aleph_bft::TaskHandle {
        let (res_tx, res_rx) = futures::channel::oneshot::channel();

        tokio::spawn(async move {
            task.await;
            res_tx.send(()).expect("We own the rx.");
        });

        Box::pin(async move { res_rx.await.map_err(|_| ()) })
    }
}
