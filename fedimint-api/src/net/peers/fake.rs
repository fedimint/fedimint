/// Fake (channel-based) implementation of [`super::DynPeerConnections`].
use std::time::Duration;

use async_trait::async_trait;
use fedimint_api::cancellable::{Cancellable, Cancelled};
use fedimint_api::net::peers::{DynPeerConnections, IPeerConnections};
use fedimint_api::task::TaskHandle;
use fedimint_api::PeerId;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::sleep;

struct FakePeerConnections<Msg> {
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    peer_id: PeerId,
    task_handle: TaskHandle,
}

#[async_trait]
impl<Msg> IPeerConnections<Msg> for FakePeerConnections<Msg>
where
    Msg: Serialize + DeserializeOwned + Unpin + Send,
{
    async fn send(&mut self, peers: &[PeerId], msg: Msg) -> Cancellable<()> {
        assert_eq!(peers, &[self.peer_id]);

        // If the peer is gone, just pretend we are going to resend
        // the msg eventually, even if it will never happen.
        let _ = self.tx.send(msg).await;
        Ok(())
    }

    async fn receive(&mut self) -> Cancellable<(PeerId, Msg)> {
        // Just like a real implementation, do not return
        // if the peer is gone.
        while !self.task_handle.is_shutting_down() {
            if let Some(msg) = self.rx.recv().await {
                return Ok((self.peer_id, msg));
            } else {
                sleep(Duration::from_secs(10)).await
            }
        }
        Err(Cancelled)
    }

    /// Removes a peer connection in case of misbehavior
    async fn ban_peer(&mut self, _peer: PeerId) {
        unimplemented!();
    }
}

/// Create a fake link between `peer1` and `peer2` for test purposes
///
/// `buf_size` controlls the size of the `tokio::mpsc::channel` used
/// under the hood (both ways).
pub fn make_fake_peer_connection<Msg>(
    peer1: PeerId,
    peer2: PeerId,
    buf_size: usize,
    task_handle: TaskHandle,
) -> (DynPeerConnections<Msg>, DynPeerConnections<Msg>)
where
    Msg: Serialize + DeserializeOwned + Unpin + Send + 'static,
{
    let (tx1, rx1) = mpsc::channel(buf_size);
    let (tx2, rx2) = mpsc::channel(buf_size);

    (
        FakePeerConnections {
            tx: tx1,
            rx: rx2,
            peer_id: peer2,
            task_handle: task_handle.clone(),
        }
        .into_dyn(),
        FakePeerConnections {
            tx: tx2,
            rx: rx1,
            peer_id: peer1,
            task_handle,
        }
        .into_dyn(),
    )
}
