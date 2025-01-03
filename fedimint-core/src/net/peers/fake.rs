/// Fake (channel-based) implementation of [`super::PeerConnections`].
use async_trait::async_trait;
use fedimint_core::net::peers::{IPeerConnections, PeerConnections};
use fedimint_core::task::TaskHandle;
use fedimint_core::PeerId;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::net::peers::Recipient;

struct FakePeerConnections<Msg> {
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    peer_id: PeerId,
    task_handle: TaskHandle,
}

#[async_trait]
impl<M> IPeerConnections<M> for FakePeerConnections<M>
where
    M: Serialize + DeserializeOwned + Unpin + Send,
{
    async fn send(&mut self, recipient: Recipient, msg: M) {
        assert_eq!(recipient, Recipient::Peer(self.peer_id));

        // If the peer is gone, just pretend we are going to resend
        // the msg eventually, even if it will never happen.
        self.tx.send(msg).await.ok();
    }

    fn try_send(&self, recipient: Recipient, msg: M) {
        assert_eq!(recipient, Recipient::Peer(self.peer_id));

        // If the peer is gone, just pretend we are going to resend
        // the msg eventually, even if it will never happen.
        self.tx.try_send(msg).ok();
    }

    async fn receive(&mut self) -> Option<(PeerId, M)> {
        tokio::select! {
            message =  self.rx.recv() => {
                message.map(|msg| (self.peer_id, msg))
            }
            () = self.task_handle.make_shutdown_rx() => {
                None
            },
        }
    }
}

/// Create a fake link between `peer1` and `peer2` for test purposes
///
/// `buf_size` controls the size of the `tokio::mpsc::channel` used
/// under the hood (both ways).
pub fn make_fake_peer_connection<Msg>(
    peer1: PeerId,
    peer2: PeerId,
    buf_size: usize,
    task_handle: TaskHandle,
) -> (PeerConnections<Msg>, PeerConnections<Msg>)
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
