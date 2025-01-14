use async_channel::bounded;
/// Fake (channel-based) implementation of [`super::DynP2PConnections`].
use async_trait::async_trait;
use fedimint_core::net::peers::{DynP2PConnections, IP2PConnections};
use fedimint_core::PeerId;

use crate::net::peers::Recipient;

#[derive(Clone)]
struct FakePeerConnections<M> {
    tx: async_channel::Sender<M>,
    rx: async_channel::Receiver<M>,
    peer: PeerId,
}

#[async_trait]
impl<M: Clone + Send + 'static> IP2PConnections<M> for FakePeerConnections<M> {
    async fn send(&self, recipient: Recipient, msg: M) {
        assert_eq!(recipient, Recipient::Peer(self.peer));

        // If the peer is gone, just pretend we are going to resend
        // the msg eventually, even if it will never happen.
        self.tx.send(msg).await.ok();
    }

    fn try_send(&self, recipient: Recipient, msg: M) {
        assert_eq!(recipient, Recipient::Peer(self.peer));

        // If the peer is gone, just pretend we are going to resend
        // the msg eventually, even if it will never happen.
        self.tx.try_send(msg).ok();
    }

    async fn receive(&self) -> Option<(PeerId, M)> {
        self.rx.recv().await.map(|msg| (self.peer, msg)).ok()
    }

    async fn receive_from_peer(&self, _peer: PeerId) -> Option<M> {
        self.rx.recv().await.ok()
    }

    async fn await_empty_outgoing_message_queues(&self) {
        unimplemented!()
    }
}

/// Create a fake link between `peer1` and `peer2` for test purposes
///
/// `buf_size` controls the size of the `tokio::mpsc::channel` used
/// under the hood (both ways).
pub fn make_fake_peer_connection<M: Clone + Send + 'static>(
    peer_1: PeerId,
    peer_2: PeerId,
    buf_size: usize,
) -> (DynP2PConnections<M>, DynP2PConnections<M>) {
    let (tx1, rx1) = bounded(buf_size);
    let (tx2, rx2) = bounded(buf_size);

    let c_1 = FakePeerConnections {
        tx: tx1,
        rx: rx2,
        peer: peer_2,
    };

    let c_2 = FakePeerConnections {
        tx: tx2,
        rx: rx1,
        peer: peer_1,
    };

    (c_1.into_dyn(), c_2.into_dyn())
}
