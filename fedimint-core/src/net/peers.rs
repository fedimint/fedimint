use std::ops::Deref;
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_core::PeerId;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::task::Cancellable;

#[cfg(not(target_family = "wasm"))]
pub mod fake;

pub type DynP2PConnections<M> = Arc<dyn IP2PConnections<M>>;

/// Connection manager that tries to keep connections open to all peers
#[async_trait]
pub trait IP2PConnections<M>: Send + Sync + 'static {
    /// Send message to recipient; block if channel is full.
    async fn send(&self, recipient: Recipient, msg: M);

    /// Try to send message to recipient; drop message if channel is full.
    fn try_send(&self, recipient: Recipient, msg: M);

    /// Await receipt of a message; return None if we are shutting down.
    async fn receive(&self) -> Option<(PeerId, M)>;

    /// Convert the struct to trait object.
    fn into_dyn(self) -> DynP2PConnections<M>
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}

/// This enum defines the intended recipient of a p2p message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    Everyone,
    Peer(PeerId),
}

/// Owned [`MuxPeerConnections`] trait object type
#[derive(Clone)]
pub struct MuxPeerConnections<MuxKey, Msg>(
    Arc<dyn IMuxPeerConnections<MuxKey, Msg> + Send + Sync + Unpin + 'static>,
);

impl<MuxKey, Msg> Deref for MuxPeerConnections<MuxKey, Msg> {
    type Target = dyn IMuxPeerConnections<MuxKey, Msg> + Send + Sync + Unpin + 'static;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

#[async_trait]
/// Like [`IP2PConnections`] but with an ability to handle multiple
/// destinations (like modules) per each peer-connection.
///
/// Notably, unlike [`IP2PConnections`] implementations need to be thread-safe,
/// as the primary intended use should support multiple threads using
/// multiplexed channel at the same time.
pub trait IMuxPeerConnections<MuxKey, Msg>
where
    Msg: Serialize + DeserializeOwned + Unpin + Send,
    MuxKey: Serialize + DeserializeOwned + Unpin + Send,
{
    /// Send a message to a specific destination at specific peer.
    async fn send(&self, peers: &[PeerId], mux_key: MuxKey, msg: Msg) -> Cancellable<()>;

    /// Await receipt of a message from any connected peer.
    async fn receive(&self, mux_key: MuxKey) -> Cancellable<(PeerId, Msg)>;

    /// Converts the struct to a `PeerConnection` trait object
    fn into_dyn(self) -> MuxPeerConnections<MuxKey, Msg>
    where
        Self: Sized + Send + Sync + Unpin + 'static,
    {
        MuxPeerConnections(Arc::new(self))
    }
}
