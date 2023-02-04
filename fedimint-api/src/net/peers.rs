use std::ops::Deref;
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_api::PeerId;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::cancellable::Cancellable;

#[cfg(not(target_family = "wasm"))]
pub mod fake;

/// Owned [`PeerConnections`] trait object type
pub struct PeerConnections<Msg>(Arc<dyn IPeerConnections<Msg> + Send + Sync + 'static>);

impl<Msg> Deref for PeerConnections<Msg> {
    type Target = dyn IPeerConnections<Msg> + Send + Sync + 'static;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

/// Connection manager that tries to keep connections open to all peers
///
/// Production implementations of this trait have to ensure that:
/// * Connections to peers are authenticated and encrypted
/// * Messages are received exactly once and in the order they were sent
/// * Connections are reopened when closed
/// * Messages are cached in case of short-lived network interruptions and resent on reconnect, this
///   avoids the need to rejoin the consensus, which is more tricky.
///
/// In case of longer term interruptions the message cache has to be dropped to avoid DoS attacks.
/// The thus disconnected peer will need to rejoin the consensus at a later time.  
#[async_trait]
pub trait IPeerConnections<Msg>
where
    Msg: Serialize + DeserializeOwned + Sync + Send,
{
    /// Send a message to a specific peer.
    ///
    /// The message is sent immediately and cached if the peer is reachable and only cached
    /// otherwise.
    async fn send(&self, peers: &[PeerId], msg: Msg) -> Cancellable<()>;

    /// Await receipt of a message from any connected peer.
    async fn receive(&self) -> Cancellable<(PeerId, Msg)>;

    /// Removes a peer connection in case of misbehavior
    async fn ban_peer(&self, peer: PeerId);

    /// Converts the struct to a `PeerConnection` trait object
    fn into_dyn(self) -> PeerConnections<Msg>
    where
        Self: Sized + Send + Sync + 'static,
    {
        PeerConnections(Arc::new(self))
    }
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
/// Like [`IPeerConnections`] but with an ability to handle multiple destinations (like modules) per each peer-connection.
///
/// Notably, unlike [`IPeerConnections`] implementations need to be thread-safe,
/// as the primary intendet use should support multiple threads using multiplexed
/// channel at the same time.
pub trait IMuxPeerConnections<MuxKey, Msg>
where
    Msg: Serialize + DeserializeOwned + Sync + Send,
    MuxKey: Serialize + DeserializeOwned + Sync + Send,
{
    /// Send a message to a specific destination at specific peer.
    async fn send(&self, peers: &[PeerId], mux_key: MuxKey, msg: Msg) -> Cancellable<()>;

    /// Await receipt of a message from any connected peer.
    async fn receive(&self, mux_key: MuxKey) -> Cancellable<(PeerId, Msg)>;

    /// Removes a peer connection in case of misbehavior
    async fn ban_peer(&self, peer: PeerId);

    /// Converts the struct to a `PeerConnection` trait object
    fn into_dyn(self) -> MuxPeerConnections<MuxKey, Msg>
    where
        Self: Sized + Send + Sync + Unpin + 'static,
    {
        MuxPeerConnections(Arc::new(self))
    }
}
