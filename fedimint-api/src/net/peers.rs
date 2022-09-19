use async_trait::async_trait;
use fedimint_api::PeerId;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Owned [`PeerConnections`] trait object type
pub type AnyPeerConnections<M> = Box<dyn PeerConnections<M> + Send + Unpin + 'static>;

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
pub trait PeerConnections<T>
where
    T: Serialize + DeserializeOwned + Unpin + Send,
{
    /// Send a message to a specific peer.
    ///
    /// The message is sent immediately and cached if the peer is reachable and only cached
    /// otherwise.
    async fn send(&mut self, peers: &[PeerId], msg: T);

    /// Await receipt of a message from any connected peer.
    async fn receive(&mut self) -> (PeerId, T);

    /// Removes a peer connection in case of misbehavior
    async fn ban_peer(&mut self, peer: PeerId);

    /// Converts the struct to a `PeerConnection` trait object
    fn into_dyn(self) -> AnyPeerConnections<T>
    where
        Self: Sized + Send + Unpin + 'static,
    {
        Box::new(self)
    }
}
