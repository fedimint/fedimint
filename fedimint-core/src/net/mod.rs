pub mod api_announcement;
pub mod auth;
pub mod guardian_metadata;
pub mod iroh;

#[cfg(not(target_family = "wasm"))]
pub mod fake;

pub const STANDARD_FEDIMINT_P2P_PORT: u16 = 8173;

use std::sync::Arc;

use async_trait::async_trait;
use fedimint_core::PeerId;

pub type DynP2PConnections<M> = Arc<dyn IP2PConnections<M>>;

/// Connection manager that tries to keep connections open to all peers
#[async_trait]
pub trait IP2PConnections<M>: Send + Sync + 'static {
    /// Send message to recipient; drop message if channel is full.
    fn send(&self, recipient: Recipient, msg: M);

    /// Await the next message; return None if we are shutting down.
    async fn receive(&self) -> Option<(PeerId, M)>;

    /// Await the next message from peer; return None if we are shutting down.
    async fn receive_from_peer(&self, peer: PeerId) -> Option<M>;

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
