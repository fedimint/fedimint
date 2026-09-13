//! Provides an abstract network connector interface and multiple
//! implementations

mod iroh;
mod tls;

use std::sync::Arc;

use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_server_core::dashboard_ui::ConnectionType;

pub use self::iroh::*;
pub use self::tls::*;
use crate::net::p2p_connection::DynP2PConnection;

pub type DynP2PConnector<M> = Arc<dyn IP2PConnector<M>>;

/// Experimental transport negotiation; never encoded in application messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P2PProtocol {
    /// One bidirectional session, owned by the lower peer ID.
    Legacy,
    /// One session per application direction, owned by its sender.
    DualV1,
}

/// Private, experimental ALPN. Both endpoints must negotiate it.
pub(crate) const DUAL_P2P_ALPN: &[u8] = b"FEDIMINT_P2P_DUAL_V1";

/// Allows to connect to peers and to listen for incoming connections.
/// Connections are message based and should be authenticated and encrypted for
/// production deployments.
#[async_trait]
pub trait IP2PConnector<M>: Send + Sync + 'static {
    fn peers(&self) -> Vec<PeerId>;

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<M>>;

    /// Reverse dial after authenticated dual discovery. Callers must still
    /// inspect the result: old TLS servers can complete without selecting ALPN.
    async fn connect_dual(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<M>> {
        self.connect(peer).await
    }

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<M>)>;

    /// Get the connection type for a specific peer
    fn connection_type(&self, peer: PeerId) -> Option<ConnectionType>;

    fn into_dyn(self) -> DynP2PConnector<M>
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}
