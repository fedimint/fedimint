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

/// Allows to connect to peers and to listen for incoming connections.
/// Connections are message based and should be authenticated and encrypted for
/// production deployments.
#[async_trait]
pub trait IP2PConnector<M>: Send + Sync + 'static {
    fn peers(&self) -> Vec<PeerId>;

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<M>>;

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<M>)>;

    /// Get the connection type for a specific peer
    async fn connection_type(&self, peer: PeerId) -> ConnectionType;

    fn into_dyn(self) -> DynP2PConnector<M>
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}
