use std::fmt::Display;
use std::sync::Arc;

use bitcoin::Network;
use fedimint_core::secp256k1::PublicKey;
use tokio::sync::RwLock;

use super::lightning::{ILnRpcClient, LightningBuilder};

pub struct LightningManager {
    /// Builder struct that allows the gateway to build a `ILnRpcClient`, which
    /// represents a connection to a lightning node.
    pub lightning_builder: Arc<dyn LightningBuilder + Send + Sync>,

    /// The current state of the Gateway.
    pub state: Arc<RwLock<GatewayState>>,
}

impl std::fmt::Debug for LightningManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightningManager")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl LightningManager {
    pub async fn set_state(&self, state: GatewayState) {
        *self.state.write().await = state;
    }
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    Initializing -- begin intercepting HTLCs --> Connected
///    Initializing -- gateway needs config --> Configuring
///    Configuring -- configuration set --> Connected
///    Connected -- load federation clients --> Running
///    Running -- disconnected from lightning node --> Disconnected
///    Disconnected -- re-established lightning connection --> Connected
/// ```
#[derive(Clone, Debug)]
pub enum GatewayState {
    Initializing,
    Configuring,
    Connected,
    Running { lightning_context: LightningContext },
    Disconnected,
}

impl Display for GatewayState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GatewayState::Initializing => write!(f, "Initializing"),
            GatewayState::Configuring => write!(f, "Configuring"),
            GatewayState::Connected => write!(f, "Connected"),
            GatewayState::Running { .. } => write!(f, "Running"),
            GatewayState::Disconnected => write!(f, "Disconnected"),
        }
    }
}

/// Represents an active connection to the lightning node.
#[derive(Clone, Debug)]
pub struct LightningContext {
    pub lnrpc: Arc<dyn ILnRpcClient>,
    pub lightning_public_key: PublicKey,
    pub lightning_alias: String,
    pub lightning_network: Network,
}
