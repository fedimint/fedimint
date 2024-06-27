use std::fmt::Display;
use std::sync::Arc;

use bitcoin::Network;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::task::TaskGroup;
use tokio::sync::RwLock;
use tracing::error;

use super::lightning::{ILnRpcClient, LightningBuilder, LightningRpcError};
use crate::lightning::cln::RouteHtlcStream;

pub struct LightningManager {
    /// Builder struct that allows the gateway to build a `ILnRpcClient`, which
    /// represents a connection to a lightning node.
    lightning_builder: Arc<dyn LightningBuilder + Send + Sync>,

    /// The current state of the Gateway.
    state: Arc<RwLock<GatewayState>>,

    /// Task group for managing HTLC interception.
    /// Is `Some` when the gateway is intercepting HTLCs, `None` otherwise.
    htlc_task_group_or: Arc<RwLock<Option<TaskGroup>>>,
}

impl std::fmt::Debug for LightningManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightningManager")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl LightningManager {
    pub fn new_initializing(lightning_builder: Arc<dyn LightningBuilder + Send + Sync>) -> Self {
        Self {
            lightning_builder,
            state: Arc::new(RwLock::new(GatewayState::Initializing)),
            htlc_task_group_or: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn connect_route_htlcs(
        &self,
        task_group: TaskGroup,
    ) -> Result<(RouteHtlcStream, Arc<dyn ILnRpcClient>), LightningRpcError> {
        // If the gateway is already connected, stop the current HTLC interception.
        self.stop_route_htlcs().await;

        let (stream, ln_client) = self
            .lightning_builder
            .build()
            .await
            .route_htlcs(&task_group)
            .await?;

        self.set_state(GatewayState::Connected).await;

        *self.htlc_task_group_or.write().await = Some(task_group);

        Ok((stream, ln_client))
    }

    /// Sets the gateway state to `Disconnected` and shuts down the task that is
    /// listening for intercepted HTLCs if it is running.
    pub async fn disconnect_stop_route_htlcs(&self) {
        self.set_state(GatewayState::Disconnected).await;
        self.stop_route_htlcs().await;
    }

    /// Shuts down the task that is listening for intercepted HTLCs if it is
    /// running.
    async fn stop_route_htlcs(&self) {
        if let Some(htlc_task_group) = self.htlc_task_group_or.write().await.take() {
            if let Err(e) = htlc_task_group.shutdown_join_all(None).await {
                error!("HTLC task group shutdown errors: {}", e);
            }
        }
    }

    pub async fn get_state(&self) -> GatewayState {
        self.state.read().await.clone()
    }

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
