use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fedimint_core::bitcoin::Network;
use fedimint_core::core::ModuleKind;
use fedimint_core::module::ApiAuth;
use fedimint_core::module::audit::AuditSummary;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Feerate, PeerId};

use crate::{DynServerModule, ServerModule};

pub type DynDashboardApi = Arc<dyn IDashboardApi + Send + Sync + 'static>;

/// Interface for guardian dashboard API in a running federation
#[async_trait]
pub trait IDashboardApi {
    /// Get the guardian's authentication details
    async fn auth(&self) -> ApiAuth;

    /// Get the guardian ID
    async fn guardian_id(&self) -> PeerId;

    /// Get a map of peer IDs to guardian names
    async fn guardian_names(&self) -> BTreeMap<PeerId, String>;

    /// Get the federation name
    async fn federation_name(&self) -> String;

    /// Get the current active session count
    async fn session_count(&self) -> usize;

    /// The time it took to order our last proposal in the current session
    async fn consensus_ord_latency(&self) -> Option<Duration>;

    /// Returns a map of peer ID to estimated round trip time
    async fn p2p_connection_status(&self) -> BTreeMap<PeerId, Option<Duration>>;

    /// Get the federation invite code to share with users
    async fn federation_invite_code(&self) -> String;

    /// Get the federation audit summary
    async fn federation_audit(&self) -> AuditSummary;

    /// Get the url of the bitcoin rpc
    async fn bitcoin_rpc_url(&self) -> SafeUrl;

    /// Get the status of the bitcoin backend
    async fn bitcoin_rpc_status(&self) -> Option<ServerBitcoinRpcStatus>;

    /// Get reference to a server module instance by module kind
    fn get_module_by_kind(&self, kind: ModuleKind) -> Option<&DynServerModule>;

    /// Get a list of modules supported by the server
    fn supported_modules(&self) -> Vec<String>;

    /// Create a trait object
    fn into_dyn(self) -> DynDashboardApi
    where
        Self: Sized + Send + Sync + 'static,
    {
        Arc::new(self)
    }
}

/// Extension trait for IDashboardApi providing type-safe module access
pub trait DashboardApiModuleExt {
    /// Get a typed reference to a server module instance by kind
    fn get_module<M: ServerModule + 'static>(&self) -> Option<&M>;
}

impl DashboardApiModuleExt for DynDashboardApi {
    fn get_module<M: ServerModule + 'static>(&self) -> Option<&M> {
        self.get_module_by_kind(M::module_kind())?
            .as_any()
            .downcast_ref::<M>()
    }
}

#[derive(Debug, Clone)]
pub struct ServerBitcoinRpcStatus {
    pub network: Network,
    pub block_count: u64,
    pub fee_rate: Feerate,
    pub sync_percentage: Option<f64>,
}
