use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use fedimint_core::core::ModuleKind;
use fedimint_core::module::ApiAuth;

pub type DynSetupApi = Arc<dyn ISetupApi + Send + Sync + 'static>;

/// Interface for the web UI to interact with the config generation process
#[async_trait]
pub trait ISetupApi {
    /// Get our connection info encoded as base32 string
    async fn setup_code(&self) -> Option<String>;

    /// Get our guardian name
    async fn guardian_name(&self) -> Option<String>;

    /// Get the auth token for API calls
    async fn auth(&self) -> Option<ApiAuth>;

    /// Get list of names of connected peers
    async fn connected_peers(&self) -> Vec<String>;

    /// Get the available modules that can be enabled during setup
    fn available_modules(&self) -> BTreeSet<ModuleKind>;

    /// Get the modules that should be enabled by default in the setup UI
    fn default_modules(&self) -> BTreeSet<ModuleKind>;

    /// Reset the set of other guardians
    async fn reset_setup_codes(&self);

    /// Set local guardian parameters
    async fn set_local_parameters(
        &self,
        auth: ApiAuth,
        name: String,
        federation_name: Option<String>,
        disable_base_fees: Option<bool>,
        enabled_modules: Option<BTreeSet<ModuleKind>>,
        federation_size: Option<u32>,
    ) -> Result<String>;

    /// Add peer connection info
    async fn add_peer_setup_code(&self, info: String) -> Result<String>;

    /// Start the distributed key generation process
    async fn start_dkg(&self) -> Result<()>;

    /// Returns the expected federation size if any setup code (ours or a
    /// peer's) has set it
    async fn federation_size(&self) -> Option<u32>;

    /// Returns the federation name if set by any setup code
    async fn cfg_federation_name(&self) -> Option<String>;

    /// Returns whether base fees are disabled, if set by any setup code
    async fn cfg_base_fees_disabled(&self) -> Option<bool>;

    /// Returns the enabled modules, if set by any setup code
    async fn cfg_enabled_modules(&self) -> Option<BTreeSet<ModuleKind>>;

    /// Create a trait object
    fn into_dyn(self) -> DynSetupApi
    where
        Self: Sized + Send + Sync + 'static,
    {
        Arc::new(self)
    }
}
