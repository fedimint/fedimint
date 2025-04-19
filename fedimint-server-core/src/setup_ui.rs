use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use fedimint_core::module::ApiAuth;

pub type DynSetupApi = Arc<dyn ISetupApi + Send + Sync + 'static>;

/// Interface for the web UI to interact with the config generation process
#[async_trait]
pub trait ISetupApi {
    /// Get our connection info encoded as base32 string
    async fn setup_code(&self) -> Option<String>;

    /// Get the auth token for API calls
    async fn auth(&self) -> Option<ApiAuth>;

    /// Get list of names of connected peers
    async fn connected_peers(&self) -> Vec<String>;

    /// Reset the set of other guardians
    async fn reset_setup_codes(&self);

    /// Set initial setup parameters for guardian
    async fn init_setup(
        &self,
        auth: ApiAuth,
        name: String,
        federation_name: Option<String>,
    ) -> Result<String>;

    /// Add setup code from peer
    async fn add_setup_code(&self, info: String) -> Result<String>;

    /// Start the distributed key generation process
    async fn start_dkg(&self) -> Result<()>;

    /// Create a trait object
    fn into_dyn(self) -> DynSetupApi
    where
        Self: Sized + Send + Sync + 'static,
    {
        Arc::new(self)
    }
}
