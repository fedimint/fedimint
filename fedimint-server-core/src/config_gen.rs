use async_trait::async_trait;
use anyhow::Result;
use fedimint_core::module::ApiAuth;

/// Interface for the web UI to interact with the config generation process
#[async_trait]
pub trait ConfigGenApiInterface: Send + Sync + 'static {
    /// Get our connection info encoded as base32 string
    async fn our_connection_info(&self) -> Option<String>;
    
    /// Get the auth token for API calls
    async fn auth(&self) -> Option<ApiAuth>;
    
    /// Get list of names of connected peers
    async fn connected_peers(&self) -> Vec<String>;
    
    /// Reset all connection info (remove all peers)
    async fn reset_connection_info(&self);
    
    /// Set local guardian parameters
    async fn set_local_parameters(
        &self,
        auth: ApiAuth,
        name: String,
        federation_name: Option<String>,
    ) -> Result<String>;
    
    /// Add peer connection info
    async fn add_peer_connection_info(&self, info: String) -> Result<String>;
    
    /// Start the distributed key generation process
    async fn start_dkg(&self) -> Result<()>;
} 