use std::sync::Arc;

use fedimint_api::{db::Database, dyn_newtype_define};
use mint_client::{Client, FederationId, GatewayClientConfig};

use crate::Result;

/// Trait for gateway federation client builders
pub trait IGatewayClientBuilder {
    /// Build a new gateway federation client
    fn build(&self, config: GatewayClientConfig) -> Result<Client<GatewayClientConfig>>;

    /// Create a new database for the gateway federation client
    fn create_database(&self, federation_id: FederationId) -> Result<Database>;

    /// Save and persist the configuration of the gateway federation client
    fn save_config(&self, config: GatewayClientConfig) -> Result<()>;
}

dyn_newtype_define! {
  /// Arc reference to a Gateway federation client builder
  #[derive(Clone)]
  pub GatewayClientBuilder(Arc<IGatewayClientBuilder>)
}
