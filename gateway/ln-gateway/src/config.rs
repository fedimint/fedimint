use mint_client::FederationId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub password: String,
    // FIXME: Issue 664: We should avoid having a special reference to a federation
    // all requests, including `ReceivePaymentPayload`, should contain the federation id
    pub default_federation: FederationId,
}
