use std::net::SocketAddr;

use mint_client::FederationId;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GatewayConfig {
    /// API webserver bind address
    pub bind_address: SocketAddr,
    /// URL under which the API will be reachable
    pub announce_address: Url,
    /// webserver authentication password
    pub password: String,
    // FIXME: Issue 664: We should avoid having a special reference to a federation
    // all requests, including `ReceivePaymentPayload`, should contain the federation id
    pub default_federation: FederationId,
}
