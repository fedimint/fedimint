use std::net::SocketAddr;

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
}
