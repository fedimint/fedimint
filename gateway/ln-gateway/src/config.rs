use std::net::SocketAddr;

use mint_client::FederationId;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GatewayConfig {
    /* lightning configs */
    /// Lightning RPC bind address
    pub lnrpc_bind_address: SocketAddr,
    /// RPC connection config when using LND nodes
    pub lnd_rpc_connect: Option<LndRpcConfig>,

    /* webserver configs */
    /// Webserver bind address
    pub webserver_bind_address: SocketAddr,
    /// Webserver authentication password
    pub webserver_password: String,
    /// URL under which the Gateway API will be reachable
    pub api_announce_address: Url,

    // FIXME: Issue 664: We should avoid having a special reference to a federation
    // all requests, including `ReceivePaymentPayload`, should contain the federation id
    pub default_federation: FederationId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LndRpcConfig {
    // LND node host
    pub node_host: String,
    // LND node port
    pub node_port: u32,
    // LND node tls certificate path
    pub tls_cert_path: String,
    // LND node macaroon path. Usually path to admin.macaroon
    pub macaroon_path: String,
}
