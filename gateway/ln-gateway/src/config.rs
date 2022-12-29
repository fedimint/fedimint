use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GatewayConfig {
    /// Webserver bind address
    pub api_bind_address: SocketAddr,
    /// Webserver authentication password
    pub webserver_password: String,
    /// URL under which the Gateway API will be reachable
    pub api_announce_address: Url,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LndRpcConfig {
    /// Lightning RPC server bind address
    pub lnrpc_bind_address: SocketAddr,
    // LND node host
    pub node_host: String,
    // LND node port
    pub node_port: u32,
    // LND node tls certificate path
    pub tls_cert_path: String,
    // LND node macaroon path. Usually path to admin.macaroon
    pub macaroon_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClnRpcConfig {
    /// Lightning RPC server bind address
    pub lnrpc_bind_address: SocketAddr,
}
