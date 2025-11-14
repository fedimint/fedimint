use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use fedimint_api_client::api::{
    ConnectorRegistry, ConnectorRegistryBuilder, DynGatewayConnection, PeerError, PeerResult,
};
use fedimint_core::util::SafeUrl;
use fedimint_core::util::backoff_util::{FibonacciBackoff, custom_backoff};
use fedimint_logging::LOG_GATEWAY;
use iroh::NodeAddr;
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tokio::sync::OnceCell;
use tracing::trace;

use crate::iroh::GatewayIrohConnector;

/// Inner part of [`ConnectionState`] preserving state between attempts to
/// initialize [`ConnectionState::connection`]
#[derive(Debug)]
struct ConnectionStateInner {
    fresh: bool,
    backoff: FibonacciBackoff,
}

#[derive(Debug)]
struct ConnectionState {
    /// Connection we are trying to or already established
    connection: tokio::sync::OnceCell<DynGatewayConnection>,
    /// State that technically is protected every time by
    /// the serialization of `OnceCell::get_or_try_init`, but
    /// for Rust purposes needs to be locked.
    inner: std::sync::Mutex<ConnectionStateInner>,
}

impl ConnectionState {
    /// Create a new connection state for a first time connection
    fn new_initial() -> Self {
        Self {
            connection: OnceCell::new(),
            inner: std::sync::Mutex::new(ConnectionStateInner {
                fresh: true,
                backoff: custom_backoff(
                    // First time connections start quick
                    Duration::from_millis(5),
                    Duration::from_secs(30),
                    None,
                ),
            }),
        }
    }

    /// Create a new connection state for a connection that already failed, and
    /// is being reset
    fn new_reconnecting() -> Self {
        Self {
            connection: OnceCell::new(),
            inner: std::sync::Mutex::new(ConnectionStateInner {
                // set the attempts to 1, indicating that
                fresh: false,
                backoff: custom_backoff(
                    // Connections after a disconnect start with some minimum delay
                    Duration::from_millis(500),
                    Duration::from_secs(30),
                    None,
                ),
            }),
        }
    }

    /// Record the fact that an attempt to connect is being made, and return
    /// time the caller should wait.
    fn pre_reconnect_delay(&self) -> Duration {
        let mut backoff_locked = self.inner.lock().expect("Locking failed");
        let fresh = backoff_locked.fresh;

        backoff_locked.fresh = false;

        if fresh {
            Duration::default()
        } else {
            backoff_locked.backoff.next().expect("Keeps retrying")
        }
    }
}

#[derive(Clone, Debug)]
pub struct GatewayApi {
    connectors: ConnectorRegistry,
    password: Option<String>,

    /// Connection pool
    ///
    /// Every entry in this map will be created on demand and correspond to a
    /// single outgoing connection to a certain URL that is in the process
    /// of being established, or we already established.
    #[allow(clippy::type_complexity)]
    connections: Arc<tokio::sync::Mutex<HashMap<SafeUrl, Arc<ConnectionState>>>>,
}

impl GatewayApi {
    pub fn new(password: Option<String>, connectors: ConnectorRegistry) -> Self {
        Self {
            connectors,
            password,
            connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    async fn get_or_create_connection(
        &self,
        url: &SafeUrl,
    ) -> anyhow::Result<DynGatewayConnection> {
        let mut pool_locked = self.connections.lock().await;

        let pool_entry_arc = pool_locked
            .entry(url.to_owned())
                        .and_modify(|entry_arc| {
                // Check if existing connection is disconnected and reset the whole entry.
                //
                // This resets the state (like connectivity backoff), which is what we want.
                // Since the (`OnceCell`) was already initialized, it means connection was successfully
                // before, and disconnected afterwards.
                if let Some(existing_conn) = entry_arc.connection.get()
                    && !existing_conn.is_connected(){
                        trace!(target: LOG_GATEWAY, %url, "Existing connection is disconnected, removing from pool");
                        *entry_arc = Arc::new(ConnectionState::new_reconnecting());
                    }
            })
            .or_insert_with(|| Arc::new(ConnectionState::new_initial()))
            .clone();

        // Drop the pool lock so other connections can work in parallel
        drop(pool_locked);

        let conn = pool_entry_arc
            .connection
            // This serializes all the connection attempts. If one attempt to connect (including
            // waiting for the reconnect backoff) succeeds, all waiting ones will use it. If it
            // fails, any already pending/next will attempt it right afterwards.
            // Nit: if multiple calls are trying to connect to the same host that is offline, it
            // will take some of them multiples of maximum retry delay to actually return with
            // an error. This should be fine in practice and hard to avoid without a lot of
            // complexity.
            .get_or_try_init(|| async {
                let retry_delay = pool_entry_arc.pre_reconnect_delay();
                fedimint_core::runtime::sleep(retry_delay).await;

                let conn: DynGatewayConnection = self.connectors.connect_gateway(url).await?;

                Ok::<DynGatewayConnection, anyhow::Error>(conn)
            })
            .await?;

        trace!(target: LOG_GATEWAY, %url, "Using websocket connection");
        Ok(conn.clone())
    }

    async fn request<P: Serialize, T: DeserializeOwned>(
        &self,
        base_url: &SafeUrl,
        method: Method,
        route: &str,
        payload: Option<P>,
    ) -> PeerResult<T> {
        let conn = self
            .get_or_create_connection(base_url)
            .await
            .context("Failed to connect to gateway")
            .map_err(PeerError::Connection)?;
        let payload = payload.map(|p| serde_json::to_value(p).expect("Could not serialize"));
        let res = conn
            .request(self.password.clone(), method, route, payload)
            .await?;
        let response = serde_json::from_value::<T>(res).map_err(|e| {
            PeerError::InvalidResponse(anyhow::anyhow!("Received invalid response: {e}"))
        })?;
        Ok(response)
    }
}

pub struct GatewayRpcClient {
    base_url: SafeUrl,
    iroh_connector: Option<GatewayIrohConnector>,
    client: reqwest::Client,
    password: Option<String>,
}

impl GatewayRpcClient {
    pub async fn new(
        api: SafeUrl,
        password: Option<String>,
        iroh_dns: Option<SafeUrl>,
        connection_override: Option<SafeUrl>,
    ) -> anyhow::Result<Self> {
        let iroh_connector = if api.scheme() == "iroh" {
            let host = api.host_str().context("Url is missing host")?;
            let iroh_pk = iroh::PublicKey::from_str(host).context(format!(
                "Could not parse Iroh Public key: Invalid public key: {host}"
            ))?;
            let mut iroh_connector =
                GatewayIrohConnector::new(iroh_pk, password.clone(), iroh_dns).await?;

            if let Some(connection_override) = connection_override {
                let node_addr = NodeAddr {
                    node_id: iroh_pk,
                    relay_url: None,
                    direct_addresses: BTreeSet::from([SocketAddr::V4(SocketAddrV4::new(
                        connection_override
                            .host_str()
                            .ok_or(anyhow::anyhow!("No connection override host"))?
                            .parse::<Ipv4Addr>()?,
                        connection_override.port().ok_or(anyhow::anyhow!(
                            "No iroh port supplied for connection override"
                        ))?,
                    ))]),
                };

                iroh_connector = iroh_connector.with_connection_override(iroh_pk, node_addr);
            }
            Some(iroh_connector)
        } else {
            None
        };

        Ok(Self {
            base_url: api,
            iroh_connector,
            client: reqwest::Client::new(),
            password,
        })
    }

    async fn call<P: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        route: &str,
        payload: Option<P>,
    ) -> Result<T, GatewayRpcError> {
        if let Some(iroh_connector) = &self.iroh_connector {
            let payload = payload.map(|p| serde_json::to_value(p).expect("Could not serialize"));
            let response = iroh_connector
                .request(route, payload)
                .await
                .map_err(|e| GatewayRpcError::IrohError(e.to_string()))?;
            let status_code = StatusCode::from_u16(response.status)
                .map_err(|e| GatewayRpcError::IrohError(e.to_string()))?;
            match status_code {
                StatusCode::OK => {
                    let response = serde_json::from_value::<T>(response.body)
                        .map_err(|e| GatewayRpcError::IrohError(e.to_string()))?;
                    Ok(response)
                }
                status => Err(GatewayRpcError::BadStatus(status)),
            }
        } else {
            let url = self.base_url.join(route).expect("Invalid base url");
            let mut builder = self.client.request(method, url.clone().to_unsafe());
            if let Some(password) = self.password.clone() {
                builder = builder.bearer_auth(password);
            }
            if let Some(payload) = payload {
                builder = builder.json(&payload);
            }

            let response = builder
                .send()
                .await
                .map_err(|e| GatewayRpcError::RequestError(e.to_string()))?;

            match response.status() {
                StatusCode::OK => Ok(response
                    .json::<T>()
                    .await
                    .map_err(|e| GatewayRpcError::RequestError(e.to_string()))?),
                status => Err(GatewayRpcError::BadStatus(status)),
            }
        }
    }

    pub async fn call_get<T: DeserializeOwned>(&self, route: &str) -> Result<T, GatewayRpcError> {
        self.call(Method::GET, route, None::<()>).await
    }

    pub async fn call_post<P: Serialize, T: DeserializeOwned>(
        &self,
        route: &str,
        payload: P,
    ) -> Result<T, GatewayRpcError> {
        self.call(Method::POST, route, Some(payload)).await
    }
}

pub type GatewayRpcResult<T> = Result<T, GatewayRpcError>;

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum GatewayRpcError {
    #[error("Bad status returned {0}")]
    BadStatus(StatusCode),
    #[error("Error connecting to the gateway {0}")]
    RequestError(String),
    #[error("Iroh error: {0}")]
    IrohError(String),
}
