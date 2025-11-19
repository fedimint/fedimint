use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::Context;
use fedimint_api_client::api::{
    ConnectionState, ConnectionType, ConnectorRegistry, DynGatewayConnection, PeerError, PeerResult,
};
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_GATEWAY;
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::trace;

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

                Ok::<ConnectionType, anyhow::Error>(ConnectionType::Gateway(conn))
            })
            .await?;

        trace!(target: LOG_GATEWAY, %url, "Using websocket connection");
        Ok(conn.as_gateway().expect("Should be a gateway").clone())
    }

    pub async fn request<P: Serialize, T: DeserializeOwned>(
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
