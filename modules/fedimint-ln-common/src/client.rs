use std::fmt::Debug;

use anyhow::Context;
use fedimint_connectors::error::ServerError;
use fedimint_connectors::{
    ConnectionPool, ConnectorRegistry, DynGatewayConnection, IGatewayConnection, ServerResult,
};
use fedimint_core::util::SafeUrl;
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Clone, Debug)]
pub struct GatewayApi {
    password: Option<String>,
    connection_pool: ConnectionPool<dyn IGatewayConnection>,
}

impl GatewayApi {
    pub fn new(password: Option<String>, connectors: ConnectorRegistry) -> Self {
        Self {
            password,
            connection_pool: ConnectionPool::new(connectors),
        }
    }

    async fn get_or_create_connection(&self, url: &SafeUrl) -> ServerResult<DynGatewayConnection> {
        self.connection_pool
            .get_or_create_connection(url, None, |url, _api_secret, connectors| async move {
                let conn = connectors
                    .connect_gateway(&url)
                    .await
                    .map_err(ServerError::Connection)?;
                Ok(conn)
            })
            .await
    }

    pub async fn request<P: Serialize, T: DeserializeOwned>(
        &self,
        base_url: &SafeUrl,
        method: Method,
        route: &str,
        payload: Option<P>,
    ) -> ServerResult<T> {
        let conn = self
            .get_or_create_connection(base_url)
            .await
            .context("Failed to connect to gateway")
            .map_err(ServerError::Connection)?;
        let payload = payload.map(|p| serde_json::to_value(p).expect("Could not serialize"));
        let res = conn
            .request(self.password.clone(), method, route, payload)
            .await?;
        let response = serde_json::from_value::<T>(res).map_err(|e| {
            ServerError::InvalidResponse(anyhow::anyhow!("Received invalid response: {e}"))
        })?;
        Ok(response)
    }
}
