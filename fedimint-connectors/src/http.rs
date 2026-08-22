use std::sync::Arc;

use anyhow::anyhow;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send};
use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::error::{GatewayStatusCode, ServerError};
use crate::{
    Connectivity, DynGatewayConnection, DynGuaridianConnection, IConnection, IGatewayConnection,
    ServerResult,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct HttpConnector {
    client: Arc<reqwest::Client>,
}

#[async_trait::async_trait]
impl crate::Connector for HttpConnector {
    async fn connect_guardian(
        &self,
        _url: &SafeUrl,
        _api_secret: Option<&str>,
    ) -> ServerResult<DynGuaridianConnection> {
        Err(ServerError::InternalClientError(anyhow!(
            "Unsupported transport mechanism"
        )))
    }

    async fn connect_gateway(&self, url: &SafeUrl) -> anyhow::Result<DynGatewayConnection> {
        let http_connection = HttpConnection {
            client: self.client.clone(),
            base_url: url.clone(),
        };

        Ok(IGatewayConnection::into_dyn(http_connection))
    }

    fn connectivity(&self, _url: &SafeUrl) -> Connectivity {
        Connectivity::Direct
    }
}

#[derive(Debug)]
pub(crate) struct HttpConnection {
    client: Arc<reqwest::Client>,
    base_url: SafeUrl,
}

#[apply(async_trait_maybe_send!)]
impl IConnection for HttpConnection {
    async fn await_disconnection(&self) {
        // `HttpConnection` is a stateless wrapper over a pooled `reqwest::Client`;
        // it never actually disconnects. Returning immediately would make the
        // `ConnectionPool` treat every request as a reconnection and impose its
        // reconnect backoff (a 500ms floor) before each one, so we pend forever.
        std::future::pending().await
    }

    fn is_connected(&self) -> bool {
        // `reqwest::Client` handles TCP/TLS connection pooling internally, so this
        // wrapper is always "connected" and safe to cache. Reporting `false` here
        // forced the `ConnectionPool` to reset the entry to a reconnecting state on
        // every request, penalizing each one with a 500ms reconnect-backoff sleep
        // even though the underlying connection was reused the whole time.
        true
    }
}

#[apply(async_trait_maybe_send!)]
impl IGatewayConnection for HttpConnection {
    async fn request(
        &self,
        password: Option<String>,
        method: Method,
        route: &str,
        payload: Option<Value>,
    ) -> ServerResult<Value> {
        let url = self.base_url.join(route).expect("Invalid base url");
        let mut builder = self.client.request(method, url.clone().to_unsafe());
        if let Some(password) = password.clone() {
            builder = builder.bearer_auth(password);
        }
        if let Some(payload) = payload {
            builder = builder.json(&payload);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| ServerError::Transport(e.into()))?;

        match response.status() {
            StatusCode::OK => Ok(response
                .json::<Value>()
                .await
                .map_err(|e| ServerError::InvalidResponse(e.into()))?),
            status => Err(ServerError::GatewayStatus {
                status: GatewayStatusCode::from_http(status),
            }),
        }
    }
}

#[cfg(test)]
mod tests;
