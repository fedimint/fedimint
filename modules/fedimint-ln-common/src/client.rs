use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;

use anyhow::Context;
use fedimint_core::util::SafeUrl;
use iroh::NodeAddr;
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::iroh::GatewayIrohConnector;

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
        let iroh_connector = if api.is_iroh() {
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
                builder = builder
                    .json(&payload)
                    .header(reqwest::header::CONTENT_TYPE, "application/json");
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
