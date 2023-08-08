use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::{sleep, TaskGroup};
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;
use tracing::info;
use url::Url;

use crate::gatewaylnrpc::gateway_lightning_client::GatewayLightningClient;
use crate::gatewaylnrpc::{
    EmptyRequest, EmptyResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcRequest,
    InterceptHtlcResponse, PayInvoiceRequest, PayInvoiceResponse,
};
pub type RouteHtlcStream<'a> =
    BoxStream<'a, std::result::Result<InterceptHtlcRequest, tonic::Status>>;

pub const MAX_LIGHTNING_RETRIES: u32 = 10;

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum LightningRpcError {
    #[error("Failed to connect to Lightning node")]
    FailedToConnect,
    #[error("Failed to retrieve node info: {failure_reason}")]
    FailedToGetNodeInfo { failure_reason: String },
    #[error("Failed to retrieve route hints: {failure_reason}")]
    FailedToGetRouteHints { failure_reason: String },
    #[error("Payment failed: {failure_reason}")]
    FailedPayment { failure_reason: String },
    #[error("Failed to route HTLCs: {failure_reason}")]
    FailedToRouteHtlcs { failure_reason: String },
    #[error("Failed to complete HTLC: {failure_reason}")]
    FailedToCompleteHtlc { failure_reason: String },
    #[error("Failed to open channel: {failure_reason}")]
    FailedToOpenChannel { failure_reason: String },
    #[error("Failed to get Invoice: {failure_reason}")]
    FailedToGetInvoice { failure_reason: String },
}

#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    /// Get the public key and alias of the lightning node
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError>;

    /// Get route hints to the lightning node
    async fn routehints(&self) -> Result<GetRouteHintsResponse, LightningRpcError>;

    /// Attempt to pay an invoice using the lightning node
    async fn pay(
        &self,
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError>;

    // Consumes the current lightning client because `route_htlcs` should only be
    // called once per client. A stream of intercepted HTLCs and a `Arc<dyn
    // ILnRpcClient> are returned to the caller. The caller can use this new
    // client to interact with the lightning node, but since it is an `Arc` is
    // cannot call `route_htlcs` again.
    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError>;

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError>;
}

/// An `ILnRpcClient` that wraps around `GatewayLightningClient` for
/// convenience, and makes real RPC requests over the wire to a remote lightning
/// node. The lightning node is exposed via a corresponding
/// `GatewayLightningServer`.
#[derive(Debug)]
pub struct NetworkLnRpcClient {
    connection_url: Url,
}

impl NetworkLnRpcClient {
    pub async fn new(url: Url) -> Self {
        info!(
            "Gateway configured to connect to remote LnRpcClient at \n cln extension address: {} ",
            url.to_string()
        );
        NetworkLnRpcClient {
            connection_url: url,
        }
    }

    async fn connect(
        connection_url: Url,
    ) -> Result<GatewayLightningClient<Channel>, LightningRpcError> {
        let mut retries = 0;
        let client = loop {
            if retries >= MAX_LIGHTNING_RETRIES {
                return Err(LightningRpcError::FailedToConnect);
            }

            retries += 1;

            if let Ok(endpoint) = Endpoint::from_shared(connection_url.to_string()) {
                if let Ok(client) = GatewayLightningClient::connect(endpoint.clone()).await {
                    break client;
                }
            }

            tracing::debug!("Couldn't connect to CLN extension, retrying in 1 second...");
            sleep(Duration::from_secs(1)).await;
        };

        Ok(client)
    }
}

#[async_trait]
impl ILnRpcClient for NetworkLnRpcClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let req = Request::new(EmptyRequest {});
        let mut client = Self::connect(self.connection_url.clone()).await?;
        let res = client.get_node_info(req).await.map_err(|status| {
            LightningRpcError::FailedToGetNodeInfo {
                failure_reason: status.message().to_string(),
            }
        })?;
        Ok(res.into_inner())
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse, LightningRpcError> {
        let req = Request::new(EmptyRequest {});
        let mut client = Self::connect(self.connection_url.clone()).await?;
        let res = client.get_route_hints(req).await.map_err(|status| {
            LightningRpcError::FailedToGetRouteHints {
                failure_reason: status.message().to_string(),
            }
        })?;
        Ok(res.into_inner())
    }

    async fn pay(
        &self,
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let req = Request::new(invoice);
        let mut client = Self::connect(self.connection_url.clone()).await?;
        let res =
            client
                .pay_invoice(req)
                .await
                .map_err(|status| LightningRpcError::FailedPayment {
                    failure_reason: status.message().to_string(),
                })?;
        Ok(res.into_inner())
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        _task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        let mut client = Self::connect(self.connection_url.clone()).await?;
        let res = client
            .route_htlcs(EmptyRequest {})
            .await
            .map_err(|status| LightningRpcError::FailedToRouteHtlcs {
                failure_reason: status.message().to_string(),
            })?;
        Ok((
            Box::pin(res.into_inner()),
            Arc::new(Self::new(self.connection_url.clone()).await),
        ))
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        let mut client = Self::connect(self.connection_url.clone()).await?;
        let res = client.complete_htlc(htlc).await.map_err(|status| {
            LightningRpcError::FailedToCompleteHtlc {
                failure_reason: status.message().to_string(),
            }
        })?;
        Ok(res.into_inner())
    }
}
