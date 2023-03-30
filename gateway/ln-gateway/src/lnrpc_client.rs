use std::fmt::Debug;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::task::sleep;
use futures::stream::BoxStream;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;
use tracing::error;
use url::Url;

use crate::gatewaylnrpc::gateway_lightning_client::GatewayLightningClient;
use crate::gatewaylnrpc::{
    CompleteHtlcsRequest, CompleteHtlcsResponse, EmptyRequest, GetNodeInfoResponse,
    GetRouteHintsResponse, PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
    SubscribeInterceptHtlcsResponse,
};
use crate::{GatewayError, Result};

pub type HtlcStream<'a> =
    BoxStream<'a, std::result::Result<SubscribeInterceptHtlcsResponse, tonic::Status>>;

#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    /// Get the public key and alias of the lightning node
    async fn info(&self) -> Result<GetNodeInfoResponse>;

    /// Get route hints to the lightning node
    async fn routehints(&self) -> Result<GetRouteHintsResponse>;

    /// Attempt to pay an invoice using the lightning node
    async fn pay(&self, invoice: PayInvoiceRequest) -> Result<PayInvoiceResponse>;

    /// Subscribe to intercept htlcs that belong to a specific mint identified
    /// by `short_channel_id`
    async fn subscribe_htlcs<'a>(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> Result<HtlcStream<'a>>;

    /// Request completion of an intercepted htlc after processing and
    /// determining an outcome
    async fn complete_htlc(&self, outcome: CompleteHtlcsRequest) -> Result<CompleteHtlcsResponse>;

    /// Create a connection to the lightning node
    async fn connect(&mut self) -> Result<()>;

    // Disconnect the current connection to the lightning node
    async fn disconnect(&mut self) -> Result<()>;
}

/// An `ILnRpcClient` that wraps around `GatewayLightningClient` for
/// convenience, and makes real RPC requests over the wire to a remote lightning
/// node. The lightning node is exposed via a corresponding
/// `GatewayLightningServer`.
#[derive(Debug)]
pub struct NetworkLnRpcClient {
    client: Option<GatewayLightningClient<Channel>>,
    endpoint: Endpoint,
}

impl NetworkLnRpcClient {
    pub async fn new(url: Url) -> Result<Self> {
        let endpoint = Endpoint::from_shared(url.to_string()).map_err(|e| {
            error!("Failed to create lnrpc endpoint from url : {:?}", e);
            GatewayError::Other(anyhow!("Failed to create lnrpc endpoint from url"))
        })?;

        let mut gw_rpc = NetworkLnRpcClient {
            client: None,
            endpoint,
        };
        gw_rpc.connect().await?;
        Ok(gw_rpc)
    }
}

#[async_trait]
impl ILnRpcClient for NetworkLnRpcClient {
    async fn info(&self) -> Result<GetNodeInfoResponse> {
        if let Some(mut client) = self.client.clone() {
            let req = Request::new(EmptyRequest {});
            let res = client.get_node_info(req).await?;

            return Ok(res.into_inner());
        }

        Err(GatewayError::other(
            "Error: not connected to CLN extension".to_string(),
        ))
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse> {
        if let Some(mut client) = self.client.clone() {
            let req = Request::new(EmptyRequest {});
            let res = client.get_route_hints(req).await?;

            return Ok(res.into_inner());
        }

        Err(GatewayError::other(
            "Error: not connected to CLN extension".to_string(),
        ))
    }

    async fn pay(&self, invoice: PayInvoiceRequest) -> Result<PayInvoiceResponse> {
        if let Some(mut client) = self.client.clone() {
            let req = Request::new(invoice);
            let res = client.pay_invoice(req).await?;

            return Ok(res.into_inner());
        }

        Err(GatewayError::other(
            "Error: not connected to CLN extension".to_string(),
        ))
    }

    async fn subscribe_htlcs<'a>(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> Result<HtlcStream<'a>> {
        if let Some(mut client) = self.client.clone() {
            let req = Request::new(subscription);
            let res = client.subscribe_intercept_htlcs(req).await?;

            return Ok(Box::pin(res.into_inner()));
        }

        Err(GatewayError::other(
            "Error: not connected to CLN extension".to_string(),
        ))
    }

    async fn complete_htlc(&self, outcome: CompleteHtlcsRequest) -> Result<CompleteHtlcsResponse> {
        if let Some(mut client) = self.client.clone() {
            let req = Request::new(outcome);
            let res = client.complete_htlc(req).await?;

            return Ok(res.into_inner());
        }

        Err(GatewayError::other(
            "Error: not connected to CLN extension".to_string(),
        ))
    }

    async fn connect(&mut self) -> Result<()> {
        let client = loop {
            match GatewayLightningClient::connect(self.endpoint.clone()).await {
                Ok(client) => break client,
                Err(_) => {
                    tracing::warn!("Couldn't connect to CLN extension, retrying in 5 seconds...");
                    sleep(Duration::from_secs(5)).await;
                }
            }
        };

        self.client = Some(client);
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        tracing::warn!("Disconnected from CLN extension");
        self.client = None;
        Ok(())
    }
}
