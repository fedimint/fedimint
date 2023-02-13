use std::{fmt::Debug, sync::Arc};

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_api::dyn_newtype_define;
use futures::stream::BoxStream;
use mint_client::modules::ln::route_hints::RouteHint;
use tonic::{
    transport::{Channel, Endpoint},
    Request,
};
use tracing::error;
use url::Url;

use crate::{
    gatewaylnrpc::{
        gateway_lightning_client::GatewayLightningClient, CompleteHtlcsRequest,
        CompleteHtlcsResponse, GetPubKeyRequest, GetPubKeyResponse, PayInvoiceRequest,
        PayInvoiceResponse, SubscribeInterceptHtlcsRequest, SubscribeInterceptHtlcsResponse,
    },
    LnGatewayError, Result,
};

// TODO: Issue 1554: Define gatewaylnpc spec for getting route hints
pub struct GetRouteHintsResponse {
    pub route_hints: Vec<RouteHint>,
}

pub type HtlcStream<'a> =
    BoxStream<'a, std::result::Result<SubscribeInterceptHtlcsResponse, tonic::Status>>;

#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    /// Get the public key of the lightning node
    async fn pubkey(&self) -> Result<GetPubKeyResponse>;

    /// Get route hints to the lightning node
    async fn route_hints(&self) -> Result<GetRouteHintsResponse>;

    /// Attempt to pay an invoice using the lightning node
    async fn pay(&self, invoice: PayInvoiceRequest) -> Result<PayInvoiceResponse>;

    /// Subscribe to intercept htlcs that belong to a specific mint identified by `short_channel_id`
    async fn subscribe_htlcs<'a>(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> Result<HtlcStream<'a>>;

    /// Request completion of an intercepted htlc after processing and determining an outcome
    async fn complete_htlc(&self, outcome: CompleteHtlcsRequest) -> Result<CompleteHtlcsResponse>;
}

dyn_newtype_define!(
    /// Arc reference to a gateway lightning rpc client
    #[derive(Clone)]
    pub DynLnRpcClient(Arc<ILnRpcClient>)
);

impl DynLnRpcClient {
    pub fn new(client: Arc<dyn ILnRpcClient + Send + Sync>) -> Self {
        DynLnRpcClient(client)
    }
}

/// An `ILnRpcClient` that wraps around `GatewayLightningClient` for convenience,
/// and makes real RPC requests over the wire to a remote lightning node.
/// The lightning node is exposed via a corresponding `GatewayLightningServer`.
#[derive(Debug)]
pub struct NetworkLnRpcClient {
    client: GatewayLightningClient<Channel>,
}

impl NetworkLnRpcClient {
    pub async fn new(url: Url) -> Result<Self> {
        let endpoint = Endpoint::from_shared(url.to_string()).map_err(|e| {
            error!("Failed to create lnrpc endpoint from url : {:?}", e);
            LnGatewayError::Other(anyhow!("Failed to create lnrpc endpoint from url"))
        })?;

        let client = GatewayLightningClient::connect(endpoint)
            .await
            .map_err(|e| {
                error!("Failed to connect to lnrpc server: {:?}", e);
                LnGatewayError::Other(anyhow!("Failed to connect to lnrpc server"))
            })?;

        Ok(Self { client })
    }
}

#[async_trait]
impl ILnRpcClient for NetworkLnRpcClient {
    async fn pubkey(&self) -> Result<GetPubKeyResponse> {
        let req = Request::new(GetPubKeyRequest {});

        let mut client = self.client.clone();
        let res = client.get_pub_key(req).await?;

        Ok(res.into_inner())
    }

    async fn route_hints(&self) -> Result<GetRouteHintsResponse> {
        unimplemented!()
    }

    async fn pay(&self, invoice: PayInvoiceRequest) -> Result<PayInvoiceResponse> {
        let req = Request::new(invoice);

        let mut client = self.client.clone();
        let res = client.pay_invoice(req).await?;

        Ok(res.into_inner())
    }

    async fn subscribe_htlcs<'a>(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> Result<HtlcStream<'a>> {
        let req = Request::new(subscription);

        let mut client = self.client.clone();
        let res = client.subscribe_intercept_htlcs(req).await?;

        Ok(Box::pin(res.into_inner()))
    }

    async fn complete_htlc(&self, outcome: CompleteHtlcsRequest) -> Result<CompleteHtlcsResponse> {
        let req = Request::new(outcome);

        let mut client = self.client.clone();
        let res = client.complete_htlc(req).await?;

        Ok(res.into_inner())
    }
}
