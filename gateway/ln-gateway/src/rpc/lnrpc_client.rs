use std::{fmt::Debug, sync::Arc};

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_api::dyn_newtype_define;
use futures::stream;
use tonic::{
    transport::{Channel, Endpoint},
    Request, Streaming,
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

/// Convenience wrapper around `GatewayLightningClient` protocol spec
/// This provides ease in constructing rpc requests
#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    /// Get the public key of the lightning node
    async fn get_pubkey(&self) -> Result<GetPubKeyResponse>;

    /// Attempt to pay an invoice using the lightning node
    async fn pay_invoice(
        &self,
        invoices: Vec<PayInvoiceRequest>,
    ) -> Result<Streaming<PayInvoiceResponse>>;

    /// Subscribe to intercept htlcs that belong to a specific mint identified by `short_channel_id`
    async fn subscribe_intercept_htlcs(
        &self,
        channel: SubscribeInterceptHtlcsRequest,
    ) -> Result<Streaming<SubscribeInterceptHtlcsResponse>>;

    async fn complete_htlcs(
        &self,
        outcomes: Vec<CompleteHtlcsRequest>,
    ) -> Result<Streaming<CompleteHtlcsResponse>>;
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
/// The lightnign node is exposed via a corresponding `GatewayLightningServer`.
#[derive(Debug)]
pub struct NetworkLnRpcClient {
    client: GatewayLightningClient<Channel>,
}

impl NetworkLnRpcClient {
    async fn new(url: Url) -> Result<Self> {
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
    async fn get_pubkey(&self) -> Result<GetPubKeyResponse> {
        let req = Request::new(GetPubKeyRequest {});

        let mut client = self.client.clone();
        let res = client.get_pub_key(req).await.map_err(|s| {
            error!("Failed to get pubkey: {:?}", s.message());
            LnGatewayError::LnrpcError(s)
        })?;

        Ok(res.into_inner())
    }

    async fn pay_invoice(
        &self,
        invoices: Vec<PayInvoiceRequest>,
    ) -> Result<Streaming<PayInvoiceResponse>> {
        let req = Request::new(stream::iter(invoices.into_iter()));

        let mut client = self.client.clone();
        let res = client.pay_invoice(req).await.map_err(|s| {
            error!("Failed to pay invoices: {:?}", s.message());
            LnGatewayError::LnrpcError(s)
        })?;

        Ok(res.into_inner())
    }

    async fn subscribe_intercept_htlcs(
        &self,
        channel: SubscribeInterceptHtlcsRequest,
    ) -> Result<Streaming<SubscribeInterceptHtlcsResponse>> {
        let req = Request::new(channel);

        let mut client = self.client.clone();
        let res = client.subscribe_intercept_htlcs(req).await.map_err(|s| {
            error!("Failed to subscribe intercept htlcs: {:?}", s.message());
            LnGatewayError::LnrpcError(s)
        })?;

        Ok(res.into_inner())
    }

    async fn complete_htlcs(
        &self,
        outcomes: Vec<CompleteHtlcsRequest>,
    ) -> Result<Streaming<CompleteHtlcsResponse>> {
        let req = Request::new(stream::iter(outcomes.into_iter()));

        let mut client = self.client.clone();
        let res = client.complete_htlcs(req).await.map_err(|s| {
            error!("Failed to complete processed htlcs: {:?}", s.message());
            LnGatewayError::LnrpcError(s)
        })?;

        Ok(res.into_inner())
    }
}

/// A generic factory trait for creating `DynLnRpcClient` instances.
#[async_trait]
pub trait ILnRpcClientFactory: Debug {
    async fn create(&self, url: Url) -> Result<DynLnRpcClient>;
}

dyn_newtype_define!(
    /// Arc reference to a gateway lightning rpc client factory
    #[derive(Clone)]
    pub DynLnRpcClientFactory(Arc<ILnRpcClientFactory>)
);

#[derive(Debug, Default)]
pub struct NetworkLnRpcClientFactory;

/// An `ILnRpcClientFactory` that creates `NetworkLnRpcClient` instances.
#[async_trait]
impl ILnRpcClientFactory for NetworkLnRpcClientFactory {
    async fn create(&self, url: Url) -> Result<DynLnRpcClient> {
        Ok(NetworkLnRpcClient::new(url).await?.into())
    }
}
