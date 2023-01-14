use std::{fmt::Debug, net::SocketAddr, sync::Arc};

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_api::dyn_newtype_define;
use tonic::{transport::Channel, Streaming};
use tracing::error;

use crate::{
    gatewaylnrpc::{
        gateway_lightning_client::GatewayLightningClient, CompleteHtlcsRequest,
        CompleteHtlcsResponse, GetPubKeyResponse, PayInvoiceRequest, PayInvoiceResponse,
        SubscribeInterceptHtlcsResponse,
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
        short_channel_id: u64,
    ) -> Result<Streaming<SubscribeInterceptHtlcsResponse>>;

    async fn complete_htlcs(
        &self,
        requests: Vec<CompleteHtlcsRequest>,
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
    async fn new(address: SocketAddr) -> Result<Self> {
        // TODO: Use secure connections to `GatewayLightningServer`
        let url = format!("http://{}", address);

        let client = GatewayLightningClient::connect(url).await.map_err(|e| {
            error!("Failed to connect to lnrpc server: {:?}", e);
            LnGatewayError::Other(anyhow!("Failed to connect to lnrpc server"))
        })?;

        Ok(Self { client })
    }
}

#[async_trait]
impl ILnRpcClient for NetworkLnRpcClient {
    async fn get_pubkey(&self) -> Result<GetPubKeyResponse> {
        unimplemented!()
    }

    async fn pay_invoice(
        &self,
        _invoices: Vec<PayInvoiceRequest>,
    ) -> Result<Streaming<PayInvoiceResponse>> {
        unimplemented!()
    }

    async fn subscribe_intercept_htlcs(
        &self,
        _short_channel_id: u64,
    ) -> Result<Streaming<SubscribeInterceptHtlcsResponse>> {
        unimplemented!()
    }

    async fn complete_htlcs(
        &self,
        _requests: Vec<CompleteHtlcsRequest>,
    ) -> Result<Streaming<CompleteHtlcsResponse>> {
        unimplemented!()
    }
}
