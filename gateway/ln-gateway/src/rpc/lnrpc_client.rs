use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use fedimint_api::dyn_newtype_define;
use tonic::Streaming;

use crate::{
    gatewaylnrpc::{
        CompleteHtlcsRequest, CompleteHtlcsResponse, GetPubKeyResponse, PayInvoiceRequest,
        PayInvoiceResponse, SubscribeInterceptHtlcsResponse,
    },
    Result,
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
