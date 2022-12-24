use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use fedimint_api::dyn_newtype_define;
use fedimint_server::modules::ln::route_hints::RouteHint;
use tonic::Streaming;

use crate::{
    gatewaylnrpc::{
        CompleteHtlcsRequest, CompleteHtlcsResponse, GetPubKeyResponse, PayInvoiceRequest,
        PayInvoiceResponse, SubscribeInterceptHtlcsRequest, SubscribeInterceptHtlcsResponse,
    },
    Result,
};

// TODO: Issue 1554: Define gatewaylnpc spec for getting route hints
pub struct GetRouteHintsResponse {
    pub route_hints: Vec<RouteHint>,
}

pub type HtlcStream = Streaming<SubscribeInterceptHtlcsResponse>;

#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    /// Get the public key of the lightning node
    async fn pubkey(&self) -> Result<GetPubKeyResponse>;

    /// Get route hints to the lightning node
    async fn route_hints(&self) -> Result<GetRouteHintsResponse>;

    /// Attempt to pay an invoice using the lightning node
    async fn pay(&self, invoice: PayInvoiceRequest) -> Result<PayInvoiceResponse>;

    /// Subscribe to intercept htlcs that belong to a specific mint identified by `short_channel_id`
    async fn subscribe_htlcs(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> Result<HtlcStream>;

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
