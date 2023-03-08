use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use cln_rpc::model::{GetinfoRequest, GetinfoResponse};
use fedimint_core::dyn_newtype_define;
use futures::stream::BoxStream;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;
use tracing::error;
use url::Url;

use crate::gatewaylnrpc::gateway_lightning_client::GatewayLightningClient;
use crate::gatewaylnrpc::{
    CompleteHtlcsRequest, CompleteHtlcsResponse, EmptyRequest, GetRouteHintsResponse,
    PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
    SubscribeInterceptHtlcsResponse,
};
use crate::{GatewayError, Result};

pub type HtlcStream<'a> =
    BoxStream<'a, std::result::Result<SubscribeInterceptHtlcsResponse, tonic::Status>>;

#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    /// Get the public key of the lightning node
    /// TODO: rename to `node_pubkey`
    async fn pubkey(&self) -> anyhow::Result<secp256k1::PublicKey>;

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

/// An `ILnRpcClient` that wraps around `GatewayLightningClient` for
/// convenience, and makes real RPC requests over the wire to a remote lightning
/// node. The lightning node is exposed via a corresponding
/// `GatewayLightningServer`.
#[derive(Debug)]
pub struct NetworkLnRpcClient {
    client: GatewayLightningClient<Channel>,
    cln_rpc_socket: PathBuf,
}

impl NetworkLnRpcClient {
    pub async fn new(url: Url, cln_rpc_socket: PathBuf) -> Result<Self> {
        let endpoint = Endpoint::from_shared(url.to_string()).map_err(|e| {
            error!("Failed to create lnrpc endpoint from url : {:?}", e);
            GatewayError::Other(anyhow!("Failed to create lnrpc endpoint from url"))
        })?;

        let client = GatewayLightningClient::connect(endpoint)
            .await
            .map_err(|e| {
                error!("Failed to connect to lnrpc server: {:?}", e);
                GatewayError::Other(anyhow!("Failed to connect to lnrpc server"))
            })?;

        Ok(Self {
            client,
            cln_rpc_socket,
        })
    }

    async fn cln_client(&self) -> anyhow::Result<cln_rpc::ClnRpc> {
        cln_rpc::ClnRpc::new(&self.cln_rpc_socket).await
    }
}

#[async_trait]
impl ILnRpcClient for NetworkLnRpcClient {
    async fn pubkey(&self) -> anyhow::Result<secp256k1::PublicKey> {
        self.cln_client()
            .await?
            .call(cln_rpc::Request::Getinfo(GetinfoRequest {}))
            .await
            .map(|response| match response {
                cln_rpc::Response::Getinfo(GetinfoResponse { id, .. }) => Ok(id),
                _ => bail!("Wrong response from CLN"),
            })?
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse> {
        let req = Request::new(EmptyRequest {});

        let mut client = self.client.clone();
        let res = client.get_route_hints(req).await?;

        Ok(res.into_inner())
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
