use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use cln_rpc::{model, ClnRpc, Request, Response};
use fedimint_core::dyn_newtype_define;
use fedimint_ln_common::route_hints::{RouteHint, RouteHintHop};
use futures::stream::BoxStream;
use tonic::transport::{Channel, Endpoint};
use tonic::Request as TonicRequest;
use tracing::{debug, error, trace, warn};
use url::Url;

use crate::cln::scid_to_u64;
use crate::gatewaylnrpc::gateway_lightning_client::GatewayLightningClient;
use crate::gatewaylnrpc::{
    CompleteHtlcsRequest, CompleteHtlcsResponse, PayInvoiceRequest, PayInvoiceResponse,
    SubscribeInterceptHtlcsRequest, SubscribeInterceptHtlcsResponse,
};
use crate::{GatewayError, Result};

pub type HtlcStream<'a> =
    BoxStream<'a, std::result::Result<SubscribeInterceptHtlcsResponse, tonic::Status>>;

#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    /// Get the public key of the lightning node
    async fn node_pubkey(&self) -> anyhow::Result<secp256k1::PublicKey>;

    /// Get route hints to the lightning node
    async fn route_hints(&self) -> anyhow::Result<Vec<RouteHint>>;

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

    async fn cln_client(&self) -> anyhow::Result<ClnRpc> {
        ClnRpc::new(&self.cln_rpc_socket).await
    }
}

#[async_trait]
impl ILnRpcClient for NetworkLnRpcClient {
    async fn node_pubkey(&self) -> anyhow::Result<secp256k1::PublicKey> {
        self.cln_client()
            .await?
            .call(Request::Getinfo(model::GetinfoRequest {}))
            .await
            .map(|response| match response {
                Response::Getinfo(model::GetinfoResponse { id, .. }) => Ok(id),
                _ => bail!("Wrong response from CLN"),
            })?
    }

    async fn route_hints(&self) -> anyhow::Result<Vec<RouteHint>> {
        let our_pub_key = self
            .node_pubkey()
            .await
            .map_err(|err| anyhow!("Lightning error: {:?}", err))?;

        let peers_response = self
            .cln_client()
            .await?
            .call(Request::ListPeers(model::ListpeersRequest {
                id: None,
                level: None,
            }))
            .await?;
        let peers = match peers_response {
            Response::ListPeers(peers) => peers.peers,
            _ => {
                panic!("Unexpected response")
            }
        };

        let active_peer_channels = peers
            .into_iter()
            .flat_map(|peer| peer.channels.into_iter().map(move |chan| (peer.id, chan)))
            .filter_map(|(peer_id, chan)| {
                // TODO: upstream eq derive
                if !matches!(
                    chan.state,
                    model::ListpeersPeersChannelsState::CHANNELD_NORMAL
                ) {
                    return None;
                }

                let Some(scid) = chan.short_channel_id else {
                    warn!("Encountered channel without short channel id");
                    return None;
                };

                Some((peer_id, scid))
            })
            .collect::<Vec<_>>();

        debug!(
            "Found {} active channels to use as route hints",
            active_peer_channels.len()
        );

        let mut route_hints = vec![];
        for (peer_id, scid) in active_peer_channels {
            let channels_response = self
                .cln_client()
                .await?
                .call(Request::ListChannels(model::ListchannelsRequest {
                    short_channel_id: Some(scid),
                    source: None,
                    destination: None,
                }))
                .await
                .map_err(|err| anyhow!("Lightning error: {:?}", err))?;
            let channel = match channels_response {
                Response::ListChannels(channels) => {
                    let Some(channel) = channels.channels.into_iter().find(|chan| chan.destination == our_pub_key) else {
                        warn!("Channel {:?} not found in graph", scid);
                        continue;
                    };
                    channel
                }
                _ => panic!("Unexpected response"),
            };

            let route_hint_hop = RouteHintHop {
                src_node_id: peer_id,
                short_channel_id: scid_to_u64(scid),
                base_msat: channel.base_fee_millisatoshi,
                proportional_millionths: channel.fee_per_millionth,
                cltv_expiry_delta: channel
                    .delay
                    .try_into()
                    .expect("CLN returned too big cltv expiry delta"),
                htlc_minimum_msat: Some(channel.htlc_minimum_msat.msat()),
                htlc_maximum_msat: channel.htlc_maximum_msat.map(|amt| amt.msat()),
            };

            trace!("Constructed route hint {:?}", route_hint_hop);
            route_hints.push(RouteHint(vec![route_hint_hop]))
        }

        Ok(route_hints)
    }

    async fn pay(&self, invoice: PayInvoiceRequest) -> Result<PayInvoiceResponse> {
        let req = TonicRequest::new(invoice);

        let mut client = self.client.clone();
        let res = client.pay_invoice(req).await?;

        Ok(res.into_inner())
    }

    async fn subscribe_htlcs<'a>(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> Result<HtlcStream<'a>> {
        let req = TonicRequest::new(subscription);

        let mut client = self.client.clone();
        let res = client.subscribe_intercept_htlcs(req).await?;

        Ok(Box::pin(res.into_inner()))
    }

    async fn complete_htlc(&self, outcome: CompleteHtlcsRequest) -> Result<CompleteHtlcsResponse> {
        let req = TonicRequest::new(outcome);

        let mut client = self.client.clone();
        let res = client.complete_htlc(req).await?;

        Ok(res.into_inner())
    }
}
