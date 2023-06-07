use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::task::{sleep, TaskGroup};
use secp256k1::PublicKey;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tonic_lnd::lnrpc::failure::FailureCode;
use tonic_lnd::lnrpc::{ChanInfoRequest, GetInfoRequest, ListChannelsRequest, SendRequest};
use tonic_lnd::routerrpc::{CircuitKey, ForwardHtlcInterceptResponse, ResolveHoldForwardAction};
use tonic_lnd::{connect, LndClient};
use tracing::{error, info, trace};

use crate::gatewaylnrpc::get_route_hints_response::{RouteHint, RouteHintHop};
use crate::gatewaylnrpc::intercept_htlc_response::{Action, Cancel, Forward, Settle};
use crate::gatewaylnrpc::{
    GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcRequest, InterceptHtlcResponse,
    PayInvoiceRequest, PayInvoiceResponse,
};
use crate::lnrpc_client::{ILnRpcClient, RouteHtlcStream};
use crate::GatewayError;

type HtlcSubscriptionSender = mpsc::Sender<Result<InterceptHtlcRequest, Status>>;

pub struct GatewayLndClient {
    /// LND client
    client: LndClient,
}

impl GatewayLndClient {
    pub async fn new(address: String, tls_cert: String, macaroon: String) -> crate::Result<Self> {
        let client = Self::connect(address, tls_cert, macaroon).await?;

        let gw_rpc = GatewayLndClient { client };

        Ok(gw_rpc)
    }

    async fn connect(
        address: String,
        tls_cert: String,
        macaroon: String,
    ) -> crate::Result<LndClient> {
        let client = loop {
            match connect(address.clone(), tls_cert.clone(), macaroon.clone()).await {
                Ok(client) => break client,
                Err(_) => {
                    tracing::warn!("Couldn't connect to LND, retrying in 5 seconds...");
                    sleep(Duration::from_secs(5)).await;
                }
            }
        };

        Ok(client)
    }

    async fn spawn_interceptor(
        &self,
        task_group: &mut TaskGroup,
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
        lnd_rx: mpsc::Receiver<ForwardHtlcInterceptResponse>,
        actor_sender: HtlcSubscriptionSender,
    ) {
        let mut client = self.client.clone();
        task_group
            .spawn("LND HTLC Subscription", move |_handle| async move {
                let mut htlc_stream = match client
                    .router()
                    .htlc_interceptor(ReceiverStream::new(lnd_rx))
                    .await
                    .map_err(|e| {
                        error!("Failed to connect to lnrpc server: {:?}", e);
                        GatewayError::Other(anyhow!("Failed to subscribe to LND htlc stream"))
                    }) {
                    Ok(stream) => stream.into_inner(),
                    Err(e) => {
                        error!("Failed to establish htlc stream: {:?}", e);
                        return;
                    }
                };

                while let Some(htlc) = match htlc_stream.message().await {
                    Ok(htlc) => htlc,
                    Err(e) => {
                        error!("Error received over HTLC subscription: {:?}", e);
                        None
                    }
                } {
                    trace!("handling htlc {:?}", htlc);

                    if htlc.incoming_circuit_key.is_none() {
                        error!("Cannot route htlc with None incoming_circuit_key");
                        continue;
                    }

                    let incoming_circuit_key = htlc.incoming_circuit_key.unwrap();

                    // Forward all HTLCs to gatewayd, gatewayd will filter them based on scid
                    let intercept = InterceptHtlcRequest {
                        payment_hash: htlc.payment_hash,
                        incoming_amount_msat: htlc.incoming_amount_msat,
                        outgoing_amount_msat: htlc.outgoing_amount_msat,
                        incoming_expiry: htlc.incoming_expiry,
                        short_channel_id: htlc.outgoing_requested_chan_id,
                        incoming_chan_id: incoming_circuit_key.chan_id,
                        htlc_id: incoming_circuit_key.htlc_id,
                    };

                    match actor_sender.send(Ok(intercept)).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("Failed to send HTLC to gatewayd for processing: {:?}", e);
                            let _ = Self::cancel_htlc(incoming_circuit_key, lnd_sender.clone())
                                .await
                                .map_err(|e| {
                                    error!("Failed to cancel HTLC: {:?}", e);
                                });
                        }
                    }
                }
            })
            .await;
    }

    async fn forward_htlc(
        incoming_circuit_key: CircuitKey,
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
    ) -> crate::Result<()> {
        let response = ForwardHtlcInterceptResponse {
            incoming_circuit_key: Some(incoming_circuit_key),
            action: ResolveHoldForwardAction::Resume.into(),
            preimage: vec![],
            failure_message: vec![],
            failure_code: FailureCode::TemporaryChannelFailure.into(),
        };
        Self::send_lnd_response(lnd_sender, response).await
    }

    async fn settle_htlc(
        key: CircuitKey,
        preimage: Vec<u8>,
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
    ) -> crate::Result<()> {
        let response = ForwardHtlcInterceptResponse {
            incoming_circuit_key: Some(key),
            action: ResolveHoldForwardAction::Settle.into(),
            preimage,
            failure_message: vec![],
            failure_code: FailureCode::TemporaryChannelFailure.into(),
        };
        Self::send_lnd_response(lnd_sender, response).await
    }

    async fn cancel_htlc(
        key: CircuitKey,
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
    ) -> crate::Result<()> {
        // TODO: Specify a failure code and message
        let response = ForwardHtlcInterceptResponse {
            incoming_circuit_key: Some(key),
            action: ResolveHoldForwardAction::Fail.into(),
            preimage: vec![],
            failure_message: vec![],
            failure_code: FailureCode::TemporaryChannelFailure.into(),
        };
        Self::send_lnd_response(lnd_sender, response).await
    }

    async fn send_lnd_response(
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
        response: ForwardHtlcInterceptResponse,
    ) -> crate::Result<()> {
        // TODO: Consider retrying this if the send fails
        lnd_sender.send(response).await.map_err(|_| {
            GatewayError::Other(anyhow::anyhow!(
                "Failed to send ForwardHtlcInterceptResponse to LND"
            ))
        })
    }
}

impl fmt::Debug for GatewayLndClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LndClient")
    }
}

#[async_trait]
impl ILnRpcClient for GatewayLndClient {
    async fn info(&self) -> crate::Result<GetNodeInfoResponse> {
        let mut client = self.client.clone();
        let info = client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .map_err(|e| {
                GatewayError::LnRpcError(tonic::Status::new(
                    tonic::Code::Internal,
                    format!("LND error: {e:?}"),
                ))
            })?
            .into_inner();

        let pub_key: PublicKey = info.identity_pubkey.parse().map_err(|e| {
            GatewayError::LnRpcError(tonic::Status::new(
                tonic::Code::Internal,
                format!("LND error: {e:?}"),
            ))
        })?;
        info!("LND pubkey {:?} Alias: {}", pub_key, info.alias);

        return Ok(GetNodeInfoResponse {
            pub_key: pub_key.serialize().to_vec(),
            alias: info.alias,
        });
    }

    async fn routehints(&self) -> crate::Result<GetRouteHintsResponse> {
        let mut client = self.client.clone();
        let channels = client
            .lightning()
            .list_channels(ListChannelsRequest {
                active_only: true,
                inactive_only: false,
                public_only: false,
                private_only: false,
                peer: vec![],
            })
            .await
            .map_err(|e| {
                GatewayError::LnRpcError(tonic::Status::new(
                    tonic::Code::Internal,
                    format!("LND error: {e:?}"),
                ))
            })?
            .into_inner();

        let mut route_hints: Vec<RouteHint> = vec![];
        for chan in channels.channels {
            let info = client
                .lightning()
                .get_chan_info(ChanInfoRequest {
                    chan_id: chan.chan_id,
                })
                .await
                .map_err(|e| {
                    GatewayError::LnRpcError(tonic::Status::new(
                        tonic::Code::Internal,
                        format!("LND error: {e:?}"),
                    ))
                })?
                .into_inner();

            let policy = match info.node1_policy.clone() {
                Some(policy) => policy,
                None => continue,
            };
            let src_node_id = PublicKey::from_str(&chan.remote_pubkey)
                .unwrap()
                .serialize()
                .to_vec();
            let short_channel_id = chan.chan_id;
            let base_msat = policy.fee_base_msat as u32;
            let proportional_millionths = policy.fee_rate_milli_msat as u32;
            let cltv_expiry_delta = policy.time_lock_delta;
            let htlc_maximum_msat = Some(policy.max_htlc_msat);
            let htlc_minimum_msat = Some(policy.min_htlc as u64);

            let route_hint_hop = RouteHintHop {
                src_node_id,
                short_channel_id,
                base_msat,
                proportional_millionths,
                cltv_expiry_delta,
                htlc_minimum_msat,
                htlc_maximum_msat,
            };
            route_hints.push(RouteHint {
                hops: vec![route_hint_hop],
            });
        }

        Ok(GetRouteHintsResponse { route_hints })
    }

    async fn pay(&self, invoice: PayInvoiceRequest) -> crate::Result<PayInvoiceResponse> {
        let mut client = self.client.clone();
        let send_response = client
            .lightning()
            .send_payment_sync(SendRequest {
                payment_request: invoice.invoice.to_string(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!(format!("LND error: {e:?}")))?
            .into_inner();
        info!("send response {:?}", send_response);

        if send_response.payment_preimage.is_empty() {
            return Err(GatewayError::LnRpcError(tonic::Status::new(
                tonic::Code::Internal,
                "LND did not return a preimage",
            )));
        };

        return Ok(PayInvoiceResponse {
            preimage: send_response.payment_preimage,
        });
    }

    async fn route_htlcs<'a>(
        &mut self,
        events: ReceiverStream<InterceptHtlcResponse>,
        task_group: &mut TaskGroup,
    ) -> Result<RouteHtlcStream<'a>, GatewayError> {
        const CHANNEL_SIZE: usize = 100;

        // Channel to send intercepted htlc to actor for processing
        // actor_sender needs to be saved when the scid is received
        let (actor_sender, actor_receiver) =
            mpsc::channel::<Result<InterceptHtlcRequest, tonic::Status>>(CHANNEL_SIZE);

        let (lnd_sender, lnd_rx) = mpsc::channel::<ForwardHtlcInterceptResponse>(CHANNEL_SIZE);
        self.spawn_interceptor(task_group, lnd_sender.clone(), lnd_rx, actor_sender.clone())
            .await;

        let mut stream = events.into_inner();
        task_group.spawn("LND Route HTLCs", |_handle| async move {
            while let Some(request) = stream.recv().await {
                let InterceptHtlcResponse {
                    action,
                    incoming_chan_id,
                    htlc_id,
                } = request;

                match action {
                    Some(Action::Settle(Settle { preimage })) => {
                        let _ = Self::settle_htlc(CircuitKey { chan_id: incoming_chan_id, htlc_id }, preimage, lnd_sender.clone()).await.map_err(|e| {
                            error!("Failed to settle HTLC: {:?}", e);
                        });
                    },
                    Some(Action::Cancel(Cancel { reason: _ })) => {
                        let _ = Self::cancel_htlc(CircuitKey { chan_id: incoming_chan_id, htlc_id }, lnd_sender.clone()).await.map_err(|e| {
                            error!("Failed to cancel HTLC: {:?}", e);
                        });
                    },
                    Some(Action::Forward(Forward { })) => {
                        let _ = Self::forward_htlc(CircuitKey { chan_id: incoming_chan_id, htlc_id }, lnd_sender.clone())
                            .await
                            .map_err(|e| {
                                error!("Failed to forward HTLC: {:?}", e);
                            });
                    }
                    None => {
                        error!("No action specified for intercepted htlc. This should not happen. ChanId: {} HTLC ID: {}", incoming_chan_id, htlc_id);
                        let _ = Self::cancel_htlc(CircuitKey { chan_id: incoming_chan_id, htlc_id }, lnd_sender.clone()).await.map_err(|e| {
                            error!("Failed to cancel HTLC: {:?}", e);
                        });
                    }
                };
            }
        })
        .await;

        Ok(Box::pin(ReceiverStream::new(actor_receiver)))
    }
}
