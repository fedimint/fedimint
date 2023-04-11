use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::task::{sleep, TaskGroup};
use secp256k1::PublicKey;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tonic_lnd::lnrpc::failure::FailureCode;
use tonic_lnd::lnrpc::{GetInfoRequest, SendRequest};
use tonic_lnd::routerrpc::{CircuitKey, ForwardHtlcInterceptResponse, ResolveHoldForwardAction};
use tonic_lnd::{connect, LndClient};
use tracing::{error, info, trace};

use crate::gatewaylnrpc::complete_htlcs_request::{Action, Cancel, Settle};
use crate::gatewaylnrpc::get_route_hints_response::RouteHint;
use crate::gatewaylnrpc::{
    route_htlc_request, route_htlc_response, CompleteHtlcsRequest, GetNodeInfoResponse,
    GetRouteHintsResponse, PayInvoiceRequest, PayInvoiceResponse, RouteHtlcRequest,
    RouteHtlcResponse, SubscribeInterceptHtlcsResponse,
};
use crate::lnrpc_client::{ILnRpcClient, RouteHtlcStream};
use crate::GatewayError;

type HtlcSubscriptionSender = mpsc::Sender<Result<RouteHtlcResponse, Status>>;

pub struct GatewayLndClient {
    /// LND client
    client: LndClient,
    /// Used to spawn a task handling HTLC subscriptions
    task_group: TaskGroup,
    /// Map of short channel id to the actor that is subscribed to HTLC updates
    subscriptions: Arc<Mutex<HashMap<u64, HtlcSubscriptionSender>>>,
    /// Sender that is used to send HTLC updates to LND (Resume, Reject, Settle)
    lnd_tx: mpsc::Sender<ForwardHtlcInterceptResponse>,
}

impl GatewayLndClient {
    pub async fn new(
        address: String,
        tls_cert: String,
        macaroon: String,
        task_group: TaskGroup,
    ) -> crate::Result<Self> {
        const CHANNEL_SIZE: usize = 100;
        let (lnd_tx, lnd_rx) = mpsc::channel::<ForwardHtlcInterceptResponse>(CHANNEL_SIZE);

        let client = Self::connect(address, tls_cert, macaroon).await?;
        let subscriptions = Arc::new(Mutex::new(HashMap::new()));

        let mut gw_rpc = GatewayLndClient {
            client,
            task_group,
            subscriptions,
            lnd_tx,
        };

        gw_rpc.spawn_interceptor(lnd_rx).await;
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

    async fn spawn_interceptor(&mut self, lnd_rx: mpsc::Receiver<ForwardHtlcInterceptResponse>) {
        let lnd_sender = self.lnd_tx.clone();
        let mut client = self.client.clone();
        let subs = self.subscriptions.clone();
        self.task_group
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

                    if let Some(actor_sender) =
                        Self::can_route_htlc(htlc.outgoing_requested_chan_id, subs.clone()).await
                    {
                        let intercept = SubscribeInterceptHtlcsResponse {
                            payment_hash: htlc.payment_hash,
                            incoming_amount_msat: htlc.incoming_amount_msat,
                            outgoing_amount_msat: htlc.outgoing_amount_msat,
                            incoming_expiry: htlc.incoming_expiry,
                            short_channel_id: htlc.outgoing_requested_chan_id,
                            incoming_chan_id: incoming_circuit_key.chan_id,
                            htlc_id: incoming_circuit_key.htlc_id,
                        };

                        match actor_sender
                            .send(Ok(RouteHtlcResponse {
                                action: Some(route_htlc_response::Action::SubscribeResponse(
                                    intercept,
                                )),
                            }))
                            .await
                        {
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
                    } else {
                        // Actor is not subscribed to this HTLC, simply forward it on.
                        let _ = Self::forward_htlc(incoming_circuit_key, lnd_sender.clone())
                            .await
                            .map_err(|e| {
                                error!("Failed to forward HTLC: {:?}", e);
                            });
                    }
                }
            })
            .await;
    }

    async fn can_route_htlc(
        short_channel_id: u64,
        subs: Arc<Mutex<HashMap<u64, HtlcSubscriptionSender>>>,
    ) -> Option<mpsc::Sender<Result<RouteHtlcResponse, Status>>> {
        subs.lock().await.get(&short_channel_id).cloned()
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
        // TODO: Issue #1953: Implement full route hint fetching for LND gateways
        Ok(GetRouteHintsResponse {
            route_hints: vec![RouteHint { hops: vec![] }],
        })
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
        events: ReceiverStream<RouteHtlcRequest>,
    ) -> Result<RouteHtlcStream<'a>, GatewayError> {
        const CHANNEL_SIZE: usize = 100;

        // Channel to send intercepted htlc to actor for processing
        // actor_sender needs to be saved when the scid is received
        let (actor_sender, actor_receiver) =
            mpsc::channel::<Result<RouteHtlcResponse, tonic::Status>>(CHANNEL_SIZE);

        let mut stream = events.into_inner();
        let subs = self.subscriptions.clone();
        let lnd_sender = self.lnd_tx.clone();
        self.task_group.spawn("LND Route HTLCs", |_handle| async move {
            while let Some(request) = stream.recv().await {
                match request.action {
                    Some(route_htlc_request::Action::SubscribeRequest(subscribe_request)) => {
                        // Save the channel to the actor so that the interceptor thread can send
                        // HTLCs to it
                        subs
                            .lock()
                            .await
                            .insert(subscribe_request.short_channel_id, actor_sender.clone());
                    }
                    Some(route_htlc_request::Action::CompleteRequest(complete_request)) => {
                        let CompleteHtlcsRequest {
                            action,
                            incoming_chan_id,
                            htlc_id,
                        } = complete_request;

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
                            None => {
                                error!("No action specified for intercepted htlc. This should not happen. ChanId: {} HTLC ID: {}", incoming_chan_id, htlc_id);
                                let _ = Self::cancel_htlc(CircuitKey { chan_id: incoming_chan_id, htlc_id }, lnd_sender.clone()).await.map_err(|e| {
                                    error!("Failed to cancel HTLC: {:?}", e);
                                });
                            }
                        };
                    }
                    None => {
                        error!("No action was sent as part of RouteHtlcRequest");
                    }
                }
            }
        })
        .await;

        Ok(Box::pin(ReceiverStream::new(actor_receiver)))
    }
}
