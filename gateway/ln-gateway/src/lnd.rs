use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use bitcoin_hashes::{sha256, Hash};
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
    self, route_htlc_request, route_htlc_response, CompleteHtlcsRequest, GetNodeInfoResponse,
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

    subscriptions: Arc<Mutex<HashMap<u64, HtlcSubscriptionSender>>>,

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
        let subs = Arc::new(Mutex::new(HashMap::new()));

        let mut gw_rpc = GatewayLndClient {
            client: client,
            task_group,
            subscriptions: subs,
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
                    let response: Option<ForwardHtlcInterceptResponse> = if let Some(a_tx) =
                        subs.lock().await.get(&htlc.outgoing_requested_chan_id)
                    {
                        let intercepted_htlc_id = sha256::Hash::hash(&htlc.onion_blob);

                        let CircuitKey { chan_id, htlc_id } =
                            htlc.incoming_circuit_key.clone().unwrap();

                        let intercept = SubscribeInterceptHtlcsResponse {
                            payment_hash: htlc.payment_hash,
                            incoming_amount_msat: htlc.incoming_amount_msat,
                            outgoing_amount_msat: htlc.outgoing_amount_msat,
                            incoming_expiry: htlc.incoming_expiry,
                            short_channel_id: htlc.outgoing_requested_chan_id,
                            intercepted_htlc_id: intercepted_htlc_id.into_inner().to_vec(),
                            key: Some(gatewaylnrpc::CircuitKey { chan_id, htlc_id }),
                        };

                        match a_tx
                            .send(Ok(RouteHtlcResponse {
                                action: Some(route_htlc_response::Action::SubscribeResponse(
                                    intercept,
                                )),
                            }))
                            .await
                        {
                            Ok(_) => None,
                            Err(e) => {
                                error!("Failed to send HTLC to gatewayd for processing: {:?}", e);
                                Some(cancel_intercepted_htlc(htlc.incoming_circuit_key))
                            }
                        }
                    } else {
                        // Actor is not subscribed to this HTLC, simply forward it on.
                        Some(ForwardHtlcInterceptResponse {
                            incoming_circuit_key: htlc.incoming_circuit_key,
                            action: ResolveHoldForwardAction::Resume.into(),
                            preimage: vec![],
                            failure_message: vec![],
                            failure_code: FailureCode::TemporaryChannelFailure.into(),
                        })
                    };

                    if response.is_some() {
                        lnd_sender
                            .send(response.unwrap())
                            .await
                            .unwrap_or_else(|_| {
                                error!(
                                    "Failed to send ForwardHtlcInterceptResponse over LND channel"
                                )
                            });
                    }
                }
            })
            .await;
    }

    async fn settle_htlc(
        key: gatewaylnrpc::CircuitKey,
        preimage: Vec<u8>,
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
    ) -> crate::Result<()> {
        let gatewaylnrpc::CircuitKey { chan_id, htlc_id } = key;
        let response = ForwardHtlcInterceptResponse {
            incoming_circuit_key: Some(CircuitKey { chan_id, htlc_id }),
            action: ResolveHoldForwardAction::Settle.into(),
            preimage,
            failure_message: vec![],
            failure_code: FailureCode::TemporaryChannelFailure.into(),
        };

        // TODO: Consider retrying this if the send fails
        lnd_sender.send(response).await.map_err(|_| {
            GatewayError::Other(anyhow::anyhow!(
                "Failed to send ForwardHtlcInterceptResponse to LND"
            ))
        })
    }

    async fn cancel_htlc(
        key: gatewaylnrpc::CircuitKey,
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
    ) -> crate::Result<()> {
        let response = cancel_intercepted_htlc(Some(CircuitKey {
            chan_id: key.chan_id,
            htlc_id: key.htlc_id,
        }));
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

    async fn route_htlc<'a>(
        &self,
        events: ReceiverStream<RouteHtlcRequest>,
    ) -> Result<RouteHtlcStream<'a>, GatewayError> {
        const CHANNEL_SIZE: usize = 100;

        // Channel to send intercepted htlc to actor for processing
        // a_tx needs to be save when the scid is received
        let (a_tx, a_rx) = mpsc::channel::<Result<RouteHtlcResponse, tonic::Status>>(CHANNEL_SIZE);

        let mut tg = self.task_group.make_subgroup().await;

        let mut stream = events.into_inner();
        let subs = self.subscriptions.clone();
        let lnd_sender = self.lnd_tx.clone();
        tg.spawn("LND Route HTLCs", |_handle| async move {
            while let Some(request) = stream.recv().await {
                match request.action {
                    Some(route_htlc_request::Action::SubscribeRequest(subscribe_request)) => {
                        // Save the channel to the actor so that the interceptor thread can send
                        // HTLCs to it
                        subs
                            .lock()
                            .await
                            .insert(subscribe_request.short_channel_id, a_tx.clone());
                    }
                    Some(route_htlc_request::Action::CompleteRequest(complete_request)) => {
                        let CompleteHtlcsRequest {
                            action,
                            intercepted_htlc_id: _,
                            key,
                        } = complete_request;

                        if let Some(circuit_key) = key {
                            match action {
                                Some(Action::Settle(Settle { preimage })) => {
                                    Self::settle_htlc(circuit_key, preimage, lnd_sender.clone()).await.expect("Error settling HTLC");
                                },
                                Some(Action::Cancel(Cancel { reason: _ })) => {
                                    Self::cancel_htlc(circuit_key, lnd_sender.clone()).await.expect("Error canceling HTLC");
                                },
                                None => {
                                    error!("No action specified for intercepted htlc. ChanId: {} HTLC ID: {}", circuit_key.chan_id, circuit_key.htlc_id);
                                    Self::cancel_htlc(circuit_key, lnd_sender.clone()).await.expect("Error canceling HTLC");
                                }
                            };
                        }
                    }
                    None => {
                        error!("No action was sent as part of RouteHtlcRequest");
                    }
                }
            }
        })
        .await;

        Ok(Box::pin(ReceiverStream::new(a_rx)))
    }
}

fn cancel_intercepted_htlc(key: Option<CircuitKey>) -> ForwardHtlcInterceptResponse {
    // TODO: Specify a failure code and message
    ForwardHtlcInterceptResponse {
        incoming_circuit_key: key,
        action: ResolveHoldForwardAction::Fail.into(),
        preimage: vec![],
        failure_message: vec![],
        failure_code: FailureCode::TemporaryChannelFailure.into(),
    }
}
