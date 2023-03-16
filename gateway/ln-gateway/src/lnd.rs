use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use bitcoin_hashes::{sha256, Hash};
use fedimint_core::task::TaskGroup;
use secp256k1::PublicKey;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic_lnd::lnrpc::{GetInfoRequest, SendRequest};
use tonic_lnd::routerrpc::{CircuitKey, ForwardHtlcInterceptResponse, ResolveHoldForwardAction};
use tonic_lnd::{connect, LndClient};
use tracing::{error, info, trace};

use crate::gatewaylnrpc::complete_htlcs_request::{Action, Cancel, Settle};
use crate::gatewaylnrpc::get_route_hints_response::RouteHint;
use crate::gatewaylnrpc::{
    CompleteHtlcsRequest, CompleteHtlcsResponse, GetPubKeyResponse, GetRouteHintsResponse,
    PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
    SubscribeInterceptHtlcsResponse,
};
use crate::lnrpc_client::{HtlcStream, ILnRpcClient};
use crate::GatewayError;

type OutcomeMap = Arc<Mutex<HashMap<sha256::Hash, (LndSenderRef, Option<CircuitKey>)>>>;

pub struct GatewayLndClient {
    client: LndClient,
    outcomes: OutcomeMap,
    task_group: TaskGroup,
}

// Reference to a sender that forwards ForwardHtlcInterceptResponse messages to
// LND
type LndSenderRef = Arc<mpsc::Sender<ForwardHtlcInterceptResponse>>;

impl GatewayLndClient {
    pub async fn new(
        address: String,
        tls_cert: String,
        macaroon: String,
        task_group: TaskGroup,
    ) -> crate::Result<Self> {
        let client = connect(address, tls_cert, macaroon).await.map_err(|e| {
            error!("Failed to connect to lnrpc server: {:?}", e);
            GatewayError::Other(anyhow!("Failed to connect to lnrpc server"))
        })?;

        Ok(Self {
            client,
            outcomes: Arc::new(Mutex::new(HashMap::new())),
            task_group,
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
    async fn pubkey(&self) -> crate::Result<GetPubKeyResponse> {
        let mut client = self.client.clone();

        let info = client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .expect("failed to get info")
            .into_inner();

        let pub_key: PublicKey = info.identity_pubkey.parse().expect("invalid pubkey");
        info!("fetched pubkey {:?}", pub_key);

        Ok(GetPubKeyResponse {
            pub_key: pub_key.serialize().to_vec(),
        })
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

        Ok(PayInvoiceResponse {
            preimage: send_response.payment_preimage,
        })
    }

    async fn subscribe_htlcs<'a>(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> crate::Result<HtlcStream<'a>> {
        const CHANNEL_SIZE: usize = 100;

        // Channel to send responses to LND after processing intercepted HTLC
        let (lnd_tx, lnd_rx) = mpsc::channel::<ForwardHtlcInterceptResponse>(CHANNEL_SIZE);

        // Channel to send intercepted htlc to gatewayd for processing
        let (gwd_tx, gwd_rx) =
            mpsc::channel::<Result<SubscribeInterceptHtlcsResponse, tonic::Status>>(CHANNEL_SIZE);

        let scid = subscription.short_channel_id;
        let mut client = self.client.clone();

        let mut tg = self.task_group.clone();
        let outcomes = self.outcomes.clone();

        // Spawn an LND interceptor task.
        // Within this task, we can run the thread blocking routerrpc
        // `htlc_interceptor`, And we can start a long running watcher for htlcs
        // streamed from LND.
        tg.spawn("LND HTLC Subscription", move |_handle| async move {
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
                    // Failed to establish a htlc stream.
                    // Since we don't have a stream to watch for intercepted htlcs,
                    // do the following:

                    // 1. Send an error to gatewayd htlc subscriber,
                    let _ = gwd_tx
                        .send(Err(tonic::Status::new(
                            tonic::Code::Internal,
                            e.to_string(),
                        )))
                        .await;

                    // 2. Early return to exit the spawned task
                    return;
                }
            };

            while let Some(htlc) = match htlc_stream.message().await {
                Ok(htlc) => htlc,
                Err(e) => {
                    error!("Error received over HTLC subscriprion: {:?}", e);
                    let _ = gwd_tx
                        .send(Err(tonic::Status::new(
                            tonic::Code::Internal,
                            e.to_string(),
                        )))
                        .await;
                    None
                }
            } {
                trace!("handling htlc {:?}", htlc);
                let response: Option<ForwardHtlcInterceptResponse> =
                    if htlc.outgoing_requested_chan_id != scid {
                        // Pass through: This HTLC doesn't belong to the current subscription
                        // Forward it to the next interceptor or next node
                        Some(ForwardHtlcInterceptResponse {
                            incoming_circuit_key: htlc.incoming_circuit_key,
                            action: ResolveHoldForwardAction::Resume.into(),
                            preimage: vec![],
                            failure_message: vec![],
                            failure_code: 0,
                        })
                    } else {
                        // TODO: generate unique id for each intercepted HTLC
                        let intercepted_htlc_id = sha256::Hash::hash(&htlc.onion_blob);

                        // Intercept: This HTLC belongs to the current subscription
                        let intercept = SubscribeInterceptHtlcsResponse {
                            payment_hash: htlc.payment_hash,
                            incoming_amount_msat: htlc.incoming_amount_msat,
                            outgoing_amount_msat: htlc.outgoing_amount_msat,
                            incoming_expiry: htlc.incoming_expiry,
                            short_channel_id: scid,
                            intercepted_htlc_id: intercepted_htlc_id.into_inner().to_vec(),
                        };

                        // Send it to gatewayd for processing
                        match gwd_tx.send(Ok(intercept)).await {
                            Ok(_) => {
                                // Keep a reference to LND sender reference so we can later forward
                                // outcomes on `complete_htlc` rpc
                                outcomes.lock().await.insert(
                                    intercepted_htlc_id,
                                    (Arc::new(lnd_tx.clone()), htlc.incoming_circuit_key),
                                );

                                None
                            }
                            Err(e) => {
                                error!("Failed to send HTLC to gatewayd for processing: {:?}", e);
                                Some(cancel_intercepted_htlc(htlc.incoming_circuit_key))
                            }
                        }
                    };

                if response.is_some() {
                    // TODO: Consider retrying this if the send fails
                    let _ = lnd_tx.send(response.unwrap()).await.map_err(|e| {
                        error!("Failed to send response to LND: {:?}", e);
                        // The HTLC will timeout and LND will automatically cancel it.
                        GatewayError::Other(anyhow!("Failed to send response to LND"))
                    });
                }
            }

            info!("HTLC subscription stream ended");
        })
        .await;

        Ok(Box::pin(ReceiverStream::new(gwd_rx)))
    }

    async fn complete_htlc(
        &self,
        request: CompleteHtlcsRequest,
    ) -> crate::Result<CompleteHtlcsResponse> {
        let CompleteHtlcsRequest {
            action,
            intercepted_htlc_id,
        } = request;

        let hash = match sha256::Hash::from_slice(&intercepted_htlc_id) {
            Ok(hash) => hash,
            Err(e) => {
                error!("Invalid intercepted_htlc_id: {:?}", e);
                return Err(GatewayError::LnRpcError(tonic::Status::invalid_argument(
                    e.to_string(),
                )));
            }
        };

        info!("Completing htlc with reference, {:?}", hash);

        if let Some((outcome, incoming_circuit_key)) = self.outcomes.lock().await.remove(&hash) {
            let htlc_action_res = match action {
                Some(Action::Settle(Settle { preimage })) => ForwardHtlcInterceptResponse {
                    incoming_circuit_key,
                    action: ResolveHoldForwardAction::Settle.into(),
                    preimage,
                    failure_message: vec![],
                    failure_code: 0,
                },
                Some(Action::Cancel(Cancel { reason: _ })) => cancel_intercepted_htlc(None),
                None => {
                    error!("No action specified for intercepted htlc id: {:?}", hash);
                    return Err(GatewayError::LnRpcError(tonic::Status::internal(
                        "No action specified on this intercepted htlc",
                    )));
                }
            };

            // TODO: Consider retrying this if the send fails
            let _ = outcome.send(htlc_action_res).await.map_err(|_| {
                GatewayError::LnRpcError(tonic::Status::internal(
                    "Failed to send htlc processing outcome to LND node",
                ))
            });

            Ok(CompleteHtlcsResponse {})
        } else {
            error!(
                "No interceptor reference found for this processed htlc with id: {:?}",
                intercepted_htlc_id
            );
            // FIXME: Use error codes to signal the gateway to take reactionary actions
            return Err(GatewayError::LnRpcError(tonic::Status::internal(
                "No interceptor reference found for this processed htlc. Potential loss of funds",
            )));
        }
    }
}

fn cancel_intercepted_htlc(key: Option<CircuitKey>) -> ForwardHtlcInterceptResponse {
    // TODO: Specify a failure code and message
    ForwardHtlcInterceptResponse {
        incoming_circuit_key: key,
        action: ResolveHoldForwardAction::Fail.into(),
        preimage: vec![],
        failure_message: vec![],
        failure_code: 0,
    }
}
