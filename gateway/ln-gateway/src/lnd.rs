use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use fedimint_core::task::{sleep, TaskGroup};
use secp256k1::PublicKey;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tonic_lnd::lnrpc::failure::FailureCode;
use tonic_lnd::lnrpc::payment::PaymentStatus;
use tonic_lnd::lnrpc::{ChanInfoRequest, GetInfoRequest, ListChannelsRequest};
use tonic_lnd::routerrpc::{
    CircuitKey, ForwardHtlcInterceptResponse, ResolveHoldForwardAction, SendPaymentRequest,
    TrackPaymentRequest,
};
use tonic_lnd::tonic::Code;
use tonic_lnd::{connect, Client as LndClient};
use tracing::{debug, error, info, trace, warn};

use crate::gatewaylnrpc::get_route_hints_response::{RouteHint, RouteHintHop};
use crate::gatewaylnrpc::intercept_htlc_response::{Action, Cancel, Forward, Settle};
use crate::gatewaylnrpc::{
    EmptyResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcRequest,
    InterceptHtlcResponse, PayInvoiceRequest, PayInvoiceResponse,
};
use crate::lnrpc_client::{ILnRpcClient, RouteHtlcStream, MAX_LIGHTNING_RETRIES};
use crate::GatewayError;

type HtlcSubscriptionSender = mpsc::Sender<Result<InterceptHtlcRequest, Status>>;

const LND_PAYMENT_TIMEOUT_SECONDS: i32 = 180;

pub struct GatewayLndClient {
    /// LND client
    address: String,
    tls_cert: String,
    macaroon: String,
    lnd_sender: Option<mpsc::Sender<ForwardHtlcInterceptResponse>>,
}

impl GatewayLndClient {
    pub async fn new(
        address: String,
        tls_cert: String,
        macaroon: String,
        lnd_sender: Option<mpsc::Sender<ForwardHtlcInterceptResponse>>,
    ) -> Self {
        info!(
            "Gateway configured to connect to LND LnRpcClient at \n address: {},\n tls cert path: {},\n macaroon path: {} ",
            address, tls_cert, macaroon
        );
        GatewayLndClient {
            address,
            tls_cert,
            macaroon,
            lnd_sender,
        }
    }

    async fn connect(
        address: String,
        tls_cert: String,
        macaroon: String,
    ) -> crate::Result<LndClient> {
        let mut retries = 0;
        let client = loop {
            if retries >= MAX_LIGHTNING_RETRIES {
                return Err(GatewayError::Other(anyhow::anyhow!(
                    "Failed to connect to LND"
                )));
            }

            retries += 1;

            match connect(address.clone(), tls_cert.clone(), macaroon.clone()).await {
                Ok(client) => break client,
                Err(e) => {
                    tracing::debug!("Couldn't connect to LND, retrying in 1 second... {e:?}");
                    sleep(Duration::from_secs(1)).await;
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
        gateway_sender: HtlcSubscriptionSender,
    ) -> crate::Result<()> {
        let mut client = Self::connect(
            self.address.clone(),
            self.tls_cert.clone(),
            self.macaroon.clone(),
        )
        .await?;

        // Verify that LND is reachable via RPC before attempting to spawn a new thread
        // that will intercept HTLCs.
        client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .map_err(|e| {
                GatewayError::LnRpcError(tonic::Status::new(
                    tonic::Code::Internal,
                    format!("LND error: {e:?}"),
                ))
            })?;

        task_group
            .spawn("LND HTLC Subscription", move |_handle| async move {
                let mut htlc_stream = match client
                    .router()
                    .htlc_interceptor(ReceiverStream::new(lnd_rx))
                    .await
                    .map_err(|e| {
                        error!("Failed to connect to lightning node");
                        debug!("Error: {:?}", e);
                        GatewayError::Other(anyhow!("Failed to subscribe to LND htlc stream"))
                    }) {
                    Ok(stream) => stream.into_inner(),
                    Err(e) => {
                        error!("Failed to establish htlc stream");
                        debug!("Error: {:?}", e);
                        return;
                    }
                };

                while let Some(htlc) = match htlc_stream.message().await {
                    Ok(htlc) => htlc,
                    Err(e) => {
                        error!("Error received over HTLC stream: {:?}", e);
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

                    match gateway_sender.send(Ok(intercept)).await {
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

        Ok(())
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

    async fn lookup_payment(
        &self,
        payment_hash: Vec<u8>,
        client: &mut LndClient,
    ) -> Result<Option<String>, GatewayError> {
        // Loop until we successfully get the status of the payment, or determine that
        // the payment has not been made yet.
        loop {
            let payments = client
                .router()
                .track_payment_v2(TrackPaymentRequest {
                    payment_hash: payment_hash.clone(),
                    no_inflight_updates: true,
                })
                .await;

            match payments {
                Ok(payments) => {
                    // Block until LND returns the completed payment
                    if let Some(payment) = payments
                        .into_inner()
                        .message()
                        .await
                        .map_err(|_| GatewayError::ClientNgError)?
                    {
                        if payment.status() == PaymentStatus::Succeeded {
                            return Ok(Some(payment.payment_preimage));
                        }

                        let failure_reason = payment.failure_reason();
                        return Err(GatewayError::Other(anyhow!(
                            "LND payment failed. Failure Reason: {failure_reason:?}"
                        )));
                    }
                }
                Err(e) => {
                    // Break if we got a response back from the LND node that indicates the payment
                    // hash was not found.
                    if e.code() == Code::NotFound {
                        return Ok(None);
                    }

                    warn!("Could not get the status of payment {payment_hash:?} Error: {e:?}. Trying again in 5 seconds");
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
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
        let mut client = Self::connect(
            self.address.clone(),
            self.tls_cert.clone(),
            self.macaroon.clone(),
        )
        .await?;
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

        return Ok(GetNodeInfoResponse {
            pub_key: pub_key.serialize().to_vec(),
            alias: info.alias,
        });
    }

    async fn routehints(&self) -> crate::Result<GetRouteHintsResponse> {
        let mut client = Self::connect(
            self.address.clone(),
            self.tls_cert.clone(),
            self.macaroon.clone(),
        )
        .await?;
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

    async fn pay(&self, request: PayInvoiceRequest) -> crate::Result<PayInvoiceResponse> {
        let PayInvoiceRequest {
            invoice,
            max_fee_msat,
            payment_hash,
            ..
        } = request;

        let mut client = Self::connect(
            self.address.clone(),
            self.tls_cert.clone(),
            self.macaroon.clone(),
        )
        .await?;

        // If the payment exists, that means we've already tried to pay the invoice
        let preimage: Vec<u8> = if let Some(preimage) = self
            .lookup_payment(payment_hash.clone(), &mut client)
            .await?
        {
            bitcoin_hashes::hex::FromHex::from_hex(preimage.as_str())
                .map_err(|_| anyhow::anyhow!("Failed to convert preimage"))?
        } else {
            // LND API allows fee limits in the `i64` range, but we use `u64` for
            // max_fee_msat. This means we can only set an enforceable fee limit
            // between 0 and i64::MAX
            let fee_limit_msat: i64 = max_fee_msat
                .try_into()
                .map_err(|_| anyhow::anyhow!("max_fee_msat exceeds valid LND fee limit ranges"))?;

            let payments = client
                .router()
                .send_payment_v2(SendPaymentRequest {
                    payment_request: invoice,
                    allow_self_payment: true,
                    no_inflight_updates: true,
                    timeout_seconds: LND_PAYMENT_TIMEOUT_SECONDS,
                    fee_limit_msat,
                    ..Default::default()
                })
                .await
                .map_err(|e| {
                    GatewayError::Other(anyhow!("Failed to make outgoing payment: {e:?}"))
                })?;

            match payments
                .into_inner()
                .message()
                .await
                .context("Failed to get payment status")?
            {
                Some(payment) if payment.status() == PaymentStatus::Succeeded => {
                    bitcoin_hashes::hex::FromHex::from_hex(payment.payment_preimage.as_str())
                        .context("Failed to convert preimage")?
                }
                Some(payment) => {
                    return Err(GatewayError::Other(anyhow!(
                        "LND failed to complete payment: {payment:?}"
                    )));
                }
                None => {
                    return Err(GatewayError::Other(anyhow!(
                        "Failed to get payment status for payment_hash {payment_hash:?}"
                    )));
                }
            }
        };

        return Ok(PayInvoiceResponse { preimage });
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), GatewayError> {
        const CHANNEL_SIZE: usize = 100;

        // Channel to send intercepted htlc to the gateway for processing
        let (gateway_sender, gateway_receiver) =
            mpsc::channel::<Result<InterceptHtlcRequest, tonic::Status>>(CHANNEL_SIZE);

        let (lnd_sender, lnd_rx) = mpsc::channel::<ForwardHtlcInterceptResponse>(CHANNEL_SIZE);

        self.spawn_interceptor(
            task_group,
            lnd_sender.clone(),
            lnd_rx,
            gateway_sender.clone(),
        )
        .await?;
        let new_client = Arc::new(
            Self::new(
                self.address.clone(),
                self.tls_cert.clone(),
                self.macaroon.clone(),
                Some(lnd_sender.clone()),
            )
            .await,
        );
        Ok((Box::pin(ReceiverStream::new(gateway_receiver)), new_client))
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, GatewayError> {
        if let Some(lnd_sender) = self.lnd_sender.clone() {
            let InterceptHtlcResponse {
                action,
                incoming_chan_id,
                htlc_id,
            } = htlc;

            let (action, preimage) = match action {
                Some(Action::Settle(Settle { preimage })) => {
                    (ResolveHoldForwardAction::Settle.into(), preimage)
                }
                Some(Action::Cancel(Cancel { reason: _ })) => {
                    (ResolveHoldForwardAction::Fail.into(), vec![])
                }
                Some(Action::Forward(Forward {})) => {
                    (ResolveHoldForwardAction::Resume.into(), vec![])
                }
                None => (ResolveHoldForwardAction::Fail.into(), vec![]),
            };

            let response = ForwardHtlcInterceptResponse {
                incoming_circuit_key: Some(CircuitKey {
                    chan_id: incoming_chan_id,
                    htlc_id,
                }),
                action,
                preimage,
                failure_message: vec![],
                failure_code: FailureCode::TemporaryChannelFailure.into(),
            };

            Self::send_lnd_response(lnd_sender, response).await?;
            return Ok(EmptyResponse {});
        }

        Err(GatewayError::Other(anyhow::anyhow!(
            "Gatewayd has not started to route HTLCs"
        )))
    }
}
