use std::fmt::{self, Display};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::ensure;
use async_trait::async_trait;
use bitcoin::OutPoint;
use bitcoin::hashes::{Hash, sha256};
use fedimint_core::encoding::Encodable;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::FmtCompact;
use fedimint_core::{Amount, BitcoinAmountOrAll, crit, secp256k1};
use fedimint_gateway_common::{
    ListTransactionsResponse, PaymentDetails, PaymentDirection, PaymentKind,
};
use fedimint_ln_common::PrunedInvoice;
use fedimint_ln_common::contracts::Preimage;
use fedimint_ln_common::route_hints::{RouteHint, RouteHintHop};
use fedimint_logging::LOG_LIGHTNING;
use hex::ToHex;
use secp256k1::PublicKey;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic_lnd::invoicesrpc::lookup_invoice_msg::InvoiceRef;
use tonic_lnd::invoicesrpc::{
    AddHoldInvoiceRequest, CancelInvoiceMsg, LookupInvoiceMsg, SettleInvoiceMsg,
    SubscribeSingleInvoiceRequest,
};
use tonic_lnd::lnrpc::channel_point::FundingTxid;
use tonic_lnd::lnrpc::failure::FailureCode;
use tonic_lnd::lnrpc::invoice::InvoiceState;
use tonic_lnd::lnrpc::payment::PaymentStatus;
use tonic_lnd::lnrpc::{
    ChanInfoRequest, ChannelBalanceRequest, ChannelPoint, CloseChannelRequest, ConnectPeerRequest,
    GetInfoRequest, Invoice, InvoiceSubscription, LightningAddress, ListChannelsRequest,
    ListInvoiceRequest, ListPaymentsRequest, ListPeersRequest, OpenChannelRequest,
    SendCoinsRequest, WalletBalanceRequest,
};
use tonic_lnd::routerrpc::{
    CircuitKey, ForwardHtlcInterceptResponse, ResolveHoldForwardAction, SendPaymentRequest,
    TrackPaymentRequest,
};
use tonic_lnd::tonic::Code;
use tonic_lnd::walletrpc::AddrRequest;
use tonic_lnd::{Client as LndClient, connect};
use tracing::{debug, info, trace, warn};

use super::{
    ChannelInfo, ILnRpcClient, LightningRpcError, ListChannelsResponse, MAX_LIGHTNING_RETRIES,
    RouteHtlcStream,
};
use crate::{
    CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, CreateInvoiceRequest,
    CreateInvoiceResponse, GetBalancesResponse, GetInvoiceRequest, GetInvoiceResponse,
    GetLnOnchainAddressResponse, GetNodeInfoResponse, GetRouteHintsResponse,
    InterceptPaymentRequest, InterceptPaymentResponse, InvoiceDescription, OpenChannelResponse,
    PayInvoiceResponse, PaymentAction, SendOnchainRequest, SendOnchainResponse,
};

type HtlcSubscriptionSender = mpsc::Sender<InterceptPaymentRequest>;

const LND_PAYMENT_TIMEOUT_SECONDS: i32 = 180;

#[derive(Clone)]
pub struct GatewayLndClient {
    /// LND client
    address: String,
    tls_cert: String,
    macaroon: String,
    lnd_sender: Option<mpsc::Sender<ForwardHtlcInterceptResponse>>,
}

impl GatewayLndClient {
    pub fn new(
        address: String,
        tls_cert: String,
        macaroon: String,
        lnd_sender: Option<mpsc::Sender<ForwardHtlcInterceptResponse>>,
    ) -> Self {
        info!(
            target: LOG_LIGHTNING,
            address = %address,
            tls_cert_path = %tls_cert,
            macaroon = %macaroon,
            "Gateway configured to connect to LND LnRpcClient",
        );
        GatewayLndClient {
            address,
            tls_cert,
            macaroon,
            lnd_sender,
        }
    }

    async fn connect(&self) -> Result<LndClient, LightningRpcError> {
        let mut retries = 0;
        let client = loop {
            if retries >= MAX_LIGHTNING_RETRIES {
                return Err(LightningRpcError::FailedToConnect);
            }

            retries += 1;

            match connect(
                self.address.clone(),
                self.tls_cert.clone(),
                self.macaroon.clone(),
            )
            .await
            {
                Ok(client) => break client,
                Err(err) => {
                    debug!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Couldn't connect to LND, retrying in 1 second...");
                    sleep(Duration::from_secs(1)).await;
                }
            }
        };

        Ok(client)
    }

    /// Spawns a new background task that subscribes to updates of a specific
    /// HOLD invoice. When the HOLD invoice is ACCEPTED, we can request the
    /// preimage from the Gateway. A new task is necessary because LND's
    /// global `subscribe_invoices` does not currently emit updates for HOLD invoices: <https://github.com/lightningnetwork/lnd/issues/3120>
    async fn spawn_lnv2_hold_invoice_subscription(
        &self,
        task_group: &TaskGroup,
        gateway_sender: HtlcSubscriptionSender,
        payment_hash: Vec<u8>,
    ) -> Result<(), LightningRpcError> {
        let mut client = self.connect().await?;

        let self_copy = self.clone();
        let r_hash = payment_hash.clone();
        task_group.spawn("LND HOLD Invoice Subscription", |handle| async move {
            let future_stream =
                client
                    .invoices()
                    .subscribe_single_invoice(SubscribeSingleInvoiceRequest {
                        r_hash: r_hash.clone(),
                    });

            let mut hold_stream = tokio::select! {
                stream = future_stream => {
                    match stream {
                        Ok(stream) => stream.into_inner(),
                        Err(err) => {
                            crit!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Failed to subscribe to hold invoice updates");
                            return;
                        }
                    }
                },
                () = handle.make_shutdown_rx() => {
                    info!(target: LOG_LIGHTNING, "LND HOLD Invoice Subscription received shutdown signal");
                    return;
                }
            };

            while let Some(hold) = tokio::select! {
                () = handle.make_shutdown_rx() => {
                    None
                }
                hold_update = hold_stream.message() => {
                    match hold_update {
                        Ok(hold) => hold,
                        Err(err) => {
                            crit!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Error received over hold invoice update stream");
                            None
                        }
                    }
                }
            } {
                debug!(
                    target: LOG_LIGHTNING,
                    payment_hash = %PrettyPaymentHash(&r_hash),
                    state = %hold.state,
                    "LND HOLD Invoice Update",
                );

                if hold.state() == InvoiceState::Accepted {
                    let intercept = InterceptPaymentRequest {
                        payment_hash: Hash::from_slice(&hold.r_hash.clone())
                            .expect("Failed to convert to Hash"),
                        amount_msat: hold.amt_paid_msat as u64,
                        // The rest of the fields are not used in LNv2 and can be removed once LNv1
                        // support is over
                        expiry: hold.expiry as u32,
                        short_channel_id: Some(0),
                        incoming_chan_id: 0,
                        htlc_id: 0,
                    };

                    match gateway_sender.send(intercept).await {
                        Ok(()) => {}
                        Err(err) => {
                            warn!(
                                target: LOG_LIGHTNING,
                                err = %err.fmt_compact(),
                                "Hold Invoice Subscription failed to send Intercept to gateway"
                            );
                            let _ = self_copy.cancel_hold_invoice(hold.r_hash).await;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Spawns a new background task that subscribes to "add" updates for all
    /// invoices. This is used to detect when a new invoice has been
    /// created. If this invoice is a HOLD invoice, it is potentially destined
    /// for a federation. At this point, we spawn a separate task to monitor the
    /// status of the HOLD invoice.
    async fn spawn_lnv2_invoice_subscription(
        &self,
        task_group: &TaskGroup,
        gateway_sender: HtlcSubscriptionSender,
    ) -> Result<(), LightningRpcError> {
        let mut client = self.connect().await?;

        // Compute the minimum `add_index` that we need to subscribe to updates for.
        let add_index = client
            .lightning()
            .list_invoices(ListInvoiceRequest {
                pending_only: true,
                index_offset: 0,
                num_max_invoices: u64::MAX,
                reversed: false,
                ..Default::default()
            })
            .await
            .map_err(|status| {
                warn!(target: LOG_LIGHTNING, status = %status, "Failed to list all invoices");
                LightningRpcError::FailedToRouteHtlcs {
                    failure_reason: "Failed to list all invoices".to_string(),
                }
            })?
            .into_inner()
            .first_index_offset;

        let self_copy = self.clone();
        let hold_group = task_group.make_subgroup();
        task_group.spawn("LND Invoice Subscription", move |handle| async move {
            let future_stream = client.lightning().subscribe_invoices(InvoiceSubscription {
                add_index,
                settle_index: u64::MAX, // we do not need settle invoice events
            });
            let mut invoice_stream = tokio::select! {
                stream = future_stream => {
                    match stream {
                        Ok(stream) => stream.into_inner(),
                        Err(err) => {
                            warn!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Failed to subscribe to all invoice updates");
                            return;
                        }
                    }
                },
                () = handle.make_shutdown_rx() => {
                    info!(target: LOG_LIGHTNING, "LND Invoice Subscription received shutdown signal");
                    return;
                }
            };

            info!(target: LOG_LIGHTNING, "LND Invoice Subscription: starting to process invoice updates");
            while let Some(invoice) = tokio::select! {
                () = handle.make_shutdown_rx() => {
                    info!(target: LOG_LIGHTNING, "LND Invoice Subscription task received shutdown signal");
                    None
                }
                invoice_update = invoice_stream.message() => {
                    match invoice_update {
                        Ok(invoice) => invoice,
                        Err(err) => {
                            warn!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Error received over invoice update stream");
                            None
                        }
                    }
                }
            } {
                // If the `r_preimage` is empty and the invoice is OPEN, this means a new HOLD
                // invoice has been created, which is potentially an invoice destined for a
                // federation. We will spawn a new task to monitor the status of
                // the HOLD invoice.
                let payment_hash = invoice.r_hash.clone();

                debug!(
                    target: LOG_LIGHTNING,
                    payment_hash = %PrettyPaymentHash(&payment_hash),
                    state = %invoice.state,
                    "LND HOLD Invoice Update",
                );

                if invoice.r_preimage.is_empty() && invoice.state() == InvoiceState::Open {
                    info!(
                        target: LOG_LIGHTNING,
                        payment_hash = %PrettyPaymentHash(&payment_hash),
                        "Monitoring new LNv2 invoice",
                    );
                    if let Err(err) = self_copy
                        .spawn_lnv2_hold_invoice_subscription(
                            &hold_group,
                            gateway_sender.clone(),
                            payment_hash.clone(),
                        )
                        .await
                    {
                        warn!(
                            target: LOG_LIGHTNING,
                            err = %err.fmt_compact(),
                            payment_hash = %PrettyPaymentHash(&payment_hash),
                            "Failed to spawn HOLD invoice subscription task",
                        );
                    }
                }
            }
        });

        Ok(())
    }

    /// Spawns a new background task that intercepts HTLCs from the LND node. In
    /// the LNv1 protocol, this is used as a trigger mechanism for
    /// requesting the Gateway to retrieve the preimage for a payment.
    async fn spawn_lnv1_htlc_interceptor(
        &self,
        task_group: &TaskGroup,
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
        lnd_rx: mpsc::Receiver<ForwardHtlcInterceptResponse>,
        gateway_sender: HtlcSubscriptionSender,
    ) -> Result<(), LightningRpcError> {
        let mut client = self.connect().await?;

        // Verify that LND is reachable via RPC before attempting to spawn a new thread
        // that will intercept HTLCs.
        client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .map_err(|status| LightningRpcError::FailedToGetNodeInfo {
                failure_reason: format!("Failed to get node info {status:?}"),
            })?;

        task_group.spawn("LND HTLC Subscription", |handle| async move {
                let future_stream = client
                    .router()
                    .htlc_interceptor(ReceiverStream::new(lnd_rx));
                let mut htlc_stream = tokio::select! {
                    stream = future_stream => {
                        match stream {
                            Ok(stream) => stream.into_inner(),
                            Err(e) => {
                                crit!(target: LOG_LIGHTNING, err = %e.fmt_compact(), "Failed to establish htlc stream");
                                return;
                            }
                        }
                    },
                    () = handle.make_shutdown_rx() => {
                        info!(target: LOG_LIGHTNING, "LND HTLC Subscription received shutdown signal while trying to intercept HTLC stream, exiting...");
                        return;
                    }
                };

                debug!(target: LOG_LIGHTNING, "LND HTLC Subscription: starting to process stream");
                // To gracefully handle shutdown signals, we need to be able to receive signals
                // while waiting for the next message from the HTLC stream.
                //
                // If we're in the middle of processing a message from the stream, we need to
                // finish before stopping the spawned task. Checking if the task group is
                // shutting down at the start of each iteration will cause shutdown signals to
                // not process until another message arrives from the HTLC stream, which may
                // take a long time, or never.
                while let Some(htlc) = tokio::select! {
                    () = handle.make_shutdown_rx() => {
                        info!(target: LOG_LIGHTNING, "LND HTLC Subscription task received shutdown signal");
                        None
                    }
                    htlc_message = htlc_stream.message() => {
                        match htlc_message {
                            Ok(htlc) => htlc,
                            Err(err) => {
                                warn!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Error received over HTLC stream");
                                None
                            }
                    }}
                } {
                    trace!(target: LOG_LIGHTNING, ?htlc, "LND Handling HTLC");

                    if htlc.incoming_circuit_key.is_none() {
                        warn!(target: LOG_LIGHTNING, "Cannot route htlc with None incoming_circuit_key");
                        continue;
                    }

                    let incoming_circuit_key = htlc.incoming_circuit_key.unwrap();

                    // Forward all HTLCs to gatewayd, gatewayd will filter them based on scid
                    let intercept = InterceptPaymentRequest {
                        payment_hash: Hash::from_slice(&htlc.payment_hash).expect("Failed to convert payment Hash"),
                        amount_msat: htlc.outgoing_amount_msat,
                        expiry: htlc.incoming_expiry,
                        short_channel_id: Some(htlc.outgoing_requested_chan_id),
                        incoming_chan_id: incoming_circuit_key.chan_id,
                        htlc_id: incoming_circuit_key.htlc_id,
                    };

                    match gateway_sender.send(intercept).await {
                        Ok(()) => {}
                        Err(err) => {
                            warn!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Failed to send HTLC to gatewayd for processing");
                            let _ = Self::cancel_htlc(incoming_circuit_key, lnd_sender.clone())
                                .await
                                .map_err(|err| {
                                    warn!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Failed to cancel HTLC");
                                });
                        }
                    }
                }
            });

        Ok(())
    }

    /// Spawns background tasks for monitoring the status of incoming payments.
    async fn spawn_interceptor(
        &self,
        task_group: &TaskGroup,
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
        lnd_rx: mpsc::Receiver<ForwardHtlcInterceptResponse>,
        gateway_sender: HtlcSubscriptionSender,
    ) -> Result<(), LightningRpcError> {
        self.spawn_lnv1_htlc_interceptor(task_group, lnd_sender, lnd_rx, gateway_sender.clone())
            .await?;

        self.spawn_lnv2_invoice_subscription(task_group, gateway_sender)
            .await?;

        Ok(())
    }

    async fn cancel_htlc(
        key: CircuitKey,
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
    ) -> Result<(), LightningRpcError> {
        // TODO: Specify a failure code and message
        let response = ForwardHtlcInterceptResponse {
            incoming_circuit_key: Some(key),
            action: ResolveHoldForwardAction::Fail.into(),
            preimage: vec![],
            failure_message: vec![],
            failure_code: FailureCode::TemporaryChannelFailure.into(),
            ..Default::default()
        };
        Self::send_lnd_response(lnd_sender, response).await
    }

    async fn send_lnd_response(
        lnd_sender: mpsc::Sender<ForwardHtlcInterceptResponse>,
        response: ForwardHtlcInterceptResponse,
    ) -> Result<(), LightningRpcError> {
        // TODO: Consider retrying this if the send fails
        lnd_sender.send(response).await.map_err(|send_error| {
            LightningRpcError::FailedToCompleteHtlc {
                failure_reason: format!(
                    "Failed to send ForwardHtlcInterceptResponse to LND {send_error:?}"
                ),
            }
        })
    }

    async fn lookup_payment(
        &self,
        payment_hash: Vec<u8>,
        client: &mut LndClient,
    ) -> Result<Option<String>, LightningRpcError> {
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
                    if let Some(payment) =
                        payments.into_inner().message().await.map_err(|status| {
                            LightningRpcError::FailedPayment {
                                failure_reason: status.message().to_string(),
                            }
                        })?
                    {
                        if payment.status() == PaymentStatus::Succeeded {
                            return Ok(Some(payment.payment_preimage));
                        }

                        let failure_reason = payment.failure_reason();
                        return Err(LightningRpcError::FailedPayment {
                            failure_reason: format!("{failure_reason:?}"),
                        });
                    }
                }
                Err(err) => {
                    // Break if we got a response back from the LND node that indicates the payment
                    // hash was not found.
                    if err.code() == Code::NotFound {
                        return Ok(None);
                    }

                    warn!(
                        target: LOG_LIGHTNING,
                        payment_hash = %PrettyPaymentHash(&payment_hash),
                        err = %err.fmt_compact(),
                        "Could not get the status of payment. Trying again in 5 seconds"
                    );
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Settles a HOLD invoice that is specified by the `payment_hash` with the
    /// given `preimage`. If there is no invoice corresponding to the
    /// `payment_hash`, this function will return an error.
    async fn settle_hold_invoice(
        &self,
        payment_hash: Vec<u8>,
        preimage: Preimage,
    ) -> Result<(), LightningRpcError> {
        let mut client = self.connect().await?;
        let invoice = client
            .invoices()
            .lookup_invoice_v2(LookupInvoiceMsg {
                invoice_ref: Some(InvoiceRef::PaymentHash(payment_hash.clone())),
                lookup_modifier: 0,
            })
            .await
            .map_err(|_| LightningRpcError::FailedToCompleteHtlc {
                failure_reason: "Hold invoice does not exist".to_string(),
            })?
            .into_inner();

        let state = invoice.state();
        if state != InvoiceState::Accepted {
            warn!(
                target: LOG_LIGHTNING,
                state = invoice.state,
                payment_hash = %PrettyPaymentHash(&payment_hash),
                "HOLD invoice state is not accepted",
            );
            return Err(LightningRpcError::FailedToCompleteHtlc {
                failure_reason: "HOLD invoice state is not accepted".to_string(),
            });
        }

        client
            .invoices()
            .settle_invoice(SettleInvoiceMsg {
                preimage: preimage.0.to_vec(),
            })
            .await
            .map_err(|err| {
                warn!(
                    target: LOG_LIGHTNING,
                    err = %err.fmt_compact(),
                    payment_hash = %PrettyPaymentHash(&payment_hash),
                    "Failed to settle HOLD invoice",
                );
                LightningRpcError::FailedToCompleteHtlc {
                    failure_reason: "Failed to settle HOLD invoice".to_string(),
                }
            })?;

        Ok(())
    }

    /// Cancels a HOLD invoice that is specified by the `payment_hash`.
    /// If there is no invoice corresponding to the `payment_hash`, this
    /// function will return an error.
    async fn cancel_hold_invoice(&self, payment_hash: Vec<u8>) -> Result<(), LightningRpcError> {
        let mut client = self.connect().await?;
        let invoice = client
            .invoices()
            .lookup_invoice_v2(LookupInvoiceMsg {
                invoice_ref: Some(InvoiceRef::PaymentHash(payment_hash.clone())),
                lookup_modifier: 0,
            })
            .await
            .map_err(|_| LightningRpcError::FailedToCompleteHtlc {
                failure_reason: "Hold invoice does not exist".to_string(),
            })?
            .into_inner();

        let state = invoice.state();
        if state != InvoiceState::Open {
            warn!(
                target: LOG_LIGHTNING,
                state = %invoice.state,
                payment_hash = %PrettyPaymentHash(&payment_hash),
                "Trying to cancel HOLD invoice that is not OPEN",
            );
        }

        client
            .invoices()
            .cancel_invoice(CancelInvoiceMsg {
                payment_hash: payment_hash.clone(),
            })
            .await
            .map_err(|err| {
                warn!(
                    target: LOG_LIGHTNING,
                    err = %err.fmt_compact(),
                    payment_hash = %PrettyPaymentHash(&payment_hash),
                    "Failed to cancel HOLD invoice",
                );
                LightningRpcError::FailedToCompleteHtlc {
                    failure_reason: "Failed to cancel HOLD invoice".to_string(),
                }
            })?;

        Ok(())
    }
}

impl fmt::Debug for GatewayLndClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LndClient")
    }
}

#[async_trait]
impl ILnRpcClient for GatewayLndClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let mut client = self.connect().await?;
        let info = client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .map_err(|status| LightningRpcError::FailedToGetNodeInfo {
                failure_reason: format!("Failed to get node info {status:?}"),
            })?
            .into_inner();

        let pub_key: PublicKey =
            info.identity_pubkey
                .parse()
                .map_err(|e| LightningRpcError::FailedToGetNodeInfo {
                    failure_reason: format!("Failed to parse public key {e:?}"),
                })?;

        let network = match info
            .chains
            .first()
            .ok_or_else(|| LightningRpcError::FailedToGetNodeInfo {
                failure_reason: "Failed to parse node network".to_string(),
            })?
            .network
            .as_str()
        {
            // LND uses "mainnet", but rust-bitcoin uses "bitcoin".
            // TODO: create a fedimint `Network` type that understands "mainnet"
            "mainnet" => "bitcoin",
            other => other,
        }
        .to_string();

        return Ok(GetNodeInfoResponse {
            pub_key,
            alias: info.alias,
            network,
            block_height: info.block_height,
            synced_to_chain: info.synced_to_chain,
        });
    }

    async fn routehints(
        &self,
        num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        let mut client = self.connect().await?;
        let mut channels = client
            .lightning()
            .list_channels(ListChannelsRequest {
                active_only: true,
                inactive_only: false,
                public_only: false,
                private_only: false,
                peer: vec![],
                peer_alias_lookup: false,
            })
            .await
            .map_err(|status| LightningRpcError::FailedToGetRouteHints {
                failure_reason: format!("Failed to list channels {status:?}"),
            })?
            .into_inner()
            .channels;

        // Take the channels with the largest incoming capacity
        channels.sort_by(|a, b| b.remote_balance.cmp(&a.remote_balance));
        channels.truncate(num_route_hints);

        let mut route_hints: Vec<RouteHint> = vec![];
        for chan in &channels {
            let info = client
                .lightning()
                .get_chan_info(ChanInfoRequest {
                    chan_id: chan.chan_id,
                    ..Default::default()
                })
                .await
                .map_err(|status| LightningRpcError::FailedToGetRouteHints {
                    failure_reason: format!("Failed to get channel info {status:?}"),
                })?
                .into_inner();

            let Some(policy) = info.node1_policy else {
                continue;
            };
            let src_node_id =
                PublicKey::from_str(&chan.remote_pubkey).expect("Failed to parse pubkey");
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
                cltv_expiry_delta: cltv_expiry_delta as u16,
                htlc_minimum_msat,
                htlc_maximum_msat,
            };
            route_hints.push(RouteHint(vec![route_hint_hop]));
        }

        Ok(GetRouteHintsResponse { route_hints })
    }

    async fn pay_private(
        &self,
        invoice: PrunedInvoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let payment_hash = invoice.payment_hash.to_byte_array().to_vec();
        info!(
            target: LOG_LIGHTNING,
            payment_hash = %PrettyPaymentHash(&payment_hash),
            "LND Paying invoice",
        );
        let mut client = self.connect().await?;

        debug!(
            target: LOG_LIGHTNING,
            payment_hash = %PrettyPaymentHash(&payment_hash),
            "pay_private checking if payment for invoice exists"
        );

        // If the payment exists, that means we've already tried to pay the invoice
        let preimage: Vec<u8> = match self
            .lookup_payment(invoice.payment_hash.to_byte_array().to_vec(), &mut client)
            .await?
        {
            Some(preimage) => {
                info!(
                    target: LOG_LIGHTNING,
                    payment_hash = %PrettyPaymentHash(&payment_hash),
                    "LND payment already exists for invoice",
                );
                hex::FromHex::from_hex(preimage.as_str()).map_err(|error| {
                    LightningRpcError::FailedPayment {
                        failure_reason: format!("Failed to convert preimage {error:?}"),
                    }
                })?
            }
            _ => {
                // LND API allows fee limits in the `i64` range, but we use `u64` for
                // max_fee_msat. This means we can only set an enforceable fee limit
                // between 0 and i64::MAX
                let fee_limit_msat: i64 =
                    max_fee
                        .msats
                        .try_into()
                        .map_err(|error| LightningRpcError::FailedPayment {
                            failure_reason: format!(
                                "max_fee_msat exceeds valid LND fee limit ranges {error:?}"
                            ),
                        })?;

                let amt_msat = invoice.amount.msats.try_into().map_err(|error| {
                    LightningRpcError::FailedPayment {
                        failure_reason: format!("amount exceeds valid LND amount ranges {error:?}"),
                    }
                })?;
                let final_cltv_delta =
                    invoice.min_final_cltv_delta.try_into().map_err(|error| {
                        LightningRpcError::FailedPayment {
                            failure_reason: format!(
                                "final cltv delta exceeds valid LND range {error:?}"
                            ),
                        }
                    })?;
                let cltv_limit =
                    max_delay
                        .try_into()
                        .map_err(|error| LightningRpcError::FailedPayment {
                            failure_reason: format!("max delay exceeds valid LND range {error:?}"),
                        })?;

                let dest_features = wire_features_to_lnd_feature_vec(&invoice.destination_features)
                    .map_err(|e| LightningRpcError::FailedPayment {
                        failure_reason: e.to_string(),
                    })?;

                debug!(
                    target: LOG_LIGHTNING,
                    payment_hash = %PrettyPaymentHash(&payment_hash),
                    "LND payment does not exist, will attempt to pay",
                );
                let payments = client
                    .router()
                    .send_payment_v2(SendPaymentRequest {
                        amt_msat,
                        dest: invoice.destination.serialize().to_vec(),
                        dest_features,
                        payment_hash: invoice.payment_hash.to_byte_array().to_vec(),
                        payment_addr: invoice.payment_secret.to_vec(),
                        route_hints: route_hints_to_lnd(&invoice.route_hints),
                        final_cltv_delta,
                        cltv_limit,
                        no_inflight_updates: false,
                        timeout_seconds: LND_PAYMENT_TIMEOUT_SECONDS,
                        fee_limit_msat,
                        ..Default::default()
                    })
                    .await
                    .map_err(|status| {
                        warn!(
                            target: LOG_LIGHTNING,
                            status = %status,
                            payment_hash = %PrettyPaymentHash(&payment_hash),
                            "LND payment request failed",
                        );
                        LightningRpcError::FailedPayment {
                            failure_reason: format!("Failed to make outgoing payment {status:?}"),
                        }
                    })?;

                debug!(
                    target: LOG_LIGHTNING,
                    payment_hash = %PrettyPaymentHash(&payment_hash),
                    "LND payment request sent, waiting for payment status...",
                );
                let mut messages = payments.into_inner();
                loop {
                    match messages.message().await.map_err(|error| {
                        LightningRpcError::FailedPayment {
                            failure_reason: format!("Failed to get payment status {error:?}"),
                        }
                    }) {
                        Ok(Some(payment)) if payment.status() == PaymentStatus::Succeeded => {
                            info!(
                                target: LOG_LIGHTNING,
                                payment_hash = %PrettyPaymentHash(&payment_hash),
                                "LND payment succeeded for invoice",
                            );
                            break hex::FromHex::from_hex(payment.payment_preimage.as_str())
                                .map_err(|error| LightningRpcError::FailedPayment {
                                    failure_reason: format!("Failed to convert preimage {error:?}"),
                                })?;
                        }
                        Ok(Some(payment)) if payment.status() == PaymentStatus::InFlight => {
                            debug!(
                                target: LOG_LIGHTNING,
                                payment_hash = %PrettyPaymentHash(&payment_hash),
                                "LND payment is inflight",
                            );
                            continue;
                        }
                        Ok(Some(payment)) => {
                            warn!(
                                target: LOG_LIGHTNING,
                                payment_hash = %PrettyPaymentHash(&payment_hash),
                                status = %payment.status,
                                "LND payment failed",
                            );
                            let failure_reason = payment.failure_reason();
                            return Err(LightningRpcError::FailedPayment {
                                failure_reason: format!("{failure_reason:?}"),
                            });
                        }
                        Ok(None) => {
                            warn!(
                                target: LOG_LIGHTNING,
                                payment_hash = %PrettyPaymentHash(&payment_hash),
                                "LND payment failed with no payment status",
                            );
                            return Err(LightningRpcError::FailedPayment {
                                failure_reason: format!(
                                    "Failed to get payment status for payment hash {:?}",
                                    invoice.payment_hash
                                ),
                            });
                        }
                        Err(err) => {
                            warn!(
                                target: LOG_LIGHTNING,
                                payment_hash = %PrettyPaymentHash(&payment_hash),
                                err = %err.fmt_compact(),
                                "LND payment failed",
                            );
                            return Err(err);
                        }
                    }
                }
            }
        };
        Ok(PayInvoiceResponse {
            preimage: Preimage(preimage.try_into().expect("Failed to create preimage")),
        })
    }

    /// Returns true if the lightning backend supports payments without full
    /// invoices
    fn supports_private_payments(&self) -> bool {
        true
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        const CHANNEL_SIZE: usize = 100;

        // Channel to send intercepted htlc to the gateway for processing
        let (gateway_sender, gateway_receiver) =
            mpsc::channel::<InterceptPaymentRequest>(CHANNEL_SIZE);

        let (lnd_sender, lnd_rx) = mpsc::channel::<ForwardHtlcInterceptResponse>(CHANNEL_SIZE);

        self.spawn_interceptor(
            task_group,
            lnd_sender.clone(),
            lnd_rx,
            gateway_sender.clone(),
        )
        .await?;
        let new_client = Arc::new(Self {
            address: self.address.clone(),
            tls_cert: self.tls_cert.clone(),
            macaroon: self.macaroon.clone(),
            lnd_sender: Some(lnd_sender.clone()),
        });
        Ok((Box::pin(ReceiverStream::new(gateway_receiver)), new_client))
    }

    async fn complete_htlc(&self, htlc: InterceptPaymentResponse) -> Result<(), LightningRpcError> {
        let InterceptPaymentResponse {
            action,
            payment_hash,
            incoming_chan_id,
            htlc_id,
        } = htlc;

        let (action, preimage) = match action {
            PaymentAction::Settle(preimage) => (ResolveHoldForwardAction::Settle, preimage),
            PaymentAction::Cancel => (ResolveHoldForwardAction::Fail, Preimage([0; 32])),
            PaymentAction::Forward => (ResolveHoldForwardAction::Resume, Preimage([0; 32])),
        };

        // First check if this completion request corresponds to a HOLD LNv2 invoice
        match action {
            ResolveHoldForwardAction::Settle => {
                if let Ok(()) = self
                    .settle_hold_invoice(payment_hash.to_byte_array().to_vec(), preimage.clone())
                    .await
                {
                    info!(target: LOG_LIGHTNING, payment_hash = %PrettyPaymentHash(&payment_hash.consensus_encode_to_vec()), "Successfully settled HOLD invoice");
                    return Ok(());
                }
            }
            _ => {
                if let Ok(()) = self
                    .cancel_hold_invoice(payment_hash.to_byte_array().to_vec())
                    .await
                {
                    info!(target: LOG_LIGHTNING, payment_hash = %PrettyPaymentHash(&payment_hash.consensus_encode_to_vec()), "Successfully canceled HOLD invoice");
                    return Ok(());
                }
            }
        }

        // If we can't settle/cancel the payment via LNv2, try LNv1
        if let Some(lnd_sender) = self.lnd_sender.clone() {
            let response = ForwardHtlcInterceptResponse {
                incoming_circuit_key: Some(CircuitKey {
                    chan_id: incoming_chan_id,
                    htlc_id,
                }),
                action: action.into(),
                preimage: preimage.0.to_vec(),
                failure_message: vec![],
                failure_code: FailureCode::TemporaryChannelFailure.into(),
                ..Default::default()
            };

            Self::send_lnd_response(lnd_sender, response).await?;
            return Ok(());
        }

        crit!("Gatewayd has not started to route HTLCs");
        Err(LightningRpcError::FailedToCompleteHtlc {
            failure_reason: "Gatewayd has not started to route HTLCs".to_string(),
        })
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let mut client = self.connect().await?;
        let description = create_invoice_request
            .description
            .unwrap_or(InvoiceDescription::Direct(String::new()));

        if create_invoice_request.payment_hash.is_none() {
            let invoice = match description {
                InvoiceDescription::Direct(description) => Invoice {
                    memo: description,
                    value_msat: create_invoice_request.amount_msat as i64,
                    expiry: i64::from(create_invoice_request.expiry_secs),
                    ..Default::default()
                },
                InvoiceDescription::Hash(desc_hash) => Invoice {
                    description_hash: desc_hash.to_byte_array().to_vec(),
                    value_msat: create_invoice_request.amount_msat as i64,
                    expiry: i64::from(create_invoice_request.expiry_secs),
                    ..Default::default()
                },
            };

            let add_invoice_response =
                client.lightning().add_invoice(invoice).await.map_err(|e| {
                    LightningRpcError::FailedToGetInvoice {
                        failure_reason: e.to_string(),
                    }
                })?;

            let invoice = add_invoice_response.into_inner().payment_request;
            Ok(CreateInvoiceResponse { invoice })
        } else {
            let payment_hash = create_invoice_request
                .payment_hash
                .expect("Already checked payment hash")
                .to_byte_array()
                .to_vec();
            let hold_invoice_request = match description {
                InvoiceDescription::Direct(description) => AddHoldInvoiceRequest {
                    memo: description,
                    hash: payment_hash.clone(),
                    value_msat: create_invoice_request.amount_msat as i64,
                    expiry: i64::from(create_invoice_request.expiry_secs),
                    ..Default::default()
                },
                InvoiceDescription::Hash(desc_hash) => AddHoldInvoiceRequest {
                    description_hash: desc_hash.to_byte_array().to_vec(),
                    hash: payment_hash.clone(),
                    value_msat: create_invoice_request.amount_msat as i64,
                    expiry: i64::from(create_invoice_request.expiry_secs),
                    ..Default::default()
                },
            };

            let hold_invoice_response = client
                .invoices()
                .add_hold_invoice(hold_invoice_request)
                .await
                .map_err(|e| LightningRpcError::FailedToGetInvoice {
                    failure_reason: e.to_string(),
                })?;

            let invoice = hold_invoice_response.into_inner().payment_request;
            Ok(CreateInvoiceResponse { invoice })
        }
    }

    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError> {
        let mut client = self.connect().await?;

        match client
            .wallet()
            .next_addr(AddrRequest {
                account: String::new(), // Default wallet account.
                r#type: 4,              // Taproot address.
                change: false,
            })
            .await
        {
            Ok(response) => Ok(GetLnOnchainAddressResponse {
                address: response.into_inner().addr,
            }),
            Err(e) => Err(LightningRpcError::FailedToGetLnOnchainAddress {
                failure_reason: format!("Failed to get funding address {e:?}"),
            }),
        }
    }

    async fn send_onchain(
        &self,
        SendOnchainRequest {
            address,
            amount,
            fee_rate_sats_per_vbyte,
        }: SendOnchainRequest,
    ) -> Result<SendOnchainResponse, LightningRpcError> {
        #[allow(deprecated)]
        let request = match amount {
            BitcoinAmountOrAll::All => SendCoinsRequest {
                addr: address.assume_checked().to_string(),
                amount: 0,
                target_conf: 0,
                sat_per_vbyte: fee_rate_sats_per_vbyte,
                sat_per_byte: 0,
                send_all: true,
                label: String::new(),
                min_confs: 0,
                spend_unconfirmed: true,
                ..Default::default()
            },
            BitcoinAmountOrAll::Amount(amount) => SendCoinsRequest {
                addr: address.assume_checked().to_string(),
                amount: amount.to_sat() as i64,
                target_conf: 0,
                sat_per_vbyte: fee_rate_sats_per_vbyte,
                sat_per_byte: 0,
                send_all: false,
                label: String::new(),
                min_confs: 0,
                spend_unconfirmed: true,
                ..Default::default()
            },
        };

        match self.connect().await?.lightning().send_coins(request).await {
            Ok(res) => Ok(SendOnchainResponse {
                txid: res.into_inner().txid,
            }),
            Err(e) => Err(LightningRpcError::FailedToWithdrawOnchain {
                failure_reason: format!("Failed to withdraw funds on-chain {e:?}"),
            }),
        }
    }

    async fn open_channel(
        &self,
        crate::OpenChannelRequest {
            pubkey,
            host,
            channel_size_sats,
            push_amount_sats,
        }: crate::OpenChannelRequest,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        let mut client = self.connect().await?;

        let peers = client
            .lightning()
            .list_peers(ListPeersRequest { latest_error: true })
            .await
            .map_err(|e| LightningRpcError::FailedToConnectToPeer {
                failure_reason: format!("Could not list peers: {e:?}"),
            })?
            .into_inner();

        // Connect to the peer first if we are not connected already
        if !peers.peers.into_iter().any(|peer| {
            PublicKey::from_str(&peer.pub_key).expect("could not parse public key") == pubkey
        }) {
            client
                .lightning()
                .connect_peer(ConnectPeerRequest {
                    addr: Some(LightningAddress {
                        pubkey: pubkey.to_string(),
                        host,
                    }),
                    perm: false,
                    timeout: 10,
                })
                .await
                .map_err(|e| LightningRpcError::FailedToConnectToPeer {
                    failure_reason: format!("Failed to connect to peer {e:?}"),
                })?;
        }

        // Open the channel
        match client
            .lightning()
            .open_channel_sync(OpenChannelRequest {
                node_pubkey: pubkey.serialize().to_vec(),
                local_funding_amount: channel_size_sats.try_into().expect("u64 -> i64"),
                push_sat: push_amount_sats.try_into().expect("u64 -> i64"),
                ..Default::default()
            })
            .await
        {
            Ok(res) => Ok(OpenChannelResponse {
                funding_txid: match res.into_inner().funding_txid {
                    Some(txid) => match txid {
                        FundingTxid::FundingTxidBytes(mut bytes) => {
                            bytes.reverse();
                            hex::encode(bytes)
                        }
                        FundingTxid::FundingTxidStr(str) => str,
                    },
                    None => String::new(),
                },
            }),
            Err(e) => Err(LightningRpcError::FailedToOpenChannel {
                failure_reason: format!("Failed to open channel {e:?}"),
            }),
        }
    }

    async fn close_channels_with_peer(
        &self,
        CloseChannelsWithPeerRequest {
            pubkey,
            force,
            sats_per_vbyte,
        }: CloseChannelsWithPeerRequest,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        let mut client = self.connect().await?;

        let channels_with_peer = client
            .lightning()
            .list_channels(ListChannelsRequest {
                active_only: false,
                inactive_only: false,
                public_only: false,
                private_only: false,
                peer: pubkey.serialize().to_vec(),
                peer_alias_lookup: false,
            })
            .await
            .map_err(|e| LightningRpcError::FailedToCloseChannelsWithPeer {
                failure_reason: format!("Failed to list channels {e:?}"),
            })?
            .into_inner()
            .channels;

        for channel in &channels_with_peer {
            let channel_point =
                bitcoin::OutPoint::from_str(&channel.channel_point).map_err(|e| {
                    LightningRpcError::FailedToCloseChannelsWithPeer {
                        failure_reason: format!("Failed to parse channel point {e:?}"),
                    }
                })?;

            if force {
                client
                    .lightning()
                    .close_channel(CloseChannelRequest {
                        channel_point: Some(ChannelPoint {
                            funding_txid: Some(
                                tonic_lnd::lnrpc::channel_point::FundingTxid::FundingTxidBytes(
                                    <bitcoin::Txid as AsRef<[u8]>>::as_ref(&channel_point.txid)
                                        .to_vec(),
                                ),
                            ),
                            output_index: channel_point.vout,
                        }),
                        force,
                        ..Default::default()
                    })
                    .await
                    .map_err(|e| LightningRpcError::FailedToCloseChannelsWithPeer {
                        failure_reason: format!("Failed to close channel {e:?}"),
                    })?;
            } else {
                client
                    .lightning()
                    .close_channel(CloseChannelRequest {
                        channel_point: Some(ChannelPoint {
                            funding_txid: Some(
                                tonic_lnd::lnrpc::channel_point::FundingTxid::FundingTxidBytes(
                                    <bitcoin::Txid as AsRef<[u8]>>::as_ref(&channel_point.txid)
                                        .to_vec(),
                                ),
                            ),
                            output_index: channel_point.vout,
                        }),
                        force,
                        sat_per_vbyte: sats_per_vbyte.unwrap_or_default(),
                        ..Default::default()
                    })
                    .await
                    .map_err(|e| LightningRpcError::FailedToCloseChannelsWithPeer {
                        failure_reason: format!("Failed to close channel {e:?}"),
                    })?;
            }
        }

        Ok(CloseChannelsWithPeerResponse {
            num_channels_closed: channels_with_peer.len() as u32,
        })
    }

    async fn list_channels(&self) -> Result<ListChannelsResponse, LightningRpcError> {
        let mut client = self.connect().await?;

        match client
            .lightning()
            .list_channels(ListChannelsRequest {
                active_only: false,
                inactive_only: false,
                public_only: false,
                private_only: false,
                peer: vec![],
                peer_alias_lookup: true,
            })
            .await
        {
            Ok(response) => Ok(ListChannelsResponse {
                channels: response
                    .into_inner()
                    .channels
                    .into_iter()
                    .map(|channel| {
                        let channel_size_sats = channel.capacity.try_into().expect("i64 -> u64");

                        let local_balance_sats: u64 =
                            channel.local_balance.try_into().expect("i64 -> u64");
                        let local_channel_reserve_sats: u64 = match channel.local_constraints {
                            Some(constraints) => constraints.chan_reserve_sat,
                            None => 0,
                        };

                        let outbound_liquidity_sats =
                            local_balance_sats.saturating_sub(local_channel_reserve_sats);

                        let remote_balance_sats: u64 =
                            channel.remote_balance.try_into().expect("i64 -> u64");
                        let remote_channel_reserve_sats: u64 = match channel.remote_constraints {
                            Some(constraints) => constraints.chan_reserve_sat,
                            None => 0,
                        };

                        let inbound_liquidity_sats =
                            remote_balance_sats.saturating_sub(remote_channel_reserve_sats);

                        let funding_outpoint = OutPoint::from_str(&channel.channel_point).ok();

                        ChannelInfo {
                            remote_pubkey: PublicKey::from_str(&channel.remote_pubkey)
                                .expect("Lightning node returned invalid remote channel pubkey"),
                            channel_size_sats,
                            outbound_liquidity_sats,
                            inbound_liquidity_sats,
                            is_active: channel.active,
                            funding_outpoint,
                        }
                    })
                    .collect(),
            }),
            Err(e) => Err(LightningRpcError::FailedToListChannels {
                failure_reason: format!("Failed to list active channels {e:?}"),
            }),
        }
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        let mut client = self.connect().await?;

        let wallet_balance_response = client
            .lightning()
            .wallet_balance(WalletBalanceRequest {
                ..Default::default()
            })
            .await
            .map_err(|e| LightningRpcError::FailedToGetBalances {
                failure_reason: format!("Failed to get on-chain balance {e:?}"),
            })?
            .into_inner();

        let channel_balance_response = client
            .lightning()
            .channel_balance(ChannelBalanceRequest {})
            .await
            .map_err(|e| LightningRpcError::FailedToGetBalances {
                failure_reason: format!("Failed to get lightning balance {e:?}"),
            })?
            .into_inner();
        let total_outbound = channel_balance_response.local_balance.unwrap_or_default();
        let unsettled_outbound = channel_balance_response
            .unsettled_local_balance
            .unwrap_or_default();
        let pending_outbound = channel_balance_response
            .pending_open_local_balance
            .unwrap_or_default();
        let lightning_balance_msats = total_outbound
            .msat
            .saturating_sub(unsettled_outbound.msat)
            .saturating_sub(pending_outbound.msat);

        let total_inbound = channel_balance_response.remote_balance.unwrap_or_default();
        let unsettled_inbound = channel_balance_response
            .unsettled_remote_balance
            .unwrap_or_default();
        let pending_inbound = channel_balance_response
            .pending_open_remote_balance
            .unwrap_or_default();
        let inbound_lightning_liquidity_msats = total_inbound
            .msat
            .saturating_sub(unsettled_inbound.msat)
            .saturating_sub(pending_inbound.msat);

        Ok(GetBalancesResponse {
            onchain_balance_sats: (wallet_balance_response.total_balance
                + wallet_balance_response.reserved_balance_anchor_chan)
                as u64,
            lightning_balance_msats,
            inbound_lightning_liquidity_msats,
        })
    }

    async fn get_invoice(
        &self,
        get_invoice_request: GetInvoiceRequest,
    ) -> Result<Option<GetInvoiceResponse>, LightningRpcError> {
        let mut client = self.connect().await?;
        let invoice = client
            .invoices()
            .lookup_invoice_v2(LookupInvoiceMsg {
                invoice_ref: Some(InvoiceRef::PaymentHash(
                    get_invoice_request.payment_hash.consensus_encode_to_vec(),
                )),
                ..Default::default()
            })
            .await;
        let invoice = match invoice {
            Ok(invoice) => invoice.into_inner(),
            Err(_) => return Ok(None),
        };
        let preimage: [u8; 32] = invoice
            .clone()
            .r_preimage
            .try_into()
            .expect("Could not convert preimage");
        let status = match &invoice.state() {
            InvoiceState::Settled => fedimint_gateway_common::PaymentStatus::Succeeded,
            InvoiceState::Canceled => fedimint_gateway_common::PaymentStatus::Failed,
            _ => fedimint_gateway_common::PaymentStatus::Pending,
        };

        Ok(Some(GetInvoiceResponse {
            preimage: Some(preimage.consensus_encode_to_hex()),
            payment_hash: Some(
                sha256::Hash::from_slice(&invoice.r_hash).expect("Could not convert payment hash"),
            ),
            amount: Amount::from_msats(invoice.value_msat as u64),
            created_at: UNIX_EPOCH + Duration::from_secs(invoice.creation_date as u64),
            status,
        }))
    }

    async fn list_transactions(
        &self,
        start_secs: u64,
        end_secs: u64,
    ) -> Result<ListTransactionsResponse, LightningRpcError> {
        let mut client = self.connect().await?;
        let payments = client
            .lightning()
            .list_payments(ListPaymentsRequest {
                // On higher versions on LND, we can filter on the time range directly in the query
                ..Default::default()
            })
            .await
            .map_err(|err| LightningRpcError::FailedToListTransactions {
                failure_reason: err.to_string(),
            })?
            .into_inner();

        let mut payments = payments
            .payments
            .iter()
            .filter_map(|payment| {
                let timestamp_secs = (payment.creation_time_ns / 1_000_000_000) as u64;
                if timestamp_secs < start_secs || timestamp_secs >= end_secs {
                    return None;
                }
                let payment_hash = sha256::Hash::from_str(&payment.payment_hash).ok();
                let preimage = (!payment.payment_preimage.is_empty())
                    .then_some(payment.payment_preimage.clone());
                let status = match &payment.status() {
                    PaymentStatus::Succeeded => fedimint_gateway_common::PaymentStatus::Succeeded,
                    PaymentStatus::Failed => fedimint_gateway_common::PaymentStatus::Failed,
                    _ => fedimint_gateway_common::PaymentStatus::Pending,
                };
                Some(PaymentDetails {
                    payment_hash,
                    preimage,
                    payment_kind: PaymentKind::Bolt11,
                    amount: Amount::from_msats(payment.value_msat as u64),
                    direction: PaymentDirection::Outbound,
                    status,
                    timestamp_secs,
                })
            })
            .collect::<Vec<_>>();

        let invoices = client
            .lightning()
            .list_invoices(ListInvoiceRequest {
                pending_only: false,
                // On higher versions on LND, we can filter on the time range directly in the query
                ..Default::default()
            })
            .await
            .map_err(|err| LightningRpcError::FailedToListTransactions {
                failure_reason: err.to_string(),
            })?
            .into_inner();

        let mut incoming_payments = invoices
            .invoices
            .iter()
            .filter_map(|invoice| {
                let timestamp_secs = invoice.settle_date as u64;
                if timestamp_secs < start_secs || timestamp_secs >= end_secs {
                    return None;
                }
                let status = match &invoice.state() {
                    InvoiceState::Settled => fedimint_gateway_common::PaymentStatus::Succeeded,
                    InvoiceState::Canceled => fedimint_gateway_common::PaymentStatus::Failed,
                    _ => return None,
                };
                let preimage = (!invoice.r_preimage.is_empty())
                    .then_some(invoice.r_preimage.encode_hex::<String>());
                Some(PaymentDetails {
                    payment_hash: Some(
                        sha256::Hash::from_slice(&invoice.r_hash)
                            .expect("Could not convert payment hash"),
                    ),
                    preimage,
                    payment_kind: PaymentKind::Bolt11,
                    amount: Amount::from_msats(invoice.value_msat as u64),
                    direction: PaymentDirection::Inbound,
                    status,
                    timestamp_secs,
                })
            })
            .collect::<Vec<_>>();

        payments.append(&mut incoming_payments);
        payments.sort_by_key(|p| p.timestamp_secs);

        Ok(ListTransactionsResponse {
            transactions: payments,
        })
    }

    fn create_offer(
        &self,
        _amount_msat: Option<Amount>,
        _description: Option<String>,
        _expiry_secs: Option<u32>,
        _quantity: Option<u64>,
    ) -> Result<String, LightningRpcError> {
        Err(LightningRpcError::Bolt12Error {
            failure_reason: "LND Does not support Bolt12".to_string(),
        })
    }

    async fn pay_offer(
        &self,
        _offer: String,
        _quantity: Option<u64>,
        _amount: Option<Amount>,
        _payer_note: Option<String>,
    ) -> Result<Preimage, LightningRpcError> {
        Err(LightningRpcError::Bolt12Error {
            failure_reason: "LND Does not support Bolt12".to_string(),
        })
    }

    fn sync_wallet(&self) -> Result<(), LightningRpcError> {
        // There is nothing explicit needed to do for syncing an LND node
        Ok(())
    }
}

fn route_hints_to_lnd(
    route_hints: &[fedimint_ln_common::route_hints::RouteHint],
) -> Vec<tonic_lnd::lnrpc::RouteHint> {
    route_hints
        .iter()
        .map(|hint| tonic_lnd::lnrpc::RouteHint {
            hop_hints: hint
                .0
                .iter()
                .map(|hop| tonic_lnd::lnrpc::HopHint {
                    node_id: hop.src_node_id.serialize().encode_hex(),
                    chan_id: hop.short_channel_id,
                    fee_base_msat: hop.base_msat,
                    fee_proportional_millionths: hop.proportional_millionths,
                    cltv_expiry_delta: u32::from(hop.cltv_expiry_delta),
                })
                .collect(),
        })
        .collect()
}

fn wire_features_to_lnd_feature_vec(features_wire_encoded: &[u8]) -> anyhow::Result<Vec<i32>> {
    ensure!(
        features_wire_encoded.len() <= 1_000,
        "Will not process feature bit vectors larger than 1000 byte"
    );

    let lnd_features = features_wire_encoded
        .iter()
        .rev()
        .enumerate()
        .flat_map(|(byte_idx, &feature_byte)| {
            (0..8).filter_map(move |bit_idx| {
                if (feature_byte & (1u8 << bit_idx)) != 0 {
                    Some(
                        i32::try_from(byte_idx * 8 + bit_idx)
                            .expect("Index will never exceed i32::MAX for feature vectors <8MB"),
                    )
                } else {
                    None
                }
            })
        })
        .collect::<Vec<_>>();

    Ok(lnd_features)
}

/// Utility struct for logging payment hashes. Useful for debugging.
struct PrettyPaymentHash<'a>(&'a Vec<u8>);

impl Display for PrettyPaymentHash<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "payment_hash={}", self.0.encode_hex::<String>())
    }
}

#[cfg(test)]
mod tests;
