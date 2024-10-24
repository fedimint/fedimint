use std::collections::BTreeSet;
use std::fmt::{self, Display};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::ensure;
use async_trait::async_trait;
use bitcoin30::Address;
use bitcoin_hashes::{sha256, Hash};
use fedimint_core::db::Database;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::{secp256k1, Amount, BitcoinAmountOrAll};
use fedimint_ln_common::PrunedInvoice;
use fedimint_lnv2_common::contracts::PaymentImage;
use hex::ToHex;
use secp256k1::PublicKey;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
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
    ListInvoiceRequest, OpenChannelRequest, SendCoinsRequest, WalletBalanceRequest,
};
use tonic_lnd::routerrpc::{
    CircuitKey, ForwardHtlcInterceptResponse, ResolveHoldForwardAction, SendPaymentRequest,
    TrackPaymentRequest,
};
use tonic_lnd::tonic::Code;
use tonic_lnd::walletrpc::AddrRequest;
use tonic_lnd::{connect, Client as LndClient};
use tracing::{debug, error, info, trace, warn};

use super::{ChannelInfo, ILnRpcClient, LightningRpcError, RouteHtlcStream, MAX_LIGHTNING_RETRIES};
use crate::db::GatewayDbtxNcExt;
use crate::gateway_lnrpc::create_invoice_request::Description;
use crate::gateway_lnrpc::get_route_hints_response::{RouteHint, RouteHintHop};
use crate::gateway_lnrpc::intercept_htlc_response::{Action, Cancel, Forward, Settle};
use crate::gateway_lnrpc::{
    CloseChannelsWithPeerResponse, CreateInvoiceRequest, CreateInvoiceResponse, EmptyResponse,
    GetBalancesResponse, GetLnOnchainAddressResponse, GetNodeInfoResponse, GetRouteHintsResponse,
    InterceptHtlcRequest, InterceptHtlcResponse, OpenChannelResponse, PayInvoiceResponse,
    WithdrawOnchainResponse,
};

type HtlcSubscriptionSender = mpsc::Sender<Result<InterceptHtlcRequest, Status>>;

const LND_PAYMENT_TIMEOUT_SECONDS: i32 = 180;

#[derive(Clone)]
pub struct GatewayLndClient {
    /// LND client
    address: String,
    tls_cert: String,
    macaroon: String,
    lnd_sender: Option<mpsc::Sender<ForwardHtlcInterceptResponse>>,
    gateway_db: Database,
    payment_hashes: Arc<RwLock<BTreeSet<Vec<u8>>>>,
}

impl GatewayLndClient {
    pub fn new(
        address: String,
        tls_cert: String,
        macaroon: String,
        lnd_sender: Option<mpsc::Sender<ForwardHtlcInterceptResponse>>,
        gateway_db: Database,
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
            gateway_db,
            payment_hashes: Arc::new(RwLock::new(BTreeSet::new())),
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
                Err(e) => {
                    tracing::debug!("Couldn't connect to LND, retrying in 1 second... {e:?}");
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
                        Err(e) => {
                            error!(?e, "Failed to subscribe to hold invoice updates");
                            return;
                        }
                    }
                },
                () = handle.make_shutdown_rx() => {
                    info!("LND HOLD Invoice Subscription received shutdown signal");
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
                        Err(e) => {
                            error!(?e, "Error received over hold invoice update stream");
                            None
                        }
                    }
                }
            } {
                debug!(
                    ?hold,
                    "LND HOLD Invoice Update {}",
                    PrettyPaymentHash(&r_hash)
                );

                if hold.state() == InvoiceState::Accepted {
                    let intercept = InterceptHtlcRequest {
                        payment_hash: hold.r_hash.clone(),
                        incoming_amount_msat: hold.amt_paid_msat as u64,
                        // The rest of the fields are not used in LNv2 and can be removed once LNv1
                        // support is over
                        outgoing_amount_msat: hold.amt_paid_msat as u64,
                        incoming_expiry: hold.expiry as u32,
                        short_channel_id: Some(0),
                        incoming_chan_id: 0,
                        htlc_id: 0,
                    };

                    match gateway_sender.send(Ok(intercept)).await {
                        Ok(()) => {}
                        Err(e) => {
                            error!(
                                ?e,
                                "Hold Invoice Subscription failed to send Intercept to gateway"
                            );
                            let _ = self_copy.cancel_hold_invoice(hold.r_hash).await;
                        }
                    }
                }
            }
        });

        // Invoice monitor task has already spawned, we can safely remove it from the
        // set
        self.payment_hashes.write().await.remove(&payment_hash);

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
            })
            .await
            .map_err(|status| {
                error!(?status, "Failed to list all invoices");
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
                        Err(e) => {
                            error!(?e, "Failed to subscribe to all invoice updates");
                            return;
                        }
                    }
                },
                () = handle.make_shutdown_rx() => {
                    info!("LND Invoice Subscription received shutdown signal");
                    return;
                }
            };

            info!("LND Invoice Subscription: starting to process invoice updates");
            while let Some(invoice) = tokio::select! {
                () = handle.make_shutdown_rx() => {
                    info!("LND Invoice Subscription task received shutdown signal");
                    None
                }
                invoice_update = invoice_stream.message() => {
                    match invoice_update {
                        Ok(invoice) => invoice,
                        Err(e) => {
                            error!(?e, "Error received over invoice update stream");
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

                let created_payment_hash = self_copy
                    .payment_hashes
                    .read()
                    .await
                    .contains(&payment_hash);
                let db_contains_payment_hash = self_copy
                    .gateway_db
                    .begin_transaction_nc()
                    .await
                    .load_registered_incoming_contract(PaymentImage::Hash(
                        sha256::Hash::from_byte_array(
                            payment_hash
                                .clone()
                                .try_into()
                                .expect("Malformatted payment hash"),
                        ),
                    ))
                    .await
                    .is_some();
                let contains_payment_hash = created_payment_hash || db_contains_payment_hash;

                debug!(
                    ?invoice,
                    ?created_payment_hash,
                    ?db_contains_payment_hash,
                    "LND Invoice Update {}",
                    PrettyPaymentHash(&payment_hash),
                );

                if contains_payment_hash
                    && invoice.r_preimage.is_empty()
                    && invoice.state() == InvoiceState::Open
                {
                    info!(
                        "Monitoring new LNv2 invoice with {}",
                        PrettyPaymentHash(&payment_hash)
                    );
                    if let Err(e) = self_copy
                        .spawn_lnv2_hold_invoice_subscription(
                            &hold_group,
                            gateway_sender.clone(),
                            payment_hash.clone(),
                        )
                        .await
                    {
                        error!(
                            ?e,
                            "Failed to spawn HOLD invoice subscription task {}",
                            PrettyPaymentHash(&payment_hash),
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
                                error!("Failed to establish htlc stream");
                                let e = LightningRpcError::FailedToGetRouteHints {
                                    failure_reason: format!("Failed to subscribe to LND htlc stream {e:?}"),
                                };
                                debug!("Error: {e}");
                                return;
                            }
                        }
                    },
                    () = handle.make_shutdown_rx() => {
                        info!("LND HTLC Subscription received shutdown signal while trying to intercept HTLC stream, exiting...");
                        return;
                    }
                };

                debug!("LND HTLC Subscription: starting to process stream");
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
                        info!("LND HTLC Subscription task received shutdown signal");
                        None
                    }
                    htlc_message = htlc_stream.message() => {
                        match htlc_message {
                            Ok(htlc) => htlc,
                            Err(e) => {
                                error!(?e, "Error received over HTLC stream");
                                None
                            }
                    }}
                } {
                    trace!("LND HTLC Subscription: handling htlc {htlc:?}");

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
                        short_channel_id: Some(htlc.outgoing_requested_chan_id),
                        incoming_chan_id: incoming_circuit_key.chan_id,
                        htlc_id: incoming_circuit_key.htlc_id,
                    };

                    match gateway_sender.send(Ok(intercept)).await {
                        Ok(()) => {}
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

    /// Settles a HOLD invoice that is specified by the `payment_hash` with the
    /// given `preimage`. If there is no invoice corresponding to the
    /// `payment_hash`, this function will return an error.
    async fn settle_hold_invoice(
        &self,
        payment_hash: Vec<u8>,
        preimage: Vec<u8>,
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
            error!(
                ?state,
                "HOLD invoice state is not accepted {}",
                PrettyPaymentHash(&payment_hash)
            );
            return Err(LightningRpcError::FailedToCompleteHtlc {
                failure_reason: "HOLD invoice state is not accepted".to_string(),
            });
        }

        client
            .invoices()
            .settle_invoice(SettleInvoiceMsg { preimage })
            .await
            .map_err(|e| {
                error!(
                    ?e,
                    "Failed to settle HOLD invoice {}",
                    PrettyPaymentHash(&payment_hash)
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
            warn!(?state, "Trying to cancel HOLD invoice with {} that is not OPEN, gateway likely encountered an issue", PrettyPaymentHash(&payment_hash));
        }

        client
            .invoices()
            .cancel_invoice(CancelInvoiceMsg {
                payment_hash: payment_hash.clone(),
            })
            .await
            .map_err(|e| {
                error!(
                    ?e,
                    "Failed to cancel HOLD invoice {}",
                    PrettyPaymentHash(&payment_hash)
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
            pub_key: pub_key.serialize().to_vec(),
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
                })
                .await
                .map_err(|status| LightningRpcError::FailedToGetRouteHints {
                    failure_reason: format!("Failed to get channel info {status:?}"),
                })?
                .into_inner();

            let Some(policy) = info.node1_policy.clone() else {
                continue;
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

    async fn pay_private(
        &self,
        invoice: PrunedInvoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let payment_hash = invoice.payment_hash.to_byte_array().to_vec();
        info!(
            "LND Paying invoice with {}",
            PrettyPaymentHash(&payment_hash)
        );
        let mut client = self.connect().await?;

        debug!(
            ?invoice,
            "pay_private checking if payment for invoice exists"
        );

        // If the payment exists, that means we've already tried to pay the invoice
        let preimage: Vec<u8> = if let Some(preimage) = self
            .lookup_payment(invoice.payment_hash.to_byte_array().to_vec(), &mut client)
            .await?
        {
            info!(
                "LND payment already exists for invoice with {}",
                PrettyPaymentHash(&payment_hash)
            );
            hex::FromHex::from_hex(preimage.as_str()).map_err(|error| {
                LightningRpcError::FailedPayment {
                    failure_reason: format!("Failed to convert preimage {error:?}"),
                }
            })?
        } else {
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
            let final_cltv_delta = invoice.min_final_cltv_delta.try_into().map_err(|error| {
                LightningRpcError::FailedPayment {
                    failure_reason: format!("final cltv delta exceeds valid LND range {error:?}"),
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
                "LND payment does not exist for invoice with {}, will attempt to pay",
                PrettyPaymentHash(&payment_hash)
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
                    error!(
                        "LND payment request failed for invoice with {} with {status:?}",
                        PrettyPaymentHash(&payment_hash)
                    );
                    LightningRpcError::FailedPayment {
                        failure_reason: format!("Failed to make outgoing payment {status:?}"),
                    }
                })?;

            debug!(
                "LND payment request sent for invoice with {}, waiting for payment status...",
                PrettyPaymentHash(&payment_hash),
            );
            let mut messages = payments.into_inner();
            loop {
                match messages
                    .message()
                    .await
                    .map_err(|error| LightningRpcError::FailedPayment {
                        failure_reason: format!("Failed to get payment status {error:?}"),
                    }) {
                    Ok(Some(payment)) if payment.status() == PaymentStatus::Succeeded => {
                        info!(
                            "LND payment succeeded for invoice with {}",
                            PrettyPaymentHash(&payment_hash)
                        );
                        break hex::FromHex::from_hex(payment.payment_preimage.as_str()).map_err(
                            |error| LightningRpcError::FailedPayment {
                                failure_reason: format!("Failed to convert preimage {error:?}"),
                            },
                        )?;
                    }
                    Ok(Some(payment)) if payment.status() == PaymentStatus::InFlight => {
                        debug!(
                            "LND payment for invoice with {} is inflight",
                            PrettyPaymentHash(&payment_hash)
                        );
                        continue;
                    }
                    Ok(Some(payment)) => {
                        error!(
                            "LND payment failed for invoice with {} with {payment:?}",
                            PrettyPaymentHash(&payment_hash)
                        );
                        let failure_reason = payment.failure_reason();
                        return Err(LightningRpcError::FailedPayment {
                            failure_reason: format!("{failure_reason:?}"),
                        });
                    }
                    Ok(None) => {
                        error!(
                            "LND payment failed for invoice with {} with no payment status",
                            PrettyPaymentHash(&payment_hash)
                        );
                        return Err(LightningRpcError::FailedPayment {
                            failure_reason: format!(
                                "Failed to get payment status for payment hash {:?}",
                                invoice.payment_hash
                            ),
                        });
                    }
                    Err(e) => {
                        error!(
                            "LND payment failed for invoice with {} with {e:?}",
                            PrettyPaymentHash(&payment_hash)
                        );
                        return Err(e);
                    }
                }
            }
        };
        Ok(PayInvoiceResponse { preimage })
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
            mpsc::channel::<Result<InterceptHtlcRequest, tonic::Status>>(CHANNEL_SIZE);

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
            gateway_db: self.gateway_db.clone(),
            payment_hashes: self.payment_hashes.clone(),
        });
        Ok((Box::pin(ReceiverStream::new(gateway_receiver)), new_client))
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        let InterceptHtlcResponse {
            action,
            payment_hash,
            incoming_chan_id,
            htlc_id,
        } = htlc;

        let (action, preimage) = match action {
            Some(Action::Settle(Settle { preimage })) => {
                (ResolveHoldForwardAction::Settle, preimage)
            }
            Some(Action::Forward(Forward {})) => (ResolveHoldForwardAction::Resume, vec![]),
            Some(Action::Cancel(Cancel { reason: _ })) | None => {
                (ResolveHoldForwardAction::Fail, vec![])
            }
        };

        // First check if this completion request corresponds to a HOLD LNv2 invoice
        match action {
            ResolveHoldForwardAction::Settle => {
                if let Ok(()) = self
                    .settle_hold_invoice(payment_hash.clone(), preimage.clone())
                    .await
                {
                    info!(
                        "Successfully settled HOLD invoice {}",
                        PrettyPaymentHash(&payment_hash)
                    );
                    return Ok(EmptyResponse {});
                }
            }
            _ => {
                if let Ok(()) = self.cancel_hold_invoice(payment_hash.clone()).await {
                    info!(
                        "Successfully canceled HOLD invoice {}",
                        PrettyPaymentHash(&payment_hash)
                    );
                    return Ok(EmptyResponse {});
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
                preimage,
                failure_message: vec![],
                failure_code: FailureCode::TemporaryChannelFailure.into(),
            };

            Self::send_lnd_response(lnd_sender, response).await?;
            return Ok(EmptyResponse {});
        }

        error!("Gatewayd has not started to route HTLCs");
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
            .unwrap_or(Description::Direct(String::new()));

        if create_invoice_request.payment_hash.is_empty() {
            let invoice = match description {
                Description::Direct(description) => Invoice {
                    memo: description,
                    value_msat: create_invoice_request.amount_msat as i64,
                    expiry: i64::from(create_invoice_request.expiry_secs),
                    ..Default::default()
                },
                Description::Hash(desc_hash) => Invoice {
                    description_hash: desc_hash,
                    value_msat: create_invoice_request.amount_msat as i64,
                    expiry: i64::from(create_invoice_request.expiry_secs),
                    ..Default::default()
                },
            };

            self.payment_hashes
                .write()
                .await
                .insert(create_invoice_request.payment_hash);

            let add_invoice_response =
                client.lightning().add_invoice(invoice).await.map_err(|e| {
                    LightningRpcError::FailedToGetInvoice {
                        failure_reason: e.to_string(),
                    }
                })?;

            let invoice = add_invoice_response.into_inner().payment_request;
            Ok(CreateInvoiceResponse { invoice })
        } else {
            let hold_invoice_request = match description {
                Description::Direct(description) => AddHoldInvoiceRequest {
                    memo: description,
                    hash: create_invoice_request.payment_hash.clone(),
                    value_msat: create_invoice_request.amount_msat as i64,
                    expiry: i64::from(create_invoice_request.expiry_secs),
                    ..Default::default()
                },
                Description::Hash(desc_hash) => AddHoldInvoiceRequest {
                    description_hash: desc_hash,
                    hash: create_invoice_request.payment_hash.clone(),
                    value_msat: create_invoice_request.amount_msat as i64,
                    expiry: i64::from(create_invoice_request.expiry_secs),
                    ..Default::default()
                },
            };

            self.payment_hashes
                .write()
                .await
                .insert(create_invoice_request.payment_hash);

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

    async fn withdraw_onchain(
        &self,
        address: Address,
        amount: BitcoinAmountOrAll,
        fee_rate_sats_per_vbyte: u64,
    ) -> Result<WithdrawOnchainResponse, LightningRpcError> {
        #[allow(deprecated)]
        let request = match amount {
            BitcoinAmountOrAll::All => SendCoinsRequest {
                addr: address.to_string(),
                amount: 0,
                target_conf: 0,
                sat_per_vbyte: fee_rate_sats_per_vbyte,
                sat_per_byte: 0,
                send_all: true,
                label: String::new(),
                min_confs: 0,
                spend_unconfirmed: true,
            },
            BitcoinAmountOrAll::Amount(amount) => SendCoinsRequest {
                addr: address.to_string(),
                amount: amount.to_sat() as i64,
                target_conf: 0,
                sat_per_vbyte: fee_rate_sats_per_vbyte,
                sat_per_byte: 0,
                send_all: false,
                label: String::new(),
                min_confs: 0,
                spend_unconfirmed: true,
            },
        };

        match self.connect().await?.lightning().send_coins(request).await {
            Ok(res) => Ok(WithdrawOnchainResponse {
                txid: res.into_inner().txid,
            }),
            Err(e) => Err(LightningRpcError::FailedToWithdrawOnchain {
                failure_reason: format!("Failed to withdraw funds on-chain {e:?}"),
            }),
        }
    }

    async fn open_channel(
        &self,
        pubkey: PublicKey,
        host: String,
        channel_size_sats: u64,
        push_amount_sats: u64,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        let mut client = self.connect().await?;

        // Connect to the peer first
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
        pubkey: PublicKey,
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
            })
            .await
            .map_err(|e| LightningRpcError::FailedToCloseChannelsWithPeer {
                failure_reason: format!("Failed to list channels {e:?}"),
            })?
            .into_inner()
            .channels;

        for channel in &channels_with_peer {
            let channel_point =
                bitcoin30::OutPoint::from_str(&channel.channel_point).map_err(|e| {
                    LightningRpcError::FailedToCloseChannelsWithPeer {
                        failure_reason: format!("Failed to parse channel point {e:?}"),
                    }
                })?;

            client
                .lightning()
                .close_channel(CloseChannelRequest {
                    channel_point: Some(ChannelPoint {
                        funding_txid: Some(
                            tonic_lnd::lnrpc::channel_point::FundingTxid::FundingTxidBytes(
                                <bitcoin30::Txid as AsRef<[u8]>>::as_ref(&channel_point.txid)
                                    .to_vec(),
                            ),
                        ),
                        output_index: channel_point.vout,
                    }),
                    ..Default::default()
                })
                .await
                .map_err(|e| LightningRpcError::FailedToCloseChannelsWithPeer {
                    failure_reason: format!("Failed to close channel {e:?}"),
                })?;
        }

        Ok(CloseChannelsWithPeerResponse {
            num_channels_closed: channels_with_peer.len() as u32,
        })
    }

    async fn list_active_channels(&self) -> Result<Vec<ChannelInfo>, LightningRpcError> {
        let mut client = self.connect().await?;

        match client
            .lightning()
            .list_channels(ListChannelsRequest {
                active_only: true,
                inactive_only: false,
                public_only: false,
                private_only: false,
                peer: vec![],
            })
            .await
        {
            Ok(response) => Ok(response
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
                        if local_balance_sats >= local_channel_reserve_sats {
                            // We must only perform this subtraction if the local balance is
                            // greater than or equal to the channel reserve, otherwise we would
                            // underflow and panic.
                            local_balance_sats - local_channel_reserve_sats
                        } else {
                            0
                        };

                    let remote_balance_sats: u64 =
                        channel.remote_balance.try_into().expect("i64 -> u64");
                    let remote_channel_reserve_sats: u64 = match channel.remote_constraints {
                        Some(constraints) => constraints.chan_reserve_sat,
                        None => 0,
                    };

                    let inbound_liquidity_sats =
                        if remote_balance_sats >= remote_channel_reserve_sats {
                            // We must only perform this subtraction if the remote balance is
                            // greater than or equal to the channel reserve, otherwise we would
                            // underflow and panic.
                            remote_balance_sats - remote_channel_reserve_sats
                        } else {
                            0
                        };

                    ChannelInfo {
                        remote_pubkey: PublicKey::from_str(&channel.remote_pubkey)
                            .expect("Lightning node returned invalid remote channel pubkey"),
                        channel_size_sats,
                        outbound_liquidity_sats,
                        inbound_liquidity_sats,
                        short_channel_id: channel.chan_id,
                    }
                })
                .collect()),
            Err(e) => Err(LightningRpcError::FailedToListActiveChannels {
                failure_reason: format!("Failed to list active channels {e:?}"),
            }),
        }
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        let mut client = self.connect().await?;

        let wallet_balance_response = client
            .lightning()
            .wallet_balance(WalletBalanceRequest {})
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

        Ok(GetBalancesResponse {
            onchain_balance_sats: wallet_balance_response.total_balance as u64,
            lightning_balance_msats: channel_balance_response
                .local_balance
                .unwrap_or_default()
                .msat,
            inbound_lightning_liquidity_msats: channel_balance_response
                .remote_balance
                .unwrap_or_default()
                .msat,
        })
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
mod tests {
    use hex::FromHex;
    use lightning::ln::features::Bolt11InvoiceFeatures;
    use lightning::util::ser::{WithoutLength, Writeable};

    use super::wire_features_to_lnd_feature_vec;

    #[test]
    fn features_to_lnd() {
        assert_eq!(
            wire_features_to_lnd_feature_vec(&[]).unwrap(),
            Vec::<i32>::new()
        );

        let features_payment_secret = {
            let mut f = Bolt11InvoiceFeatures::empty();
            f.set_payment_secret_optional();
            WithoutLength(&f).encode()
        };
        assert_eq!(
            wire_features_to_lnd_feature_vec(&features_payment_secret).unwrap(),
            vec![15]
        );

        // Phoenix feature flags
        let features_payment_secret =
            Vec::from_hex("20000000000000000000000002000000024100").unwrap();
        assert_eq!(
            wire_features_to_lnd_feature_vec(&features_payment_secret).unwrap(),
            vec![8, 14, 17, 49, 149]
        );
    }
}
