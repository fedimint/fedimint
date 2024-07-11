use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::ensure;
use async_trait::async_trait;
use bitcoin_hashes::Hash;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::{secp256k1, Amount};
use fedimint_ln_common::PrunedInvoice;
use futures::StreamExt;
use hex::ToHex;
use secp256k1::PublicKey;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tonic_lnd::invoicesrpc::AddHoldInvoiceRequest;
use tonic_lnd::lnrpc::failure::FailureCode;
use tonic_lnd::lnrpc::fee_limit::Limit;
use tonic_lnd::lnrpc::htlc_attempt::HtlcStatus;
use tonic_lnd::lnrpc::payment::PaymentStatus;
use tonic_lnd::lnrpc::{
    ChanInfoRequest, ChannelPoint, CloseChannelRequest, ConnectPeerRequest, FeeLimit,
    GetInfoRequest, LightningAddress, ListChannelsRequest, MppRecord, OpenChannelRequest,
    QueryRoutesRequest,
};
use tonic_lnd::routerrpc::{
    CircuitKey, ForwardHtlcInterceptResponse, ResolveHoldForwardAction, SendPaymentRequest,
    SendToRouteRequest, TrackPaymentRequest,
};
use tonic_lnd::tonic::{Code, Response};
use tonic_lnd::walletrpc::AddrRequest;
use tonic_lnd::{connect, Client as LndClient, Client};
use tracing::{debug, error, info, trace, warn};

use super::{ChannelInfo, ILnRpcClient, LightningRpcError, RouteHtlcStream, MAX_LIGHTNING_RETRIES};
use crate::gateway_lnrpc::create_invoice_request::Description;
use crate::gateway_lnrpc::get_route_hints_response::{RouteHint, RouteHintHop};
use crate::gateway_lnrpc::intercept_htlc_response::{Action, Cancel, Forward, Settle};
use crate::gateway_lnrpc::{
    CloseChannelsWithPeerResponse, CreateInvoiceRequest, CreateInvoiceResponse, EmptyResponse,
    GetFundingAddressResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcRequest,
    InterceptHtlcResponse, PayInvoiceRequest, PayInvoiceResponse,
};

type HtlcSubscriptionSender = mpsc::Sender<Result<InterceptHtlcRequest, Status>>;

const LND_PAYMENT_TIMEOUT_SECONDS: u64 = 180;

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

    async fn spawn_interceptor(
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
                                error!("Error received over HTLC stream: {:?}", e);
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
        let network = info
            .chains
            .first()
            .ok_or_else(|| LightningRpcError::FailedToGetNodeInfo {
                failure_reason: "Failed to parse node network".to_string(),
            })?
            .clone()
            .network;

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

    async fn pay(
        &self,
        _request: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        error!("LND supports private payments, legacy `pay` should not be used.");
        Err(LightningRpcError::FailedPayment {
            failure_reason: "LND supports private payments, legacy `pay` should not be used."
                .to_string(),
        })
    }

    async fn pay_private(
        &self,
        invoice: PrunedInvoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        info!("LND Paying invoice {invoice:?}");
        let mut client = self.connect().await?;

        debug!("LND got client to pay invoice {invoice:?}, will check if payment already exists");

        // If the payment exists, that means we've already tried to pay the invoice
        if let Some(preimage) = self
            .lookup_payment(invoice.payment_hash.to_byte_array().to_vec(), &mut client)
            .await?
        {
            info!("LND payment already exists for invoice {invoice:?}");
            let preimage = hex::FromHex::from_hex(preimage.as_str()).map_err(|error| {
                LightningRpcError::FailedPayment {
                    failure_reason: format!("Failed to convert preimage {error:?}"),
                }
            })?;
            return Ok(PayInvoiceResponse { preimage });
        }

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

        let send_amt_msat: i64 = invoice
            .send_amount
            .unwrap_or(invoice.amount)
            .msats
            .try_into()
            .map_err(|error| LightningRpcError::FailedPayment {
                failure_reason: format!("amount exceeds valid LND amount ranges {error:?}"),
            })?;

        let final_cltv_delta = invoice.min_final_cltv_delta.try_into().map_err(|error| {
            LightningRpcError::FailedPayment {
                failure_reason: format!("final cltv delta exceeds valid LND range {error:?}"),
            }
        })?;

        let dest_features = wire_features_to_lnd_feature_vec(&invoice.destination_features)
            .map_err(|e| LightningRpcError::FailedPayment {
                failure_reason: e.to_string(),
            })?;

        debug!("LND payment does not exist for invoice {invoice:?}, will attempt to pay");

        // if we're doing a partial payment, need to do custom routing, otherwise
        // we can use the simpler send_payment_v2 rpc
        if invoice.send_amount.is_some_and(|a| a != invoice.amount) {
            pay_partial(
                &mut client,
                invoice,
                max_delay,
                send_amt_msat,
                fee_limit_msat,
                final_cltv_delta,
                dest_features,
            )
            .await
        } else {
            let amt_msat: i64 = invoice.amount.msats.try_into().map_err(|error| {
                LightningRpcError::FailedPayment {
                    failure_reason: format!("amount exceeds valid LND amount ranges {error:?}"),
                }
            })?;

            let cltv_limit =
                max_delay
                    .try_into()
                    .map_err(|error| LightningRpcError::FailedPayment {
                        failure_reason: format!("max delay exceeds valid LND range {error:?}"),
                    })?;

            pay_full(
                &mut client,
                invoice,
                amt_msat,
                cltv_limit,
                fee_limit_msat,
                final_cltv_delta,
                dest_features,
            )
            .await
        }
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
        let new_client = Arc::new(Self::new(
            self.address.clone(),
            self.tls_cert.clone(),
            self.macaroon.clone(),
            Some(lnd_sender.clone()),
        ));
        Ok((Box::pin(ReceiverStream::new(gateway_receiver)), new_client))
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        if let Some(lnd_sender) = self.lnd_sender.clone() {
            let InterceptHtlcResponse {
                action,
                payment_hash: _,
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

        Err(LightningRpcError::FailedToCompleteHtlc {
            failure_reason: "Gatewayd has not started to route HTLCs".to_string(),
        })
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let mut client = self.connect().await?;
        let description =
            create_invoice_request
                .description
                .ok_or(LightningRpcError::FailedToGetInvoice {
                    failure_reason: "Description or description hash was not provided".to_string(),
                })?;

        let hold_invoice_request = match description {
            Description::Direct(description) => AddHoldInvoiceRequest {
                memo: description,
                hash: create_invoice_request.payment_hash,
                value_msat: create_invoice_request.amount_msat as i64,
                expiry: i64::from(create_invoice_request.expiry_secs),
                ..Default::default()
            },
            Description::Hash(desc_hash) => AddHoldInvoiceRequest {
                description_hash: desc_hash,
                hash: create_invoice_request.payment_hash,
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

    async fn get_funding_address(&self) -> Result<GetFundingAddressResponse, LightningRpcError> {
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
            Ok(response) => Ok(GetFundingAddressResponse {
                address: response.into_inner().addr,
            }),
            Err(e) => Err(LightningRpcError::FailedToGetFundingAddress {
                failure_reason: format!("Failed to get funding address {e:?}"),
            }),
        }
    }

    async fn open_channel(
        &self,
        pubkey: PublicKey,
        host: String,
        channel_size_sats: u64,
        push_amount_sats: u64,
    ) -> Result<EmptyResponse, LightningRpcError> {
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
            .open_channel(OpenChannelRequest {
                node_pubkey: pubkey.serialize().to_vec(),
                local_funding_amount: channel_size_sats.try_into().expect("u64 -> i64"),
                push_sat: push_amount_sats.try_into().expect("u64 -> i64"),
                ..Default::default()
            })
            .await
        {
            Ok(_) => Ok(EmptyResponse {}),
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
                bitcoin::OutPoint::from_str(&channel.channel_point).map_err(|e| {
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
                                <bitcoin::Txid as AsRef<[u8]>>::as_ref(&channel_point.txid)
                                    .as_ref()
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
                        remote_pubkey: channel.remote_pubkey,
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
}

async fn pay_full(
    client: &mut Client,
    invoice: PrunedInvoice,
    amt_msat: i64,
    cltv_limit: i32,
    fee_limit_msat: i64,
    final_cltv_delta: i32,
    dest_features: Vec<i32>,
) -> Result<PayInvoiceResponse, LightningRpcError> {
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
            timeout_seconds: LND_PAYMENT_TIMEOUT_SECONDS as i32,
            fee_limit_msat,
            ..Default::default()
        })
        .await
        .map_err(|status| {
            info!("LND payment request failed for invoice {invoice:?} with {status:?}");
            LightningRpcError::FailedPayment {
                failure_reason: format!("Failed to make outgoing payment {status:?}"),
            }
        })?;

    debug!("LND payment request sent for invoice {invoice:?}, waiting for payment status...");
    let mut messages = payments.into_inner();
    let preimage = loop {
        match messages
            .message()
            .await
            .map_err(|error| LightningRpcError::FailedPayment {
                failure_reason: format!("Failed to get payment status {error:?}"),
            }) {
            Ok(Some(payment)) if payment.status() == PaymentStatus::Succeeded => {
                info!("LND payment succeeded for invoice {invoice:?}");
                break hex::FromHex::from_hex(payment.payment_preimage.as_str()).map_err(
                    |error| LightningRpcError::FailedPayment {
                        failure_reason: format!("Failed to convert preimage {error:?}"),
                    },
                )?;
            }
            Ok(Some(payment)) if payment.status() == PaymentStatus::InFlight => {
                debug!("LND payment is inflight");
                continue;
            }
            Ok(Some(payment)) => {
                info!("LND payment failed for invoice {invoice:?} with {payment:?}");
                let failure_reason = payment.failure_reason();
                return Err(LightningRpcError::FailedPayment {
                    failure_reason: format!("{failure_reason:?}"),
                });
            }
            Ok(None) => {
                info!("LND payment failed for invoice {invoice:?} with no payment status");
                return Err(LightningRpcError::FailedPayment {
                    failure_reason: format!(
                        "Failed to get payment status for payment hash {:?}",
                        invoice.payment_hash
                    ),
                });
            }
            Err(e) => {
                info!("LND payment failed for invoice {invoice:?} with {e:?}");
                return Err(e);
            }
        }
    };

    Ok(PayInvoiceResponse { preimage })
}

async fn pay_partial(
    client: &mut Client,
    invoice: PrunedInvoice,
    max_delay: u64,
    send_amt_msat: i64,
    fee_limit_msat: i64,
    final_cltv_delta: i32,
    dest_features: Vec<i32>,
) -> Result<PayInvoiceResponse, LightningRpcError> {
    let total_amt_msat: i64 =
        invoice
            .amount
            .msats
            .try_into()
            .map_err(|error| LightningRpcError::FailedPayment {
                failure_reason: format!("amount exceeds valid LND amount ranges {error:?}"),
            })?;

    let cltv_limit = max_delay
        .try_into()
        .map_err(|error| LightningRpcError::FailedPayment {
            failure_reason: format!("max delay exceeds valid LND range {error:?}"),
        })?;

    let routes = client
        .lightning()
        .query_routes(QueryRoutesRequest {
            pub_key: invoice.destination.to_string(),
            amt_msat: send_amt_msat,
            final_cltv_delta,
            fee_limit: Some(FeeLimit {
                limit: Some(Limit::FixedMsat(fee_limit_msat)),
            }),
            cltv_limit,
            route_hints: route_hints_to_lnd(&invoice.route_hints),
            dest_features,
            use_mission_control: true,
            ..Default::default()
        })
        .await
        .map_err(|status| {
            error!("LND failed to query routes for invoice {invoice:?} with {status:?}");
            LightningRpcError::FailedPayment {
                failure_reason: format!("Failed to make query routes {status:?}"),
            }
        })?
        .into_inner();

    let mut last_failed_reason: Option<String> = None;

    let start = duration_since_epoch();
    let mut attempts = 0;

    for mut route in routes.routes {
        // skip any empty routes
        if route.hops.is_empty() {
            continue;
        }
        // check if we've timed out
        if duration_since_epoch() > Duration::from_secs(LND_PAYMENT_TIMEOUT_SECONDS) + start {
            return Err(LightningRpcError::FailedPayment {
                failure_reason: "Timed out waiting for payment to complete".to_string(),
            });
        }
        attempts += 1;

        // add mpp record to route
        let last = route.hops.last_mut().expect("must have at least one hop");

        last.mpp_record = Some(MppRecord {
            payment_addr: invoice.payment_secret.to_vec(),
            total_amt_msat,
        });

        trace!("Attempting to send payment to route {route:?}");

        debug!("LND payment attempt {attempts} request sent for invoice {invoice:?}, waiting for payment status...");

        let htlc_attempt = client
            .router()
            .send_to_route_v2(SendToRouteRequest {
                payment_hash: invoice.payment_hash.to_byte_array().to_vec(),
                route: Some(route),
                skip_temp_err: false,
            })
            .await
            .map_err(|status| {
                error!("LND payment request failed for invoice {invoice:?} with {status:?}");
                LightningRpcError::FailedPayment {
                    failure_reason: format!("Failed to make outgoing payment {status:?}"),
                }
            });

        match htlc_attempt.map(Response::into_inner) {
            Ok(payment) => match payment.status() {
                HtlcStatus::Failed => {
                    error!("LND payment failed for invoice {invoice:?} with {payment:?}");
                    if let Some(failure) = payment.failure {
                        last_failed_reason = Some(failure.code().as_str_name().to_string());
                    }
                }
                HtlcStatus::InFlight => {
                    debug!("LND payment is inflight, tracking...");
                    let stream = client.router().track_payment_v2(TrackPaymentRequest {
                        payment_hash: invoice.payment_hash.to_byte_array().to_vec(),
                        no_inflight_updates: false,
                    }).await.map_err(|status| {
                        error!("LND payment request failed for invoice {invoice:?} with {status:?}");
                        LightningRpcError::FailedPayment {
                            failure_reason: format!("Failed to make outgoing payment {status:?}"),
                        }
                    })?;

                    let mut stream = stream.into_inner();
                    while let Some(update) = stream.next().await {
                        match update {
                            Ok(payment) => match payment.status() {
                                PaymentStatus::Unknown => {
                                    warn!("LND payment status unknown for invoice {} with {payment:?}", invoice.payment_hash);
                                }
                                PaymentStatus::InFlight => {
                                    trace!(
                                        "LND payment {} is inflight: {payment:?}",
                                        invoice.payment_hash
                                    );
                                }
                                PaymentStatus::Failed => {
                                    error!("LND payment failed for invoice {invoice:?} with {payment:?}");
                                    last_failed_reason =
                                        Some(payment.failure_reason().as_str_name().to_string());
                                }
                                PaymentStatus::Succeeded => {
                                    info!("LND payment succeeded for invoice {invoice:?}");
                                    let preimage = hex::FromHex::from_hex(
                                        &payment.payment_preimage,
                                    )
                                    .map_err(|error| LightningRpcError::FailedPayment {
                                        failure_reason: format!(
                                            "Failed to convert preimage {error:?}"
                                        ),
                                    })?;
                                    return Ok(PayInvoiceResponse { preimage });
                                }
                            },
                            Err(e) => {
                                error!("Failed to get payment status for invoice {invoice:?} with {e:?}");
                                return Err(LightningRpcError::FailedPayment {
                                    failure_reason: format!(
                                        "Failed to get payment status for invoice {invoice:?} with {e:?}"
                                    ),
                                });
                            }
                        }
                    }
                }
                HtlcStatus::Succeeded => {
                    info!("LND payment succeeded for invoice {invoice:?}");
                    return Ok(PayInvoiceResponse {
                        preimage: payment.preimage,
                    });
                }
            },
            Err(e) => {
                error!("LND payment failed for invoice {invoice:?} with {e:?}");
                return Err(e);
            }
        }
    }

    Err(LightningRpcError::FailedPayment {
        failure_reason: last_failed_reason.unwrap_or_else(|| "No route found".to_string()),
    })
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
