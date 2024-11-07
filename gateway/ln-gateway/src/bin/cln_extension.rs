use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use axum::body::{Body, Bytes};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use bitcoin_hashes::sha256;
use clap::Parser;
use cln_plugin::options::{self, StringConfigOption};
use cln_plugin::{Builder, Plugin};
use cln_rpc::model;
use cln_rpc::model::requests::SendpayRoute;
use cln_rpc::model::responses::ListpeerchannelsChannels;
use cln_rpc::primitives::{AmountOrAll, ChannelState, ShortChannelId};
use fedimint_core::bitcoin_migration::{
    bitcoin30_to_bitcoin32_secp256k1_message, bitcoin30_to_bitcoin32_secp256k1_pubkey,
    bitcoin32_to_bitcoin30_network, bitcoin32_to_bitcoin30_recoverable_signature,
    bitcoin32_to_bitcoin30_secp256k1_pubkey,
};
use fedimint_core::secp256k1::{PublicKey, SecretKey, SECP256K1};
use fedimint_core::task::timeout;
use fedimint_core::util::handle_version_hash_command;
use fedimint_core::{fedimint_build_code_version_env, Amount, BitcoinAmountOrAll};
use fedimint_ln_common::contracts::Preimage;
use fedimint_ln_common::route_hints::{RouteHint, RouteHintHop};
use fedimint_ln_common::PrunedInvoice;
use futures_util::stream::StreamExt;
use hex::ToHex;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use ln_gateway::envs::FM_CLN_EXTENSION_LISTEN_ADDRESS_ENV;
use ln_gateway::lightning::extension::{
    CLN_CLOSE_CHANNELS_WITH_PEER_ENDPOINT, CLN_COMPLETE_PAYMENT_ENDPOINT,
    CLN_CREATE_INVOICE_ENDPOINT, CLN_GET_BALANCES_ENDPOINT, CLN_INFO_ENDPOINT,
    CLN_LIST_ACTIVE_CHANNELS_ENDPOINT, CLN_LN_ONCHAIN_ADDRESS_ENDPOINT, CLN_OPEN_CHANNEL_ENDPOINT,
    CLN_PAY_INVOICE_ENDPOINT, CLN_PAY_PRUNED_INVOICE_ENDPOINT, CLN_ROUTE_HINTS_ENDPOINT,
    CLN_ROUTE_HTLCS_ENDPOINT, CLN_SEND_ONCHAIN_ENDPOINT,
};
use ln_gateway::lightning::{
    CloseChannelsWithPeerResponse, CreateInvoiceRequest, CreateInvoiceResponse,
    GetBalancesResponse, GetLnOnchainAddressResponse, GetNodeInfoResponse, GetRouteHintsRequest,
    GetRouteHintsResponse, InterceptPaymentRequest, InterceptPaymentResponse, InvoiceDescription,
    ListActiveChannelsResponse, OpenChannelResponse, PayInvoiceRequest, PayInvoiceResponse,
    PayPrunedInvoiceRequest, PaymentAction, SendOnchainResponse,
};
use ln_gateway::rpc::{CloseChannelsWithPeerPayload, OpenChannelPayload, SendOnchainPayload};
use rand::rngs::OsRng;
use rand::Rng;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{stdin, stdout};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, instrument, warn};

const MAX_HTLC_PROCESSING_DURATION: Duration = Duration::MAX;
// Amount of time to attempt making a payment before returning an error
const PAYMENT_TIMEOUT_DURATION: Duration = Duration::from_secs(180);
// Use a `riskfactor` of 10, which is the default for lightning-pay
const ROUTE_RISK_FACTOR: u64 = 10;
// Error code for a failure along a payment route: https://docs.corelightning.org/reference/lightning-waitsendpay
const FAILURE_ALONG_ROUTE: i32 = 204;

const FM_CLN_EXTENSION_LISTEN_ADDRESS_CLI_ARG: &str = "fm-gateway-listen";
const FM_CLN_EXTENSION_LISTEN_ADDRESS_CONFIG_OPTION: StringConfigOption =
    options::ConfigOption::new_str_no_default(
        FM_CLN_EXTENSION_LISTEN_ADDRESS_CLI_ARG,
        "fedimint gateway CLN extension listen address",
    );

#[derive(Parser)]
#[command(version)]
struct ClnExtensionOpts {
    /// Gateway CLN extension service listen address
    #[arg(long = FM_CLN_EXTENSION_LISTEN_ADDRESS_CLI_ARG, env = FM_CLN_EXTENSION_LISTEN_ADDRESS_ENV)]
    fm_gateway_listen: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    handle_version_hash_command(fedimint_build_code_version_env!());

    let extension_opts = ClnExtensionOpts::parse();
    let (service, interceptor, listen, plugin) = ClnRpcService::new(extension_opts)
        .await
        .expect("Failed to create cln rpc service");

    debug!(
        "Starting gateway-cln-extension with listen address : {}",
        listen
    );

    run_webserver(listen, service.clone(), interceptor, plugin).await?;

    // lightningd needs to see exit code 0 to notice the plugin has
    // terminated -- even if we return from main().
    info!("gateway cln extension exiting...");
    std::process::exit(0);
}

async fn run_webserver(
    listen: SocketAddr,
    cln_service: ClnRpcService,
    interceptor: Arc<ClnHtlcInterceptor>,
    plugin: Plugin<Arc<ClnHtlcInterceptor>>,
) -> anyhow::Result<()> {
    let routes = routes(cln_service, interceptor);
    let listener = TcpListener::bind(&listen).await?;
    let serve = axum::serve(listener, routes.into_make_service());
    info!("Starting cln extension webserver on {}", listen);
    let graceful = serve.with_graceful_shutdown(async move {
        // Wait for plugin to signal it's shutting down
        let _ = plugin.join().await;
    });

    if let Err(e) = graceful.await {
        error!("Error shutting down cln extension webserver: {:?}", e);
    } else {
        info!("Successfully shutdown cln extension webserver");
    }

    Ok(())
}

fn routes(cln_service: ClnRpcService, interceptor: Arc<ClnHtlcInterceptor>) -> Router {
    let public_routes = Router::new()
        .route(CLN_INFO_ENDPOINT, get(cln_info))
        .route(CLN_ROUTE_HINTS_ENDPOINT, post(cln_route_hints))
        .route(CLN_ROUTE_HTLCS_ENDPOINT, get(cln_route_htlcs))
        .route(CLN_PAY_INVOICE_ENDPOINT, post(cln_pay_invoice))
        .route(
            CLN_PAY_PRUNED_INVOICE_ENDPOINT,
            post(cln_pay_pruned_invoice),
        )
        .route(CLN_COMPLETE_PAYMENT_ENDPOINT, post(cln_complete_payment))
        .route(CLN_CREATE_INVOICE_ENDPOINT, post(cln_create_invoice))
        .route(CLN_LN_ONCHAIN_ADDRESS_ENDPOINT, get(cln_ln_onchain_address))
        .route(CLN_SEND_ONCHAIN_ENDPOINT, post(cln_send_onchain))
        .route(CLN_OPEN_CHANNEL_ENDPOINT, post(cln_open_channel))
        .route(
            CLN_CLOSE_CHANNELS_WITH_PEER_ENDPOINT,
            post(cln_close_channels_with_peer),
        )
        .route(
            CLN_LIST_ACTIVE_CHANNELS_ENDPOINT,
            get(cln_list_active_channels),
        )
        .route(CLN_GET_BALANCES_ENDPOINT, get(cln_get_balances));
    Router::new()
        .merge(public_routes)
        .layer(Extension(cln_service))
        .layer(Extension(interceptor))
        .layer(CorsLayer::permissive())
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_info(
    Extension(cln_service): Extension<ClnRpcService>,
) -> Result<Json<GetNodeInfoResponse>, ClnExtensionError> {
    let response = cln_service.info().await.map(
        |(pub_key, alias, network, block_height, synced_to_chain)| GetNodeInfoResponse {
            pub_key,
            alias,
            network,
            block_height,
            synced_to_chain,
        },
    )?;

    Ok(Json(response))
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_route_hints(
    Extension(cln_service): Extension<ClnRpcService>,
    Json(payload): Json<GetRouteHintsRequest>,
) -> Result<Json<GetRouteHintsResponse>, ClnExtensionError> {
    let GetRouteHintsRequest { num_route_hints } = payload;
    let node_info = cln_service.info().await?;

    let mut client = cln_service.rpc_client().await?;

    let active_peer_channels_response = client
        .call(cln_rpc::Request::ListPeerChannels(
            model::requests::ListpeerchannelsRequest { id: None },
        ))
        .await?;

    let mut active_peer_channels = match active_peer_channels_response {
        cln_rpc::Response::ListPeerChannels(channels) => channels.channels,
        _ => unreachable!("Unexpected response from ListPeerChannels"),
    }
    .into_iter()
    .filter_map(|chan| {
        if matches!(
            chan.state,
            model::responses::ListpeerchannelsChannelsState::CHANNELD_NORMAL
        ) {
            return chan.short_channel_id.map(|scid| (chan.peer_id, scid));
        }

        None
    })
    .collect::<Vec<_>>();

    debug!(
        "Found {} active channels to use as route hints",
        active_peer_channels.len()
    );

    let listfunds_response = client
        .call(cln_rpc::Request::ListFunds(
            model::requests::ListfundsRequest { spent: None },
        ))
        .await?;
    let pubkey_to_incoming_capacity = match listfunds_response {
        cln_rpc::Response::ListFunds(listfunds) => listfunds
            .channels
            .into_iter()
            .map(|chan| (chan.peer_id, chan.amount_msat - chan.our_amount_msat))
            .collect::<HashMap<_, _>>(),
        _ => unreachable!("Unexpected response from ListFunds"),
    };
    active_peer_channels.sort_by(|a, b| {
        let a_incoming = pubkey_to_incoming_capacity.get(&a.0).unwrap().msat();
        let b_incoming = pubkey_to_incoming_capacity.get(&b.0).unwrap().msat();
        b_incoming.cmp(&a_incoming)
    });
    active_peer_channels.truncate(num_route_hints as usize);

    let mut route_hints = vec![];
    for (peer_id, scid) in active_peer_channels {
        let channels_response = client
            .call(cln_rpc::Request::ListChannels(
                model::requests::ListchannelsRequest {
                    short_channel_id: Some(scid),
                    source: None,
                    destination: None,
                },
            ))
            .await?;

        let channel = match channels_response {
            cln_rpc::Response::ListChannels(channels) => {
                let Some(channel) = channels.channels.into_iter().find(|chan| {
                    chan.destination == bitcoin32_to_bitcoin30_secp256k1_pubkey(&node_info.0)
                }) else {
                    warn!(?scid, "Channel not found in graph");
                    continue;
                };
                channel
            }
            _ => unreachable!("Unexpected response from ListChannels"),
        };

        let route_hint_hop = RouteHintHop {
            src_node_id: bitcoin30_to_bitcoin32_secp256k1_pubkey(&peer_id),
            short_channel_id: scid_to_u64(scid),
            base_msat: channel.base_fee_millisatoshi,
            proportional_millionths: channel.fee_per_millionth,
            cltv_expiry_delta: channel.delay as u16,
            htlc_minimum_msat: Some(channel.htlc_minimum_msat.msat()),
            htlc_maximum_msat: channel.htlc_maximum_msat.map(|amt| amt.msat()),
        };

        debug!("Constructed route hint {:?}", route_hint_hop);
        route_hints.push(RouteHint(vec![route_hint_hop]));
    }

    Ok(Json(GetRouteHintsResponse { route_hints }))
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_pay_invoice(
    Extension(cln_service): Extension<ClnRpcService>,
    Json(payload): Json<PayInvoiceRequest>,
) -> Result<Json<PayInvoiceResponse>, ClnExtensionError> {
    let PayInvoiceRequest {
        invoice,
        max_delay,
        max_fee_msat,
        payment_hash: _,
    } = payload;

    let outcome = cln_service
        .rpc_client()
        .await?
        .call(cln_rpc::Request::Pay(model::requests::PayRequest {
            bolt11: invoice,
            amount_msat: None,
            label: None,
            riskfactor: None,
            retry_for: None,
            maxdelay: Some(max_delay as u16),
            exemptfee: None,
            localinvreqid: None,
            exclude: None,
            maxfee: Some(cln_rpc::primitives::Amount::from_msat(max_fee_msat)),
            maxfeepercent: None,
            description: None,
            partial_msat: None,
        }))
        .await
        .map(|response| match response {
            cln_rpc::Response::Pay(model::responses::PayResponse {
                payment_preimage, ..
            }) => PayInvoiceResponse {
                preimage: Preimage(
                    payment_preimage
                        .to_vec()
                        .try_into()
                        .expect("Failed to parse preimage"),
                ),
            },
            _ => unreachable!("Unexpected response from Pay"),
        })?;

    Ok(Json(outcome))
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_pay_pruned_invoice(
    Extension(cln_service): Extension<ClnRpcService>,
    Json(payload): Json<PayPrunedInvoiceRequest>,
) -> Result<Json<PayInvoiceResponse>, ClnExtensionError> {
    let PayPrunedInvoiceRequest {
        pruned_invoice,
        max_delay,
        max_fee_msat,
    } = payload;

    let pruned_invoice = pruned_invoice.ok_or_else(|| anyhow!("PrunedInvoice is None"))?;
    let payment_hash = pruned_invoice.payment_hash;

    let mut excluded_nodes = vec![];

    let payment_future = async {
        let mut route_attempt = 0;

        loop {
            let route = cln_service
                .get_route(
                    pruned_invoice.clone(),
                    ROUTE_RISK_FACTOR,
                    excluded_nodes.clone(),
                )
                .await?;

            // Verify `max_delay` is greater than the worst case timeout for the payment
            // failure in blocks
            let delay = route
                .first()
                .ok_or_else(|| anyhow!("First hop in route did not contain a delay"))?
                .delay;
            if max_delay < delay.into() {
                return Err(ClnExtensionError::Error(anyhow!(
                    "Max delay is greater than worse case timeout"
                )));
            }

            // Verify the total fee is less than `max_fee_msat`
            let first_hop_amount = route
                .first()
                .ok_or_else(|| anyhow!("First hop did not contain an amount"))?
                .amount_msat;
            let last_hop_amount = route
                .last()
                .ok_or_else(|| anyhow!("Last hop did not contain an amount"))?
                .amount_msat;
            let fee = first_hop_amount - last_hop_amount;
            if max_fee_msat.msats < fee.msat() {
                return Err(ClnExtensionError::Error(anyhow!(
                    "Total fee is greater than `max_fee_msat`"
                )));
            }

            debug!(
                ?route_attempt,
                ?payment_hash,
                ?route,
                "Attempting payment with route"
            );
            match cln_service
                .pay_with_route(pruned_invoice.clone(), payment_hash, route.clone())
                .await
            {
                Ok(preimage) => {
                    let response = PayInvoiceResponse {
                        preimage: Preimage(preimage.try_into().expect("Failed to parse preimage")),
                    };
                    return Ok(Json(response));
                }
                Err(ClnExtensionError::FailedPayment { erring_node }) => {
                    error!(
                        ?route_attempt,
                        ?payment_hash,
                        ?erring_node,
                        "Pruned invoice payment attempt failure"
                    );
                    excluded_nodes.push(erring_node);
                }
                Err(e) => {
                    error!(
                        ?route_attempt,
                        ?payment_hash,
                        ?e,
                        "Permanent Pruned invoice payment attempt failure"
                    );
                    return Err(e);
                }
            }

            route_attempt += 1;
        }
    };

    match timeout(PAYMENT_TIMEOUT_DURATION, payment_future).await {
        Ok(preimage) => preimage,
        Err(elapsed) => {
            error!(
                ?PAYMENT_TIMEOUT_DURATION,
                ?elapsed,
                ?payment_hash,
                "Payment exceeded max attempt duration"
            );
            Err(ClnExtensionError::Error(anyhow!(
                "Payment exceeded max attempt duration"
            )))
        }
    }
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_route_htlcs(
    Extension(interceptor): Extension<Arc<ClnHtlcInterceptor>>,
) -> Result<Body, ClnExtensionError> {
    // First create new channel that we will use to send responses back to gatewayd
    let (gatewayd_sender, gatewayd_receiver) = mpsc::channel::<InterceptPaymentRequest>(100);

    let mut sender = interceptor.sender.lock().await;
    *sender = Some(gatewayd_sender.clone());
    debug!("Gateway channel sender replaced");

    let receiver_stream = ReceiverStream::new(gatewayd_receiver).map(|msg| {
        // TODO: Handle JSON decoding error
        let json = serde_json::to_vec(&msg).unwrap_or_default();
        Ok::<Bytes, ClnExtensionError>(Bytes::from(json))
    });

    let body = Body::from_stream(receiver_stream);

    Ok(body)
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_complete_payment(
    Extension(interceptor): Extension<Arc<ClnHtlcInterceptor>>,
    Json(payload): Json<InterceptPaymentResponse>,
) -> Result<Json<()>, ClnExtensionError> {
    let InterceptPaymentResponse {
        action,
        incoming_chan_id,
        htlc_id,
        ..
    } = payload;

    if let Some(outcome) = interceptor
        .outcomes
        .lock()
        .await
        .remove(&(incoming_chan_id, htlc_id))
    {
        // Translate action request into a cln rpc response for
        // `htlc_accepted` event
        let htlca_res = match action {
            PaymentAction::Settle(preimage) => {
                serde_json::json!({ "result": "resolve", "payment_key": preimage.0.encode_hex::<String>() })
            }
            PaymentAction::Cancel => {
                // Simply forward the HTLC so that a "NoRoute" error response is returned.
                serde_json::json!({ "result": "continue" })
            }
            PaymentAction::Forward => {
                serde_json::json!({ "result": "continue" })
            }
        };

        // Send translated response to the HTLC interceptor for submission
        // to the cln rpc
        match outcome.send(htlca_res) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Failed to send htlc_accepted response to interceptor: {:?}",
                    e
                );
                return Err(ClnExtensionError::Error(anyhow!(
                    "Failed to send htlc_accepted response to interceptor"
                )));
            }
        };
    } else {
        error!(
            ?incoming_chan_id,
            ?htlc_id,
            "No interceptor reference found for this processed htlc",
        );
        return Err(ClnExtensionError::Error(anyhow!(
            "No interceptor reference found for this processed htlc"
        )));
    }
    Ok(Json(()))
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_create_invoice(
    Extension(cln_service): Extension<ClnRpcService>,
    Json(payload): Json<CreateInvoiceRequest>,
) -> Result<Json<CreateInvoiceResponse>, ClnExtensionError> {
    let CreateInvoiceRequest {
        payment_hash,
        amount_msat,
        expiry_secs,
        description,
    } = payload;

    let payment_hash = if let Some(payment_hash) = payment_hash {
        payment_hash
    } else {
        return cln_service
            .create_invoice_for_self(amount_msat, expiry_secs.into(), description)
            .await;
    };

    let description = description.ok_or(anyhow!("InvoiceDescription is None"))?;

    let info = cln_service.info().await?;

    let network = bitcoin32_to_bitcoin30_network(
        &bitcoin::Network::from_str(info.2.as_str())
            .map_err(|e| ClnExtensionError::Error(anyhow!(e)))?,
    );

    let invoice_builder = InvoiceBuilder::new(Currency::from(network))
        .amount_milli_satoshis(amount_msat)
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret(OsRng.gen()))
        .duration_since_epoch(fedimint_core::time::duration_since_epoch())
        .min_final_cltv_expiry_delta(18)
        .expiry_time(Duration::from_secs(expiry_secs.into()));

    let invoice_builder = match description {
        InvoiceDescription::Direct(description) => invoice_builder.invoice_description(
            lightning_invoice::Bolt11InvoiceDescription::Direct(
                &lightning_invoice::Description::new(description).expect("Description is valid"),
            ),
        ),
        InvoiceDescription::Hash(hash) => invoice_builder.invoice_description(
            lightning_invoice::Bolt11InvoiceDescription::Hash(&lightning_invoice::Sha256(hash)),
        ),
    };

    let invoice = invoice_builder
        // Temporarily sign with an ephemeral private key, we will request CLN to sign this
        // invoice next.
        .build_signed(|m| {
            bitcoin32_to_bitcoin30_recoverable_signature(&SECP256K1.sign_ecdsa_recoverable(
                &bitcoin30_to_bitcoin32_secp256k1_message(m),
                &SecretKey::new(&mut OsRng),
            ))
        })
        .map_err(|e| ClnExtensionError::Error(anyhow!(e)))?;

    let invstring = invoice.to_string();

    let response = cln_service
        .rpc_client()
        .await?
        .call(cln_rpc::Request::SignInvoice(
            model::requests::SigninvoiceRequest { invstring },
        ))
        .await
        .map(|response| match response {
            cln_rpc::Response::SignInvoice(model::responses::SigninvoiceResponse { bolt11 }) => {
                CreateInvoiceResponse { invoice: bolt11 }
            }
            _ => unreachable!("Unexpected response from SignInvoice"),
        })?;

    Ok(Json(response))
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_ln_onchain_address(
    Extension(cln_service): Extension<ClnRpcService>,
) -> Result<Json<GetLnOnchainAddressResponse>, ClnExtensionError> {
    let address_or = cln_service
        .rpc_client()
        .await?
        .call(cln_rpc::Request::NewAddr(model::requests::NewaddrRequest {
            addresstype: None,
        }))
        .await
        .map(|response| match response {
            cln_rpc::Response::NewAddr(model::responses::NewaddrResponse { bech32, .. }) => bech32,
            _ => unreachable!("Unexpected response from NewAddr"),
        })?;

    Ok(Json(GetLnOnchainAddressResponse {
        address: address_or.expect("NewAddr did not return bech32 address"),
    }))
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_send_onchain(
    Extension(cln_service): Extension<ClnRpcService>,
    Json(payload): Json<SendOnchainPayload>,
) -> Result<Json<SendOnchainResponse>, ClnExtensionError> {
    let txid = cln_service
        .rpc_client()
        .await?
        .call(cln_rpc::Request::Withdraw(
            model::requests::WithdrawRequest {
                feerate: Some(cln_rpc::primitives::Feerate::PerKw(
                    // 1 vbyte = 4 weight units, so 250 vbytes = 1,000 weight units.
                    payload.fee_rate_sats_per_vbyte as u32 * 250,
                )),
                minconf: Some(0),
                utxos: None,
                destination: payload.address.assume_checked().to_string(),
                satoshi: match payload.amount {
                    BitcoinAmountOrAll::All => AmountOrAll::All,
                    BitcoinAmountOrAll::Amount(amount) => {
                        AmountOrAll::Amount(cln_rpc::primitives::Amount::from_sat(amount.to_sat()))
                    }
                },
            },
        ))
        .await
        .map(|response| match response {
            cln_rpc::Response::Withdraw(model::responses::WithdrawResponse { txid, .. }) => txid,
            _ => unreachable!("Unexpected response from Withdraw"),
        })?;

    Ok(Json(SendOnchainResponse { txid }))
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_open_channel(
    Extension(cln_service): Extension<ClnRpcService>,
    Json(payload): Json<OpenChannelPayload>,
) -> Result<Json<OpenChannelResponse>, ClnExtensionError> {
    cln_service
        .rpc_client()
        .await?
        .call(cln_rpc::Request::Connect(model::requests::ConnectRequest {
            id: format!("{}@{}", payload.pubkey, payload.host),
            host: None,
            port: None,
        }))
        .await?;

    let funding_txid = cln_service
        .rpc_client()
        .await?
        .call(cln_rpc::Request::FundChannel(
            model::requests::FundchannelRequest {
                id: bitcoin32_to_bitcoin30_secp256k1_pubkey(&payload.pubkey),
                amount: cln_rpc::primitives::AmountOrAll::Amount(
                    cln_rpc::primitives::Amount::from_sat(payload.channel_size_sats),
                ),
                feerate: None,
                announce: None,
                minconf: None,
                push_msat: Some(cln_rpc::primitives::Amount::from_sat(
                    payload.push_amount_sats,
                )),
                close_to: None,
                request_amt: None,
                compact_lease: None,
                utxos: None,
                mindepth: None,
                reserve: None,
                channel_type: None,
            },
        ))
        .await
        .map(|response| match response {
            cln_rpc::Response::FundChannel(model::responses::FundchannelResponse {
                txid, ..
            }) => txid,
            _ => unreachable!("Unexpected response from FundChannel"),
        })?;

    Ok(Json(OpenChannelResponse { funding_txid }))
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_close_channels_with_peer(
    Extension(cln_service): Extension<ClnRpcService>,
    Json(payload): Json<CloseChannelsWithPeerPayload>,
) -> Result<Json<CloseChannelsWithPeerResponse>, ClnExtensionError> {
    let channels_with_peer: Vec<ListpeerchannelsChannels> = cln_service
        .rpc_client()
        .await?
        .call(cln_rpc::Request::ListPeerChannels(
            model::requests::ListpeerchannelsRequest {
                id: Some(bitcoin32_to_bitcoin30_secp256k1_pubkey(&payload.pubkey)),
            },
        ))
        .await
        .map(|response| match response {
            cln_rpc::Response::ListPeerChannels(model::responses::ListpeerchannelsResponse {
                channels,
            }) => channels
                .into_iter()
                .filter(|channel| {
                    channel.state
                        == model::responses::ListpeerchannelsChannelsState::CHANNELD_NORMAL
                })
                .collect(),
            _ => unreachable!("Unexpected response from ListPeerChannels"),
        })?;

    for channel_id in channels_with_peer
        .iter()
        .filter_map(|channel| channel.channel_id)
    {
        cln_service
            .rpc_client()
            .await?
            .call(cln_rpc::Request::Close(model::requests::CloseRequest {
                id: channel_id.to_string(),
                unilateraltimeout: None,
                destination: None,
                fee_negotiation_step: None,
                wrong_funding: None,
                force_lease_closed: None,
                feerange: None,
            }))
            .await
            .map_err(ClnExtensionError::RpcError)?;
    }

    Ok(Json(CloseChannelsWithPeerResponse {
        num_channels_closed: channels_with_peer.len() as u32,
    }))
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_list_active_channels(
    Extension(cln_service): Extension<ClnRpcService>,
) -> Result<Json<ListActiveChannelsResponse>, ClnExtensionError> {
    let channels = cln_service
        .rpc_client()
        .await?
        .call(cln_rpc::Request::ListPeerChannels(
            model::requests::ListpeerchannelsRequest { id: None },
        ))
        .await
        .map(|response| match response {
            cln_rpc::Response::ListPeerChannels(model::responses::ListpeerchannelsResponse {
                channels,
            }) => channels
                .into_iter()
                .filter_map(|channel| {
                    if channel.peer_connected
                        && matches!(
                            channel.state,
                            model::responses::ListpeerchannelsChannelsState::CHANNELD_NORMAL
                        )
                    {
                        Some(ln_gateway::lightning::ChannelInfo {
                            remote_pubkey: bitcoin30_to_bitcoin32_secp256k1_pubkey(
                                &channel.peer_id,
                            ),
                            channel_size_sats: channel
                                .total_msat
                                .map(|value| value.msat() / 1000)
                                .unwrap_or(0),
                            outbound_liquidity_sats: channel
                                .spendable_msat
                                .map(|value| value.msat() / 1000)
                                .unwrap_or(0),
                            inbound_liquidity_sats: channel
                                .receivable_msat
                                .map(|value| value.msat() / 1000)
                                .unwrap_or(0),
                            short_channel_id: match channel.short_channel_id {
                                Some(scid) => scid_to_u64(scid),
                                None => return None,
                            },
                        })
                    } else {
                        None
                    }
                })
                .collect(),
            _ => unreachable!("Unexpected response from ListPeerChannels"),
        })?;

    Ok(Json(ListActiveChannelsResponse { channels }))
}

#[instrument(skip_all, err)]
#[axum_macros::debug_handler]
async fn cln_get_balances(
    Extension(cln_service): Extension<ClnRpcService>,
) -> Result<Json<GetBalancesResponse>, ClnExtensionError> {
    let (channels, outputs) = cln_service
        .rpc_client()
        .await?
        .call(cln_rpc::Request::ListFunds(
            model::requests::ListfundsRequest { spent: None },
        ))
        .await
        .map(|response| match response {
            cln_rpc::Response::ListFunds(model::responses::ListfundsResponse {
                channels,
                outputs,
            }) => (channels, outputs),
            _ => unreachable!("Unexpected response from ListFunds"),
        })?;

    let channels = channels
        .iter()
        .filter(|chan| chan.connected && matches!(chan.state, ChannelState::CHANNELD_NORMAL))
        .collect::<Vec<_>>();

    let total_receivable_msat = cln_service
        .rpc_client()
        .await?
        .call(cln_rpc::Request::ListPeerChannels(
            model::requests::ListpeerchannelsRequest { id: None },
        ))
        .await
        .map(|response| match response {
            cln_rpc::Response::ListPeerChannels(model::responses::ListpeerchannelsResponse {
                channels,
            }) => channels
                .into_iter()
                .filter(|channel| {
                    matches!(
                        channel.state,
                        model::responses::ListpeerchannelsChannelsState::CHANNELD_NORMAL
                    ) && channel.peer_connected
                })
                .filter_map(|channel| channel.receivable_msat.map(|value| value.msat()))
                .sum::<u64>(), // Sum the receivable_msat values directly
            _ => unreachable!("Unexpected response from ListPeerChannels"),
        })?;

    let lightning_balance_msats = channels
        .into_iter()
        .fold(0, |acc, channel| acc + channel.our_amount_msat.msat());
    let onchain_balance_sats = outputs
        .into_iter()
        .fold(0, |acc, output| acc + output.amount_msat.msat() / 1000);

    Ok(Json(GetBalancesResponse {
        onchain_balance_sats,
        lightning_balance_msats,
        inbound_lightning_liquidity_msats: total_receivable_msat,
    }))
}

// TODO: upstream these structs to cln-plugin
// See: https://github.com/ElementsProject/lightning/blob/master/doc/PLUGINS.md#htlc_accepted
#[derive(Clone, Serialize, Deserialize, Debug)]
struct Htlc {
    amount_msat: Amount,
    // TODO: use these to validate we can actually redeem the HTLC in time
    cltv_expiry: u32,
    cltv_expiry_relative: u32,
    payment_hash: bitcoin_hashes::sha256::Hash,
    // The short channel id of the incoming channel
    short_channel_id: String,
    // The ID of the HTLC
    id: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct Onion {
    #[serde(default)]
    short_channel_id: Option<String>,
    forward_msat: Amount,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct HtlcAccepted {
    htlc: Htlc,
    onion: Onion,
}

#[derive(Clone)]
struct ClnRpcService {
    socket: PathBuf,
}

impl ClnRpcService {
    async fn new(
        extension_opts: ClnExtensionOpts,
    ) -> Result<
        (
            Self,
            Arc<ClnHtlcInterceptor>,
            SocketAddr,
            Plugin<Arc<ClnHtlcInterceptor>>,
        ),
        ClnExtensionError,
    > {
        let interceptor = Arc::new(ClnHtlcInterceptor::new());

        if let Some(plugin) = Builder::new(stdin(), stdout())
            .option(FM_CLN_EXTENSION_LISTEN_ADDRESS_CONFIG_OPTION)
            .hook(
                "htlc_accepted",
                |plugin: Plugin<Arc<ClnHtlcInterceptor>>, value: serde_json::Value| async move {
                    let payload: HtlcAccepted = serde_json::from_value(value)?;
                    Ok(plugin.state().intercept_htlc(payload).await)
                },
            )
            // Shutdown the plugin when lightningd is shutting down or when the plugin is stopped
            // via `plugin stop` command. There's a chance that the subscription is never called in
            // case lightningd crashes or aborts.
            // For details, see documentation for `shutdown` event notification:
            // https://lightning.readthedocs.io/PLUGINS.html?highlight=shutdown#shutdown
            .subscribe(
                "shutdown",
                |plugin: Plugin<Arc<ClnHtlcInterceptor>>, _: serde_json::Value| async move {
                    info!("Received \"shutdown\" notification from lightningd ... requesting cln_plugin shutdown");
                    plugin.shutdown()
                },
            )
            .dynamic() // Allow reloading the plugin
            .start(interceptor.clone())
            .await?
        {
            let config = plugin.configuration();
            let socket = PathBuf::from(config.lightning_dir).join(config.rpc_file);

            // Parse configurations or read from
            let fm_gateway_listen = match extension_opts.fm_gateway_listen {
                Some(addr) => addr,
                None => {
                    #[allow(clippy::expect_fun_call)]
                    let listen = plugin.option(&FM_CLN_EXTENSION_LISTEN_ADDRESS_CONFIG_OPTION).ok().flatten()
                        .expect(&format!("Gateway CLN extension is missing a listen address configuration.
                            You can set it via FM_CLN_EXTENSION_LISTEN_ADDRESS env variable, or by adding
                            a --{FM_CLN_EXTENSION_LISTEN_ADDRESS_CLI_ARG} config option to the CLN plugin."));

                    #[allow(clippy::expect_fun_call)]
                    SocketAddr::from_str(&listen).expect(&format!("invalid {FM_CLN_EXTENSION_LISTEN_ADDRESS_CLI_ARG} address"))
                }
            };

            Ok((
                Self {
                    socket,
                },
                interceptor,
                fm_gateway_listen,
                plugin,
            ))
        } else {
            Err(ClnExtensionError::Error(anyhow!(
                "Failed to start cln plugin - another instance of lightningd may already be running."
            )))
        }
    }

    /// Creates a new RPC client for a request.
    ///
    /// This operation is cheap enough to do it for each request since it merely
    /// connects to a UNIX domain socket without doing any further
    /// initialization.
    async fn rpc_client(&self) -> Result<cln_rpc::ClnRpc, ClnExtensionError> {
        cln_rpc::ClnRpc::new(&self.socket).await.map_err(|err| {
            let e = format!("Could not connect to CLN RPC socket: {err}");
            error!(e);
            ClnExtensionError::Error(anyhow!(e))
        })
    }

    async fn info(&self) -> Result<(PublicKey, String, String, u32, bool), ClnExtensionError> {
        self.rpc_client()
            .await?
            .call(cln_rpc::Request::Getinfo(
                model::requests::GetinfoRequest {},
            ))
            .await
            .map(|response| match response {
                cln_rpc::Response::Getinfo(model::responses::GetinfoResponse {
                    id,
                    alias,
                    network,
                    blockheight,
                    warning_bitcoind_sync,
                    warning_lightningd_sync,
                    ..
                }) => {
                    // FIXME: How to handle missing alias?
                    let alias = alias.unwrap_or_default();
                    let synced_to_chain =
                        warning_bitcoind_sync.is_none() && warning_lightningd_sync.is_none();
                    (
                        bitcoin30_to_bitcoin32_secp256k1_pubkey(&id),
                        alias,
                        network,
                        blockheight,
                        synced_to_chain,
                    )
                }
                _ => unreachable!("Unexpected response from Getinfo"),
            })
            .map_err(ClnExtensionError::RpcError)
    }

    /// Requests a route for a payment. Payment route will be passed to
    /// `pay_with_route` to initiate the payment.
    async fn get_route(
        &self,
        pruned_invoice: PrunedInvoice,
        riskfactor: u64,
        excluded_nodes: Vec<String>,
    ) -> Result<Vec<SendpayRoute>, ClnExtensionError> {
        let response = self
            .rpc_client()
            .await?
            .call(cln_rpc::Request::GetRoute(
                model::requests::GetrouteRequest {
                    id: bitcoin32_to_bitcoin30_secp256k1_pubkey(&pruned_invoice.destination),
                    amount_msat: cln_rpc::primitives::Amount::from_msat(
                        pruned_invoice.amount.msats,
                    ),
                    riskfactor,
                    cltv: Some(pruned_invoice.min_final_cltv_delta as u32),
                    fromid: None,
                    fuzzpercent: None,
                    exclude: Some(excluded_nodes),
                    maxhops: None,
                },
            ))
            .await?;

        match response {
            cln_rpc::Response::GetRoute(model::responses::GetrouteResponse { route }) => Ok(route
                .into_iter()
                .map(|r| SendpayRoute {
                    amount_msat: r.amount_msat,
                    id: r.id,
                    delay: r.delay,
                    channel: r.channel,
                })
                .collect::<Vec<_>>()),
            _ => unreachable!("Unexpected response from GetRoute"),
        }
    }

    /// Initiates a payment of a pruned invoice given a payment route. Waits for
    /// the payment to be successful or return an error.
    async fn pay_with_route(
        &self,
        pruned_invoice: PrunedInvoice,
        payment_hash: sha256::Hash,
        route: Vec<SendpayRoute>,
    ) -> Result<Vec<u8>, ClnExtensionError> {
        let payment_secret = Some(
            cln_rpc::primitives::Secret::try_from(pruned_invoice.payment_secret.to_vec())
                .map_err(ClnExtensionError::Error)?,
        );
        let amount_msat = Some(cln_rpc::primitives::Amount::from_msat(
            pruned_invoice.amount.msats,
        ));

        info!(
            ?payment_hash,
            ?amount_msat,
            "Attempting to pay pruned invoice..."
        );

        let response = self
            .rpc_client()
            .await?
            .call(cln_rpc::Request::SendPay(model::requests::SendpayRequest {
                amount_msat,
                bolt11: None,
                description: None,
                groupid: None,
                label: None,
                localinvreqid: None,
                partid: None,
                payment_metadata: None,
                payment_secret,
                payment_hash,
                route,
            }))
            .await?;

        let status = match response {
            cln_rpc::Response::SendPay(model::responses::SendpayResponse { status, .. }) => status,
            _ => unreachable!("Unexpected response from Sendpay"),
        };

        info!(?payment_hash, ?status, "Initiated payment");

        let response = self
            .rpc_client()
            .await?
            .call(cln_rpc::Request::WaitSendPay(
                model::requests::WaitsendpayRequest {
                    groupid: None,
                    partid: None,
                    timeout: None,
                    payment_hash,
                },
            ))
            .await;

        let (preimage, amount_sent_msat) = match response {
            Ok(cln_rpc::Response::WaitSendPay(model::responses::WaitsendpayResponse {
                payment_preimage,
                amount_sent_msat,
                ..
            })) => Ok((payment_preimage, amount_sent_msat)),
            Err(e)
                if e.code.is_some() && e.code.expect("Already checked") == FAILURE_ALONG_ROUTE =>
            {
                match e.data {
                    Some(route_failure) => {
                        let erring_node = route_failure
                            .get("erring_node")
                            .expect("Route failure object did not have erring_node field")
                            .to_string();
                        Err(ClnExtensionError::FailedPayment { erring_node })
                    }
                    None => {
                        error!(?e, "Returned RpcError did not contain route failure object");
                        Err(ClnExtensionError::RpcError(e))
                    }
                }
            }
            Err(e) => Err(ClnExtensionError::RpcError(e)),
            _ => unreachable!("Unexpected response from WaitSendPay"),
        }?;

        info!(
            ?preimage,
            ?payment_hash,
            ?amount_sent_msat,
            "Finished payment"
        );

        let preimage = preimage.ok_or_else(|| {
            error!(?payment_hash, "WaitSendPay did not return a preimage");
            ClnExtensionError::Error(anyhow!("WaitSendPay did not return a preimage"))
        })?;
        Ok(preimage.to_vec())
    }

    /// Creates an invoice with a preimage that is generated by CLN.
    /// This invoice can be used to receive payments directly to the node.
    async fn create_invoice_for_self(
        &self,
        amount_msat: u64,
        expiry_secs: u64,
        description_or: Option<InvoiceDescription>,
    ) -> Result<Json<CreateInvoiceResponse>, ClnExtensionError> {
        let description = match description_or {
            Some(InvoiceDescription::Direct(desc)) => desc,
            Some(InvoiceDescription::Hash(_)) => {
                return Err(ClnExtensionError::Error(anyhow!(
                    "create_invoice_for_self does not support description hashes"
                )))
            }
            None => String::new(),
        };

        let response = self
            .rpc_client()
            .await?
            .call(cln_rpc::Request::Invoice(model::requests::InvoiceRequest {
                cltv: None,
                deschashonly: None,
                expiry: Some(expiry_secs),
                preimage: None,
                exposeprivatechannels: None,
                fallbacks: None,
                amount_msat: cln_rpc::primitives::AmountOrAny::Amount(
                    cln_rpc::primitives::Amount::from_msat(amount_msat),
                ),
                description,
                label: format!("{:?}", fedimint_core::time::now()),
            }))
            .await
            .map(|response| match response {
                cln_rpc::Response::Invoice(model::responses::InvoiceResponse {
                    bolt11, ..
                }) => CreateInvoiceResponse { invoice: bolt11 },
                _ => unreachable!("Unexpected response from Invoice"),
            })?;

        Ok(Json(response))
    }
}

#[derive(Debug, Error)]
enum ClnExtensionError {
    #[error("Gateway CLN Extension Error : {0:?}")]
    Error(#[from] anyhow::Error),
    #[error("Gateway CLN Extension Error : {0:?}")]
    RpcError(#[from] cln_rpc::RpcError),
    #[error("Gateway CLN Extension failed payment")]
    FailedPayment { erring_node: String },
}

impl IntoResponse for ClnExtensionError {
    fn into_response(self) -> axum::response::Response {
        error!("{self}");
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(self.to_string().into())
            .expect("Failed to create Response")
    }
}

// TODO: upstream
fn scid_to_u64(scid: ShortChannelId) -> u64 {
    let mut scid_num = scid.outnum() as u64;
    scid_num |= (scid.txindex() as u64) << 16;
    scid_num |= (scid.block() as u64) << 40;
    scid_num
}

type HtlcInterceptionSender = mpsc::Sender<InterceptPaymentRequest>;
type HtlcOutcomeSender = oneshot::Sender<serde_json::Value>;

/// Functional structure to filter intercepted HTLCs into subscription streams.
/// Used as a CLN plugin
#[derive(Clone)]
struct ClnHtlcInterceptor {
    outcomes: Arc<Mutex<BTreeMap<(u64, u64), HtlcOutcomeSender>>>,
    sender: Arc<Mutex<Option<HtlcInterceptionSender>>>,
}

impl ClnHtlcInterceptor {
    fn new() -> Self {
        Self {
            outcomes: Arc::new(Mutex::new(BTreeMap::new())),
            sender: Arc::new(Mutex::new(None)),
        }
    }

    fn convert_short_channel_id(scid: &str) -> Result<u64, anyhow::Error> {
        match ShortChannelId::from_str(scid) {
            Ok(scid) => Ok(scid_to_u64(scid)),
            Err(_) => Err(anyhow::anyhow!(
                "Received invalid short channel id: {:?}",
                scid
            )),
        }
    }

    async fn intercept_htlc(&self, payload: HtlcAccepted) -> serde_json::Value {
        info!(?payload, "Intercepted htlc with payload");

        let htlc_expiry = payload.htlc.cltv_expiry;

        let short_channel_id = match payload.onion.short_channel_id {
            Some(scid) => {
                if let Ok(short_channel_id) = Self::convert_short_channel_id(&scid) {
                    Some(short_channel_id)
                } else {
                    return serde_json::json!({ "result": "continue" });
                }
            }
            None => {
                // This HTLC terminates at the gateway node. Ask gatewayd if there is a preimage
                // available (for LNv2)
                None
            }
        };

        info!(?short_channel_id, "Intercepted htlc with SCID");

        // Clone the sender to avoid holding the lock while sending the HTLC
        let sender = self.sender.lock().await.clone();
        if let Some(sender) = sender {
            let incoming_chan_id =
                match Self::convert_short_channel_id(payload.htlc.short_channel_id.as_str()) {
                    Ok(scid) => scid,
                    // Failed to parse incoming_chan_id, just forward the HTLC
                    Err(_) => return serde_json::json!({ "result": "continue" }),
                };

            let htlc_ret = match sender
                .send(InterceptPaymentRequest {
                    payment_hash: payload.htlc.payment_hash,
                    amount_msat: payload.onion.forward_msat.msats,
                    expiry: htlc_expiry,
                    short_channel_id,
                    incoming_chan_id,
                    htlc_id: payload.htlc.id,
                })
                .await
            {
                Ok(_) => {
                    // Open a channel to receive the outcome of the HTLC processing
                    let (sender, receiver) = oneshot::channel::<serde_json::Value>();
                    self.outcomes
                        .lock()
                        .await
                        .insert((incoming_chan_id, payload.htlc.id), sender);

                    // If the gateway does not respond within the HTLC expiry,
                    // Automatically respond with a failure message.
                    tokio::time::timeout(MAX_HTLC_PROCESSING_DURATION, async {
                        receiver.await.unwrap_or_else(|e| {
                            error!("Failed to receive outcome of intercepted htlc: {e:?}");
                            serde_json::json!({ "result": "continue" })
                        })
                    })
                    .await
                    .unwrap_or_else(|e| {
                        error!("await_htlc_processing error {e:?}");
                        serde_json::json!({ "result": "continue" })
                    })
                }
                Err(e) => {
                    error!("Failed to send htlc to subscription: {e:?}");
                    serde_json::json!({ "result": "continue" })
                }
            };

            return htlc_ret;
        }

        // We have no subscription for this HTLC.
        // Ignore it by requesting the node to continue
        serde_json::json!({ "result": "continue" })
    }

    // TODO: Add a method to remove a HTLC subscriber
}
