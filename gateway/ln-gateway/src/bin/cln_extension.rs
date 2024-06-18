use std::array::TryFromSliceError;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use bitcoin_hashes::{sha256, Hash};
use clap::Parser;
use cln_plugin::{options, Builder, Plugin};
use cln_rpc::model;
use cln_rpc::model::requests::SendpayRoute;
use cln_rpc::model::responses::ListpeerchannelsChannels;
use cln_rpc::primitives::ShortChannelId;
use fedimint_core::secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::handle_version_hash_command;
use fedimint_core::{fedimint_build_code_version_env, Amount};
use hex::ToHex;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use ln_gateway::envs::FM_CLN_EXTENSION_LISTEN_ADDRESS_ENV;
use ln_gateway::gateway_lnrpc::create_invoice_request::Description;
use ln_gateway::gateway_lnrpc::gateway_lightning_server::{
    GatewayLightning, GatewayLightningServer,
};
use ln_gateway::gateway_lnrpc::get_route_hints_response::{RouteHint, RouteHintHop};
use ln_gateway::gateway_lnrpc::intercept_htlc_response::{Action, Cancel, Forward, Settle};
use ln_gateway::gateway_lnrpc::list_active_channels_response::ChannelInfo;
use ln_gateway::gateway_lnrpc::{
    CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, CreateInvoiceRequest,
    CreateInvoiceResponse, EmptyRequest, EmptyResponse, GetFundingAddressResponse,
    GetNodeInfoResponse, GetRouteHintsRequest, GetRouteHintsResponse, InterceptHtlcRequest,
    InterceptHtlcResponse, ListActiveChannelsResponse, OpenChannelRequest, PayInvoiceRequest,
    PayInvoiceResponse, PayPrunedInvoiceRequest, PrunedInvoice,
};
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{stdin, stdout};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::Status;
use tracing::{debug, error, info, warn};

const MAX_HTLC_PROCESSING_DURATION: Duration = Duration::MAX;
// Attempt to get 10 different payment routes before returning an error
const MAX_ROUTE_ATTEMPTS: u32 = 10;
// Use a `riskfactor` of 10, which is the default for lightning-pay
const ROUTE_RISK_FACTOR: u64 = 10;

#[derive(Parser)]
#[command(version)]
struct ClnExtensionOpts {
    /// Gateway CLN extension service listen address
    #[arg(long = "fm-gateway-listen", env = FM_CLN_EXTENSION_LISTEN_ADDRESS_ENV)]
    fm_gateway_listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    handle_version_hash_command(fedimint_build_code_version_env!());

    let (service, listen, plugin) = ClnRpcService::new()
        .await
        .expect("Failed to create cln rpc service");

    debug!(
        "Starting gateway-cln-extension with listen address : {}",
        listen
    );

    Server::builder()
        .add_service(GatewayLightningServer::new(service))
        .serve_with_shutdown(listen, async {
            // Wait for plugin to signal it's shutting down
            // Shut down everything else via TaskGroup regardless of error
            let _ = plugin.join().await;
            // lightningd needs to see exit code 0 to notice the plugin has
            // terminated -- even if we return from main().
            std::process::exit(0);
        })
        .await
        .map_err(|e| ClnExtensionError::Error(anyhow!("Failed to start server, {:?}", e)))?;

    Ok(())
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

#[allow(dead_code)]
struct ClnRpcService {
    socket: PathBuf,
    interceptor: Arc<ClnHtlcInterceptor>,
    task_group: TaskGroup,
    secp: Secp256k1<All>,
}

impl ClnRpcService {
    async fn new() -> Result<(Self, SocketAddr, Plugin<Arc<ClnHtlcInterceptor>>), ClnExtensionError>
    {
        let interceptor = Arc::new(ClnHtlcInterceptor::new());

        if let Some(plugin) = Builder::new(stdin(), stdout())
            .option(options::ConfigOption::new(
                "fm-gateway-listen",
                // Set an invalid default address in the extension to force the extension plugin
                // user to supply a valid address via an environment variable or
                // cln plugin config option.
                options::Value::OptString,
                "fedimint gateway CLN extension listen address",
            ))
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
            let fm_gateway_listen: SocketAddr = match ClnExtensionOpts::try_parse() {
                Ok(opts) => opts.fm_gateway_listen,
                Err(_) => {

                    let listen_val = plugin.option("fm-gateway-listen")
                        .expect("Gateway CLN extension is missing a listen address configuration.
                        You can set it via FM_CLN_EXTENSION_LISTEN_ADDRESS env variable, or by adding
                        a --fm-gateway-listen config option to the CLN plugin.");
                    let listen = listen_val.as_str()
                        .expect("fm-gateway-listen isn't a string");

                    SocketAddr::from_str(listen).expect("invalid fm-gateway-listen address")
                }
            };

            Ok((
                Self {
                    socket,
                    interceptor,
                    task_group: TaskGroup::new(),
                    secp: Secp256k1::gen_new(),
                },
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
                    Ok((id, alias, network, blockheight, synced_to_chain))
                }
                _ => Err(ClnExtensionError::RpcWrongResponse),
            })
            .map_err(ClnExtensionError::RpcError)?
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
                    id: PublicKey::from_slice(&pruned_invoice.destination)
                        .expect("Should parse public key"),
                    amount_msat: cln_rpc::primitives::Amount::from_msat(pruned_invoice.amount_msat),
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
            _ => Err(ClnExtensionError::RpcWrongResponse),
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
            cln_rpc::primitives::Secret::try_from(pruned_invoice.payment_secret)
                .map_err(ClnExtensionError::Error)?,
        );
        let amount_msat = Some(cln_rpc::primitives::Amount::from_msat(
            pruned_invoice.amount_msat,
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
            cln_rpc::Response::SendPay(model::responses::SendpayResponse { status, .. }) => {
                Ok(status)
            }
            _ => Err(ClnExtensionError::RpcWrongResponse),
        }?;

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
            .await?;

        let (preimage, amount_sent_msat) = match response {
            cln_rpc::Response::WaitSendPay(model::responses::WaitsendpayResponse {
                payment_preimage,
                amount_sent_msat,
                ..
            }) => Ok((payment_preimage, amount_sent_msat)),
            _ => Err(ClnExtensionError::RpcWrongResponse),
        }?;

        info!(
            ?preimage,
            ?payment_hash,
            ?amount_sent_msat,
            "Finished payment"
        );

        let preimage = preimage.ok_or_else(|| {
            error!(?payment_hash, "WaitSendPay did not return a preimage");
            ClnExtensionError::RpcWrongResponse
        })?;
        Ok(preimage.to_vec())
    }
}

#[tonic::async_trait]
impl GatewayLightning for ClnRpcService {
    async fn get_node_info(
        &self,
        _request: tonic::Request<EmptyRequest>,
    ) -> Result<tonic::Response<GetNodeInfoResponse>, Status> {
        self.info()
            .await
            .map(|(pub_key, alias, network, block_height, synced_to_chain)| {
                tonic::Response::new(GetNodeInfoResponse {
                    pub_key: pub_key.serialize().to_vec(),
                    alias,
                    network,
                    block_height,
                    synced_to_chain,
                })
            })
            .map_err(|e| {
                error!("cln getinfo returned error: {:?}", e);
                Status::internal(e.to_string())
            })
    }

    async fn get_route_hints(
        &self,
        request: tonic::Request<GetRouteHintsRequest>,
    ) -> Result<tonic::Response<GetRouteHintsResponse>, Status> {
        let GetRouteHintsRequest { num_route_hints } = request.into_inner();
        let node_info = self
            .info()
            .await
            .map_err(|err| tonic::Status::internal(err.to_string()))?;

        let mut client = self
            .rpc_client()
            .await
            .map_err(|err| tonic::Status::internal(err.to_string()))?;

        let active_peer_channels_response = client
            .call(cln_rpc::Request::ListPeerChannels(
                model::requests::ListpeerchannelsRequest { id: None },
            ))
            .await
            .map_err(|err| tonic::Status::internal(err.to_string()))?;

        let mut active_peer_channels = match active_peer_channels_response {
            cln_rpc::Response::ListPeerChannels(channels) => Ok(channels.channels),
            _ => Err(ClnExtensionError::RpcWrongResponse),
        }
        .map_err(|err| tonic::Status::internal(err.to_string()))?
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
            .await
            .map_err(|err| tonic::Status::internal(err.to_string()))?;
        let pubkey_to_incoming_capacity = match listfunds_response {
            cln_rpc::Response::ListFunds(listfunds) => listfunds
                .channels
                .into_iter()
                .map(|chan| (chan.peer_id, chan.amount_msat - chan.our_amount_msat))
                .collect::<HashMap<_, _>>(),
            err => panic!("CLN received unexpected response: {err:?}"),
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
                .await
                .map_err(|err| tonic::Status::internal(err.to_string()))?;

            let channel = match channels_response {
                cln_rpc::Response::ListChannels(channels) => {
                    let Some(channel) = channels
                        .channels
                        .into_iter()
                        .find(|chan| chan.destination == node_info.0)
                    else {
                        warn!(?scid, "Channel not found in graph");
                        continue;
                    };
                    Ok(channel)
                }
                _ => Err(ClnExtensionError::RpcWrongResponse),
            }
            .map_err(|err| tonic::Status::internal(err.to_string()))?;

            let route_hint_hop = RouteHintHop {
                src_node_id: peer_id.serialize().to_vec(),
                short_channel_id: scid_to_u64(scid),
                base_msat: channel.base_fee_millisatoshi,
                proportional_millionths: channel.fee_per_millionth,
                cltv_expiry_delta: channel.delay,
                htlc_minimum_msat: Some(channel.htlc_minimum_msat.msat()),
                htlc_maximum_msat: channel.htlc_maximum_msat.map(|amt| amt.msat()),
            };

            debug!("Constructed route hint {:?}", route_hint_hop);
            route_hints.push(RouteHint {
                hops: vec![route_hint_hop],
            });
        }

        Ok(tonic::Response::new(GetRouteHintsResponse { route_hints }))
    }

    async fn pay_invoice(
        &self,
        request: tonic::Request<PayInvoiceRequest>,
    ) -> Result<tonic::Response<PayInvoiceResponse>, tonic::Status> {
        let PayInvoiceRequest {
            invoice,
            max_delay,
            max_fee_msat,
            payment_hash: _,
        } = request.into_inner();

        let outcome = self
            .rpc_client()
            .await
            .map_err(|e| Status::internal(e.to_string()))?
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
                }) => Ok(PayInvoiceResponse {
                    preimage: payment_preimage.to_vec(),
                }),
                _ => Err(ClnExtensionError::RpcWrongResponse),
            })
            .map_err(|e| {
                error!("cln pay rpc returned error {:?}", e);
                tonic::Status::internal(e.to_string())
            })?
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(outcome))
    }

    async fn pay_pruned_invoice(
        &self,
        request: tonic::Request<PayPrunedInvoiceRequest>,
    ) -> Result<tonic::Response<PayInvoiceResponse>, tonic::Status> {
        let PayPrunedInvoiceRequest {
            pruned_invoice,
            max_delay,
            max_fee_msat,
        } = request.into_inner();

        let pruned_invoice = pruned_invoice
            .ok_or_else(|| tonic::Status::internal("Pruned Invoice was not supplied"))?;
        let payment_hash = sha256::Hash::from_slice(&pruned_invoice.payment_hash)
            .map_err(|err| tonic::Status::internal(err.to_string()))?;
        let destination =
            PublicKey::from_slice(&pruned_invoice.destination).expect("Should parse public key");

        let mut excluded_nodes = vec![];

        for route_attempt in 0..MAX_ROUTE_ATTEMPTS {
            let route = self
                .get_route(
                    pruned_invoice.clone(),
                    ROUTE_RISK_FACTOR,
                    excluded_nodes.clone(),
                )
                .await
                .map_err(|err| tonic::Status::internal(err.to_string()))?;

            // Verify `max_delay` is greater than the worst case timeout for the payment
            // failure in blocks
            let delay = route
                .first()
                .ok_or_else(|| {
                    tonic::Status::internal(format!(
                        "Returned route did not have any hops for payment_hash: {payment_hash}"
                    ))
                })?
                .delay;
            if max_delay < delay.into() {
                return Err(tonic::Status::internal(format!("Worst case timeout for the payment is too long. max_delay: {max_delay} delay: {delay} payment_hash: {payment_hash}")));
            }

            // Verify the total fee is less than `max_fee_msat`
            let first_hop_amount = route
                .first()
                .ok_or_else(|| {
                    tonic::Status::internal(format!(
                        "Returned route did not have any hops for payment_hash: {payment_hash}"
                    ))
                })?
                .amount_msat;
            let last_hop_amount = route
                .last()
                .ok_or_else(|| {
                    tonic::Status::internal(format!(
                        "Returned route did not have any hops for payment_hash: {payment_hash}"
                    ))
                })?
                .amount_msat;
            let fee = first_hop_amount - last_hop_amount;
            if max_fee_msat < fee.msat() {
                return Err(tonic::Status::internal(format!(
                    "Fee: {} for payment {payment_hash} is greater than max_fee_msat: {max_fee_msat}",
                    fee.msat()
                )));
            }

            debug!(
                ?route_attempt,
                ?payment_hash,
                ?route,
                "Attempting payment with route"
            );
            match self
                .pay_with_route(pruned_invoice.clone(), payment_hash, route.clone())
                .await
            {
                Ok(preimage) => {
                    let response = PayInvoiceResponse { preimage };
                    return Ok(tonic::Response::new(response));
                }
                Err(e) => {
                    error!(
                        ?route_attempt,
                        ?payment_hash,
                        ?e,
                        "Pruned invoice payment attempt failure"
                    );
                    let mut failed_nodes = route
                        .into_iter()
                        .filter_map(|r| {
                            // Do not exclude the destination node
                            if r.id != destination {
                                Some(r.id.to_string())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();
                    excluded_nodes.append(&mut failed_nodes);
                }
            }
        }

        Err(tonic::Status::internal(format!(
            "Payment exhausted max route attempts: {MAX_ROUTE_ATTEMPTS}"
        )))
    }

    type RouteHtlcsStream = ReceiverStream<Result<InterceptHtlcRequest, Status>>;

    async fn route_htlcs(
        &self,
        _: tonic::Request<EmptyRequest>,
    ) -> Result<tonic::Response<Self::RouteHtlcsStream>, Status> {
        // First create new channel that we will use to send responses back to gatewayd
        let (gatewayd_sender, gatewayd_receiver) =
            mpsc::channel::<Result<InterceptHtlcRequest, Status>>(100);

        let mut sender = self.interceptor.sender.lock().await;
        *sender = Some(gatewayd_sender.clone());
        debug!("Gateway channel sender replaced");

        Ok(tonic::Response::new(ReceiverStream::new(gatewayd_receiver)))
    }

    async fn complete_htlc(
        &self,
        intercept_response: tonic::Request<InterceptHtlcResponse>,
    ) -> Result<tonic::Response<EmptyResponse>, Status> {
        let InterceptHtlcResponse {
            action,
            incoming_chan_id,
            htlc_id,
            ..
        } = intercept_response.into_inner();

        if let Some(outcome) = self
            .interceptor
            .outcomes
            .lock()
            .await
            .remove(&(incoming_chan_id, htlc_id))
        {
            // Translate action request into a cln rpc response for
            // `htlc_accepted` event
            let htlca_res = match action {
                Some(Action::Settle(Settle { preimage })) => {
                    let assert_pk: Result<[u8; 32], TryFromSliceError> =
                        preimage.as_slice().try_into();
                    if let Ok(pk) = assert_pk {
                        serde_json::json!({ "result": "resolve", "payment_key": pk.encode_hex::<String>() })
                    } else {
                        htlc_processing_failure()
                    }
                }
                Some(Action::Cancel(Cancel { reason: _ })) => {
                    // TODO: Translate the reason into a BOLT 4 failure message
                    // See: https://github.com/lightning/bolts/blob/master/04-onion-routing.md#failure-messages
                    htlc_processing_failure()
                }
                Some(Action::Forward(Forward {})) => {
                    serde_json::json!({ "result": "continue" })
                }
                None => {
                    error!(
                        ?incoming_chan_id,
                        ?htlc_id,
                        "No action specified for intercepted htlc"
                    );
                    return Err(Status::internal(
                        "No action specified on this intercepted htlc",
                    ));
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
                    return Err(Status::internal(
                        "Failed to send htlc_accepted response to interceptor",
                    ));
                }
            };
        } else {
            error!(
                ?incoming_chan_id,
                ?htlc_id,
                "No interceptor reference found for this processed htlc",
            );
            return Err(Status::internal("No interceptor reference found for htlc"));
        }
        Ok(tonic::Response::new(EmptyResponse {}))
    }

    async fn create_invoice(
        &self,
        create_invoice_request: tonic::Request<CreateInvoiceRequest>,
    ) -> Result<tonic::Response<CreateInvoiceResponse>, Status> {
        let CreateInvoiceRequest {
            payment_hash,
            amount_msat,
            expiry,
            description,
        } = create_invoice_request.into_inner();

        let payment_hash = sha256::Hash::from_slice(&payment_hash)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        let duration_since_epoch = fedimint_core::time::duration_since_epoch();
        let description = description.ok_or(tonic::Status::internal(
            "Description or description hash was not provided".to_string(),
        ))?;
        let info = self
            .info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let network =
            Currency::from_str(info.2.as_str()).map_err(|e| Status::internal(e.to_string()))?;

        let invoice = match description {
            Description::Direct(description) => InvoiceBuilder::new(network)
                .amount_milli_satoshis(amount_msat)
                .invoice_description(lightning_invoice::Bolt11InvoiceDescription::Direct(
                    &lightning_invoice::Description::new(description)
                        .expect("Description is valid"),
                ))
                .payment_hash(payment_hash)
                .payment_secret(PaymentSecret(OsRng.gen()))
                .duration_since_epoch(duration_since_epoch)
                .min_final_cltv_expiry_delta(18)
                .expiry_time(Duration::from_secs(expiry.into()))
                // Temporarily sign with an ephemeral private key, we will request CLN to sign this
                // invoice next.
                .build_signed(|m| {
                    self.secp
                        .sign_ecdsa_recoverable(m, &SecretKey::new(&mut OsRng))
                })
                .map_err(|e| Status::internal(e.to_string()))?,
            Description::Hash(hash) => InvoiceBuilder::new(network)
                .amount_milli_satoshis(amount_msat)
                .invoice_description(lightning_invoice::Bolt11InvoiceDescription::Hash(
                    &lightning_invoice::Sha256(
                        bitcoin_hashes::sha256::Hash::from_slice(&hash)
                            .expect("Couldnt create hash from description hash"),
                    ),
                ))
                .payment_hash(payment_hash)
                .payment_secret(PaymentSecret(OsRng.gen()))
                .duration_since_epoch(duration_since_epoch)
                .min_final_cltv_expiry_delta(18)
                .expiry_time(Duration::from_secs(expiry.into()))
                // Temporarily sign with an ephemeral private key, we will request CLN to sign this
                // invoice next.
                .build_signed(|m| {
                    self.secp
                        .sign_ecdsa_recoverable(m, &SecretKey::new(&mut OsRng))
                })
                .map_err(|e| Status::internal(e.to_string()))?,
        };

        let invstring = invoice.to_string();

        let response = self
            .rpc_client()
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .call(cln_rpc::Request::SignInvoice(
                model::requests::SigninvoiceRequest { invstring },
            ))
            .await
            .map(|response| match response {
                cln_rpc::Response::SignInvoice(model::responses::SigninvoiceResponse {
                    bolt11,
                    ..
                }) => Ok(CreateInvoiceResponse { invoice: bolt11 }),
                _ => Err(ClnExtensionError::RpcWrongResponse),
            })
            .map_err(|e| {
                error!("cln invoice returned error {e:?}");
                tonic::Status::internal(e.to_string())
            })?
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(response))
    }

    async fn get_funding_address(
        &self,
        _request: tonic::Request<EmptyRequest>,
    ) -> Result<tonic::Response<GetFundingAddressResponse>, Status> {
        let address_or = self
            .rpc_client()
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .call(cln_rpc::Request::NewAddr(model::requests::NewaddrRequest {
                addresstype: None,
            }))
            .await
            .map(|response| match response {
                cln_rpc::Response::NewAddr(model::responses::NewaddrResponse {
                    bech32, ..
                }) => Ok(bech32),
                _ => Err(ClnExtensionError::RpcWrongResponse),
            })
            .map_err(|e| {
                error!("cln newaddr rpc returned error {:?}", e);
                tonic::Status::internal(e.to_string())
            })?
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        match address_or {
            Some(address) => Ok(tonic::Response::new(GetFundingAddressResponse { address })),
            None => Err(Status::internal("cln newaddr rpc returned no address")),
        }
    }

    async fn open_channel(
        &self,
        request: tonic::Request<OpenChannelRequest>,
    ) -> Result<tonic::Response<EmptyResponse>, Status> {
        let request_inner = request.into_inner();

        self.rpc_client()
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .call(cln_rpc::Request::Connect(model::requests::ConnectRequest {
                id: format!("{}@{}", request_inner.pubkey, request_inner.host),
                host: None,
                port: None,
            }))
            .await
            .map_err(|e| {
                error!("cln connect rpc returned error {:?}", e);
                tonic::Status::internal(e.to_string())
            })?;

        self.rpc_client()
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .call(cln_rpc::Request::FundChannel(
                model::requests::FundchannelRequest {
                    id: cln_rpc::primitives::PublicKey::from_str(&request_inner.pubkey).map_err(
                        |e| {
                            error!("cln fundchannel pubkey parse error {:?}", e);
                            tonic::Status::invalid_argument(e.to_string())
                        },
                    )?,
                    amount: cln_rpc::primitives::AmountOrAll::Amount(
                        cln_rpc::primitives::Amount::from_sat(request_inner.channel_size_sats),
                    ),
                    feerate: None,
                    announce: None,
                    minconf: None,
                    push_msat: Some(cln_rpc::primitives::Amount::from_sat(
                        request_inner.push_amount_sats,
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
            .map_err(|e| {
                error!("cln fundchannel rpc returned error {:?}", e);
                tonic::Status::internal(e.to_string())
            })?;

        Ok(tonic::Response::new(EmptyResponse {}))
    }

    async fn close_channels_with_peer(
        &self,
        request: tonic::Request<CloseChannelsWithPeerRequest>,
    ) -> Result<tonic::Response<CloseChannelsWithPeerResponse>, Status> {
        let request_inner = request.into_inner();

        let peer_id = PublicKey::from_slice(&request_inner.pubkey).map_err(|e| {
            Status::invalid_argument(format!("Unable to parse request pubkey: {e}"))
        })?;

        let channels_with_peer: Vec<ListpeerchannelsChannels> = self
            .rpc_client()
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .call(cln_rpc::Request::ListPeerChannels(
                model::requests::ListpeerchannelsRequest { id: Some(peer_id) },
            ))
            .await
            .map(|response| match response {
                cln_rpc::Response::ListPeerChannels(
                    model::responses::ListpeerchannelsResponse { channels },
                ) => Ok(channels
                    .into_iter()
                    .filter(|channel| {
                        channel.state
                            == model::responses::ListpeerchannelsChannelsState::CHANNELD_NORMAL
                    })
                    .collect()),
                _ => Err(ClnExtensionError::RpcWrongResponse),
            })
            .map_err(|e| {
                error!("cln listchannels rpc returned error {:?}", e);
                tonic::Status::internal(e.to_string())
            })?
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        for channel_id in channels_with_peer
            .iter()
            .filter_map(|channel| channel.channel_id)
        {
            self.rpc_client()
                .await
                .map_err(|e| Status::internal(e.to_string()))?
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
                .map_err(|e| {
                    error!("cln fundchannel rpc returned error {:?}", e);
                    tonic::Status::internal(e.to_string())
                })?;
        }

        Ok(tonic::Response::new(CloseChannelsWithPeerResponse {
            num_channels_closed: channels_with_peer.len() as u32,
        }))
    }

    async fn list_active_channels(
        &self,
        _request: tonic::Request<EmptyRequest>,
    ) -> Result<tonic::Response<ListActiveChannelsResponse>, Status> {
        let channels = self
            .rpc_client()
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .call(cln_rpc::Request::ListPeerChannels(
                model::requests::ListpeerchannelsRequest { id: None },
            ))
            .await
            .map(|response| match response {
                cln_rpc::Response::ListPeerChannels(
                    model::responses::ListpeerchannelsResponse { channels },
                ) => Ok(channels
                    .into_iter()
                    .filter_map(|channel| {
                        if matches!(
                            channel.state,
                            model::responses::ListpeerchannelsChannelsState::CHANNELD_NORMAL
                        ) {
                            Some(ChannelInfo {
                                remote_pubkey: format!("{}", channel.peer_id),
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
                    .collect()),
                _ => Err(ClnExtensionError::RpcWrongResponse),
            })
            .map_err(|e| {
                error!("cln listchannels rpc returned error {:?}", e);
                tonic::Status::internal(e.to_string())
            })?
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(ListActiveChannelsResponse {
            channels,
        }))
    }
}

#[derive(Debug, Error)]
enum ClnExtensionError {
    #[error("Gateway CLN Extension Error : {0:?}")]
    Error(#[from] anyhow::Error),
    #[error("Gateway CLN Extension Error : {0:?}")]
    RpcError(#[from] cln_rpc::RpcError),
    #[error("Gateway CLN Extension, CLN RPC Wrong Response")]
    RpcWrongResponse,
}

// TODO: upstream
fn scid_to_u64(scid: ShortChannelId) -> u64 {
    let mut scid_num = scid.outnum() as u64;
    scid_num |= (scid.txindex() as u64) << 16;
    scid_num |= (scid.block() as u64) << 40;
    scid_num
}

// BOLT 4: https://github.com/lightning/bolts/blob/master/04-onion-routing.md#failure-messages
// 16399 error code reports unknown payment details.
//
// TODO: We should probably use a more specific error code based on htlc
// processing fail reason
fn htlc_processing_failure() -> serde_json::Value {
    serde_json::json!({
        "result": "fail",
        "failure_message": "1639"
    })
}

type HtlcInterceptionSender = mpsc::Sender<Result<InterceptHtlcRequest, Status>>;
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
            let payment_hash = payload.htlc.payment_hash.to_byte_array().to_vec();

            let incoming_chan_id =
                match Self::convert_short_channel_id(payload.htlc.short_channel_id.as_str()) {
                    Ok(scid) => scid,
                    // Failed to parse incoming_chan_id, just forward the HTLC
                    Err(_) => return serde_json::json!({ "result": "continue" }),
                };

            let htlc_ret = match sender
                .send(Ok(InterceptHtlcRequest {
                    payment_hash: payment_hash.clone(),
                    incoming_amount_msat: payload.htlc.amount_msat.msats,
                    outgoing_amount_msat: payload.onion.forward_msat.msats,
                    incoming_expiry: htlc_expiry,
                    short_channel_id,
                    incoming_chan_id,
                    htlc_id: payload.htlc.id,
                }))
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
