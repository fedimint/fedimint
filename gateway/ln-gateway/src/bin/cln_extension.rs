use std::{
    array::TryFromSliceError, collections::HashMap, net::SocketAddr, path::PathBuf, str::FromStr,
    sync::Arc, time::Duration,
};

use anyhow::anyhow;
use bitcoin_hashes::{hex::ToHex, sha256, Hash};
use clap::Parser;
use cln_plugin::{options, Builder, Plugin};
use cln_rpc::{model, ClnRpc};
use fedimint_api::{task::TaskGroup, Amount};
use ln_gateway::gatewaylnrpc::{
    complete_htlcs_request::{Action, Cancel, Settle},
    gateway_lightning_server::{GatewayLightning, GatewayLightningServer},
    CompleteHtlcsRequest, CompleteHtlcsResponse, GetPubKeyRequest, GetPubKeyResponse,
    PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
    SubscribeInterceptHtlcsResponse,
};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tokio::{
    io::{stdin, stdout},
    sync::{mpsc, oneshot, Mutex},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Status};
use tracing::{debug, error};

#[derive(Parser)]
pub struct ClnExtensionOpts {
    /// Gateway CLN extension service listen address
    #[arg(long = "listen", env = "GW_CLN_EXTENSION_LISTEN_ADDRESS")]
    pub listen: SocketAddr,
}

// Note: Once this binary is stable, we should be able to remove current
// 'ln_gateway' Use CLN_PLUGIN_LOG=<log-level> to enable debug logging from
// within cln-plugin
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let (service, listen) = ClnRpcService::new()
        .await
        .expect("Failed to create cln rpc service");

    debug!(
        "Starting gateway-cln-extension with listen address : {}",
        listen
    );

    Server::builder()
        .add_service(GatewayLightningServer::new(service))
        .serve(listen)
        .await
        .map_err(|_| ClnExtensionError::Error(anyhow!("Failed to start server")))?;

    Ok(())
}

/// The core-lightning `htlc_accepted` event's `amount` field has a "msat"
/// suffix
fn as_fedimint_amount<'de, D>(amount: D) -> Result<Amount, D::Error>
where
    D: Deserializer<'de>,
{
    let amount = String::deserialize(amount)?;
    Ok(Amount::from_msats(
        amount[0..amount.len() - 4].parse::<u64>().unwrap(),
    ))
}

// TODO: Keep in sync with cln-plugin:
// See: https://github.com/ElementsProject/lightning/blob/master/doc/PLUGINS.md#htlc_accepted
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Htlc {
    pub short_channel_id: u64,
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub amount_msat: Amount,
    pub cltv_expiry: u32,
    pub cltv_expiry_relative: u32,
    pub payment_hash: bitcoin_hashes::sha256::Hash,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Onion {
    #[serde(default)]
    pub short_channel_id: Option<u64>,
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub forward_msat: Amount,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HtlcAccepted {
    pub htlc: Htlc,
    pub onion: Onion,
}

pub struct ClnRpcClient {}

#[allow(dead_code)]
pub struct ClnRpcService {
    client: Arc<Mutex<ClnRpc>>,
    interceptor: Arc<ClnHtlcInterceptor>,
    task_group: TaskGroup,
}

impl ClnRpcService {
    pub async fn new() -> Result<(Self, SocketAddr), ClnExtensionError> {
        let interceptor = Arc::new(ClnHtlcInterceptor::new());

        if let Some(plugin) = Builder::new(stdin(), stdout())
            .option(options::ConfigOption::new(
                "listen",
                // Set an invalid default address in the extension to force the extension plugin
                // user to supply a valid address via an environment variable or
                // cln plugin config option.
                options::Value::String("default-dont-use".into()),
                "gateway cln extension address",
            ))
            .hook(
                "htlc_accepted",
                |plugin: Plugin<Arc<ClnHtlcInterceptor>>, value: serde_json::Value| async move {
                    // This callback needs to be `Sync`, so we use tokio::spawn
                    let handle = tokio::spawn(async move {
                        // Handle core-lightning "htlc_accepted" events
                        // by passing the HTLC to the interceptor in the plugin state
                        let payload: HtlcAccepted = serde_json::from_value(value)?;
                        Ok(plugin.state().intercept_htlc(payload).await)
                    });
                    handle.await?
                },
            )
            .dynamic() // Allow reloading the plugin
            .start(interceptor.clone())
            .await?
        {
            let config = plugin.configuration();
            let socket = PathBuf::from(config.lightning_dir).join(config.rpc_file);
            let client = ClnRpc::new(socket).await.expect("connect to ln_socket");

            // Parse configurations or read from
            let listen: SocketAddr = match ClnExtensionOpts::try_parse() {
                Ok(opts) => opts.listen,
                // FIXME: cln_plugin doesn't yet support optional parameters
                Err(_) => match plugin.option("listen") {
                    Some(options::Value::String(listen)) => {
                        if listen == "default-dont-use" {
                            panic!(
                                "Gateway cln extension is missing a listen address configuration. You can set it via GW_CLN_EXTENSION_LISTEN_ADDRESS env variable, or by adding a --listen config option to the cln plugin"
                            )
                        } else {
                            SocketAddr::from_str(&listen).expect("invalid listen address")
                        }
                    }
                    _ => unreachable!(),
                },
            };

            Ok((
                Self {
                    client: Arc::new(Mutex::new(client)),
                    task_group: TaskGroup::new(),
                    interceptor,
                },
                listen,
            ))
        } else {
            Err(ClnExtensionError::Error(anyhow!(
                "Failed to start cln plugin"
            )))
        }
    }
}

#[tonic::async_trait]
impl GatewayLightning for ClnRpcService {
    async fn get_pub_key(
        &self,
        _request: tonic::Request<GetPubKeyRequest>,
    ) -> Result<tonic::Response<GetPubKeyResponse>, Status> {
        self.client
            .lock()
            .await
            .call(cln_rpc::Request::Getinfo(
                model::requests::GetinfoRequest {},
            ))
            .await
            .map(|response| {
                let pub_key = match response {
                    cln_rpc::Response::Getinfo(model::responses::GetinfoResponse {
                        id, ..
                    }) => id,
                    _ => panic!("Unexpected response from cln_rpc"),
                };
                tonic::Response::new(GetPubKeyResponse {
                    pub_key: pub_key.serialize().to_vec(),
                })
            })
            .map_err(|e| {
                error!("cln getinfo returned error: {:?}", e);
                Status::internal(e.to_string())
            })
    }

    async fn pay_invoice(
        &self,
        request: tonic::Request<PayInvoiceRequest>,
    ) -> Result<tonic::Response<PayInvoiceResponse>, tonic::Status> {
        let PayInvoiceRequest {
            invoice,
            max_delay,
            max_fee_percent,
        } = request.into_inner();

        let outcome = self
            .client
            .lock()
            .await
            .call(cln_rpc::Request::Pay(model::PayRequest {
                bolt11: invoice,
                amount_msat: None,
                label: None,
                riskfactor: None,
                maxfeepercent: Some(max_fee_percent),
                retry_for: None,
                maxdelay: Some(max_delay as u16),
                exemptfee: None,
                localinvreqid: None,
                exclude: None,
                maxfee: None,
                description: None,
            }))
            .await
            .map(|response| match response {
                cln_rpc::Response::Pay(model::PayResponse {
                    payment_preimage, ..
                }) => PayInvoiceResponse {
                    preimage: payment_preimage.to_vec(),
                },
                _ => panic!("Unexpected response from cln pay rpc"),
            })
            .map_err(|e| {
                error!("cln pay rpc returned error {:?}", e);
                tonic::Status::internal(e.to_string())
            })?;

        Ok(tonic::Response::new(outcome))
    }

    type SubscribeInterceptHtlcsStream =
        ReceiverStream<Result<SubscribeInterceptHtlcsResponse, Status>>;

    async fn subscribe_intercept_htlcs(
        &self,
        request: tonic::Request<SubscribeInterceptHtlcsRequest>,
    ) -> Result<tonic::Response<Self::SubscribeInterceptHtlcsStream>, Status> {
        let SubscribeInterceptHtlcsRequest { short_channel_id } = request.into_inner();
        let receiver = self.interceptor.add_htlc_subscriber(short_channel_id).await;

        Ok(tonic::Response::new(ReceiverStream::new(receiver)))
    }

    async fn complete_htlc(
        &self,
        request: tonic::Request<CompleteHtlcsRequest>,
    ) -> Result<tonic::Response<CompleteHtlcsResponse>, Status> {
        let CompleteHtlcsRequest {
            action,
            intercepted_htlc_id,
        } = request.into_inner();

        let hash = match sha256::Hash::from_slice(&intercepted_htlc_id) {
            Ok(hash) => hash,
            Err(e) => {
                error!("Invalid intercepted_htlc_id: {:?}", e);
                return Err(Status::invalid_argument(e.to_string()));
            }
        };

        if let Some(outcome) = self.interceptor.outcomes.lock().await.remove(&hash) {
            // Translate action request into a cln rpc response for `htlc_accepted` event
            let htlca_res = match action {
                Some(Action::Settle(Settle { preimage })) => {
                    let assert_pk: Result<[u8; 32], TryFromSliceError> =
                        preimage.as_slice().try_into();
                    if let Ok(pk) = assert_pk {
                        serde_json::json!({ "result": "resolve", "payment_key": pk.to_hex() })
                    } else {
                        htlc_processing_failure()
                    }
                }
                Some(Action::Cancel(Cancel { reason: _ })) => {
                    // TODO: Translate the reason into a BOLT 4 failure message
                    // See: https://github.com/lightning/bolts/blob/master/04-onion-routing.md#failure-messages
                    htlc_processing_failure()
                }
                None => {
                    error!("No action specified for intercepted htlc id: {:?}", hash);
                    return Err(Status::internal(
                        "No action specified on this intercepted htlc",
                    ));
                }
            };

            // Send translated response to the HTLC interceptor for submission to the cln
            // rpc
            match outcome.send(htlca_res) {
                Ok(_) => {
                    return Ok(tonic::Response::new(CompleteHtlcsResponse {}));
                }
                Err(e) => {
                    error!(
                        "Failed to send htlc_accepted response to interceptor: {:?}",
                        e
                    );
                    return Err(Status::internal(
                        "Failed to send htlc_accepted outcome to interceptor",
                    ));
                }
            };
        } else {
            error!(
                "No interceptor reference found for this processed htlc with id: {:?}",
                intercepted_htlc_id
            );
            // TODO: Use error codes to signal the gateway to take reactionary actions
            return Err(Status::internal(
                "No interceptor reference found for this processed htlc. Potential loss of funds",
            ));
        }
    }
}

#[derive(Debug, Error)]
pub enum ClnExtensionError {
    #[error("Gateway CLN Extension Error : {0:?}")]
    Error(#[from] anyhow::Error),
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

type HtlcSubscriptionSender = mpsc::Sender<Result<SubscribeInterceptHtlcsResponse, Status>>;
type HtlcOutcomeSender = oneshot::Sender<serde_json::Value>;

/// Functional structure to filter intercepted HTLCs into subscription streams.
/// Used as a CLN plugin
#[derive(Clone)]
struct ClnHtlcInterceptor {
    subscriptions: Arc<Mutex<HashMap<u64, HtlcSubscriptionSender>>>,
    pub outcomes: Arc<Mutex<HashMap<sha256::Hash, HtlcOutcomeSender>>>,
}

impl ClnHtlcInterceptor {
    fn new() -> Self {
        Self {
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            outcomes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn intercept_htlc(&self, payload: HtlcAccepted) -> serde_json::Value {
        let htlc_expiry = payload.htlc.cltv_expiry;

        let short_channel_id = match payload.onion.short_channel_id {
            Some(scid) => scid,
            None => {
                // This is a HTLC terminating at the gateway node. DO NOT intercept
                return serde_json::json!({ "result": "continue" });
            }
        };

        if let Some(subscription) = self.subscriptions.lock().await.get(&short_channel_id) {
            let payment_hash = payload.htlc.payment_hash.to_vec();

            // This has a chance of collission since payment_hashes are not guaranteed to be
            // unique TODO: generate unique id for each intercepted HTLC
            let intercepted_htlc_id = sha256::Hash::hash(&payment_hash);

            match subscription
                .send(Ok(SubscribeInterceptHtlcsResponse {
                    payment_hash: payment_hash.clone(),
                    incoming_amount_msat: payload.htlc.amount_msat.msats,
                    outgoing_amount_msat: payload.onion.forward_msat.msats,
                    incoming_expiry: htlc_expiry,
                    short_channel_id,
                    intercepted_htlc_id: intercepted_htlc_id.into_inner().to_vec(),
                }))
                .await
            {
                Ok(_) => {
                    // Open a channel to receive the outcome of the HTLC processing
                    let (sender, receiver) = oneshot::channel::<serde_json::Value>();
                    self.outcomes
                        .lock()
                        .await
                        .insert(intercepted_htlc_id, sender);

                    // If the gateway does not respond within the HTLC expiry,
                    // Automatically respond with a failure message.
                    return tokio::time::timeout(Duration::from_secs(30), async {
                        receiver.await.unwrap_or_else(|e| {
                            error!("Failed to receive outcome of intercepted htlc: {:?}", e);
                            htlc_processing_failure()
                        })
                    })
                    .await
                    .unwrap_or_else(|e| {
                        error!("await_htlc_processing error {:?}", e);
                        htlc_processing_failure()
                    });
                }
                Err(e) => {
                    error!("Failed to send htlc to subscription: {:?}", e);
                    return htlc_processing_failure();
                }
            }
        }

        // We have no subscription for this HTLC.
        // Ignore it by requesting the node to continue
        serde_json::json!({ "result": "continue" })
    }

    async fn add_htlc_subscriber(
        &self,
        short_channel_id: u64,
    ) -> mpsc::Receiver<Result<SubscribeInterceptHtlcsResponse, Status>> {
        let (sender, receiver) =
            mpsc::channel::<Result<SubscribeInterceptHtlcsResponse, Status>>(100);
        self.subscriptions
            .lock()
            .await
            .insert(short_channel_id, sender);
        receiver
    }

    // TODO: Add a method to remove a HTLC subscriber
}
