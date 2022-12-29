use std::{collections::HashMap, path::PathBuf, sync::Arc};

use bitcoin::XOnlyPublicKey;
use cln::{model, ClnRpc};
use cln_plugin::{options, Builder, Plugin};
use fedimint_api::{task::TaskGroup, Amount};
use fedimint_server::config::load_from_file;
use ln_gateway::{
    config::ClnRpcConfig,
    gwlightningrpc::{
        gateway_lightning_server::{GatewayLightning, GatewayLightningServer},
        GetPubKeyRequest, GetPubKeyResponse, PayInvoiceRequest, PayInvoiceResponse,
        SubscribeInterceptHtlcsRequest, SubscribeInterceptHtlcsResponse,
    },
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::{
    io::{stdin, stdout},
    sync::{mpsc, Mutex},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Status};
use tracing::error;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let service = ClnRpcService::new()
        .await
        .expect("Failed to create cln rpc service");
    let dir = service.dir.clone();

    // Read configurations
    let gw_cfg_path = dir.join("lnrpc.config");
    let ClnRpcConfig { lnrpc_bind_address } = load_from_file(&gw_cfg_path)
        .map_err(|_| ClnRpcError::ConfigurationError)
        .expect("Failed to parse config");

    let srv = GatewayLightningServer::new(service);

    Server::builder()
        .add_service(srv)
        .serve(lnrpc_bind_address)
        .await
        .map_err(|_| ClnRpcError::RpcServerError(LightningError(Some(0))))?;

    println!(
        "CLN gateway lightning rpc server listening at : {}",
        lnrpc_bind_address
    );

    Ok(())
}

/// The core-lightning `htlc_accepted` event's `amount` field has a "msat" suffix
fn as_fedimint_amount<'de, D>(amount: D) -> Result<Amount, D::Error>
where
    D: Deserializer<'de>,
{
    let amount = String::deserialize(amount)?;
    Ok(Amount::from_msats(
        amount[0..amount.len() - 4].parse::<u64>().unwrap(),
    ))
}

// TODO: upstream these structs to cln-plugin
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Htlc {
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub amount: Amount,
    pub cltv_expiry: u32,
    pub cltv_expiry_relative: u32,
    pub payment_hash: bitcoin_hashes::sha256::Hash,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Onion {
    pub payload: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub short_channel_id: String,
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub forward_amount: Amount,
    pub outgoing_cltv_value: u32,
    pub shared_secret: bitcoin_hashes::sha256::Hash,
    pub next_onion: String,
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
    interceptor: Arc<Mutex<ClnHtlcInterceptor>>,
    task_group: TaskGroup,
    pub dir: PathBuf,
}

impl ClnRpcService {
    pub async fn new() -> Result<Self, ClnRpcError> {
        let interceptor = Arc::new(Mutex::new(ClnHtlcInterceptor::new()));

        if let Some(plugin) = Builder::new(stdin(), stdout())
            .option(options::ConfigOption::new(
                "gateway-cfg",
                // FIXME: cln_plugin doesn't support parameters without defaults
                options::Value::String("default-dont-use".into()),
                "gateway config directory",
            ))
            .hook(
                "htlc_accepted",
                |plugin: Plugin<Arc<Mutex<ClnHtlcInterceptor>>>, value: serde_json::Value| async move {
                    // This callback needs to be `Sync`, so we use tokio::spawn
                    let handle = tokio::spawn(async move {
                        // Handle core-lightning "htlc_accepted" events
                        // by passing the HTLC to the interceptor in the plugin state
                        let payload: HtlcAccepted = serde_json::from_value(value)?;
                        Ok(plugin.state().lock().await.intercept_htlc(payload).await)
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

            let dir = match plugin.option("gateway-cfg") {
                Some(options::Value::String(workdir)) => {
                    // FIXME: cln_plugin doesn't yet support optional parameters
                    if &workdir == "default-dont-use" {
                        panic!("gateway-cfg option missing")
                    } else {
                        PathBuf::from(workdir)
                    }
                }
                _ => unreachable!(),
            };

            Ok(Self {
                client: Arc::new(Mutex::new(client)),
                task_group: TaskGroup::new(),
                interceptor,
                dir,
            })
        } else {
            // TODO: Accurately define LightningError when building the plugin fails
            Err(ClnRpcError::RpcServerError(LightningError(Some(0))))
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
            .call(cln::Request::Getinfo(model::requests::GetinfoRequest {}))
            .await
            .map(|response| {
                let pub_key = match response {
                    cln::Response::Getinfo(model::responses::GetinfoResponse { id, .. }) => id,
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
    ) -> Result<tonic::Response<PayInvoiceResponse>, Status> {
        let PayInvoiceRequest {
            invoice,
            max_fee_percent,
            max_delay,
        } = request.into_inner();

        self.client
            .lock()
            .await
            .call(cln::Request::Pay(model::PayRequest {
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
            .map(|response| {
                let pay_success = match response {
                    cln::Response::Pay(model::PayResponse {
                        payment_preimage,
                        payment_hash,
                        ..
                    }) => PayInvoiceResponse {
                        preimage: payment_preimage.to_vec(),
                        payment_hash: payment_hash.to_vec(),
                    },
                    _ => panic!("Unexpected response from cln_rpc"),
                };
                tonic::Response::new(pay_success)
            })
            .map_err(|e| {
                error!("cln pay returned error {:?}", e);
                Status::internal(e.to_string())
            })
    }

    type SubscribeInterceptHtlcsStream =
        ReceiverStream<Result<SubscribeInterceptHtlcsResponse, Status>>;

    async fn subscribe_intercept_htlcs(
        &self,
        request: tonic::Request<SubscribeInterceptHtlcsRequest>,
    ) -> Result<tonic::Response<Self::SubscribeInterceptHtlcsStream>, Status> {
        let SubscribeInterceptHtlcsRequest { mint_pub_key } = request.into_inner();

        let mint_pubkey = XOnlyPublicKey::from_slice(&mint_pub_key).map_err(|_| {
            error!("Invalid mint pubkey. HTLC intercept subscription failed");
            Status::invalid_argument("Invalid mint pubkey. HTLC intercept subscription failed")
        })?;

        let receiver = self
            .interceptor
            .lock()
            .await
            .add_htlc_subscriber(mint_pubkey)
            .await;

        Ok(tonic::Response::new(ReceiverStream::new(receiver)))
    }
}

#[derive(Debug)]
pub struct LightningError(pub Option<i32>);

#[derive(Debug, Error)]
pub enum ClnRpcError {
    #[error("ConfigurationError")]
    ConfigurationError,
    #[error("RpcServerError : {0:?}")]
    RpcServerError(LightningError),
    #[error("Other: {0:?}")]
    Other(#[from] anyhow::Error),
}

/// Functional structure to filter intercepted HTLCs into subscription streams.
/// Used as a CLN plugin
struct ClnHtlcInterceptor {
    subscriptions: Mutex<
        HashMap<XOnlyPublicKey, mpsc::Sender<Result<SubscribeInterceptHtlcsResponse, Status>>>,
    >,
}

impl ClnHtlcInterceptor {
    fn new() -> Self {
        Self {
            subscriptions: Mutex::new(HashMap::new()),
        }
    }

    async fn intercept_htlc(&self, _payload: HtlcAccepted) -> serde_json::Value {
        // TODO:
        // Match intercepted htlc against any of the subscriptions
        // If there is a match, send the htlc to the subscription stream,
        // and wait for response from the subscriber

        // For now, we just request the htlc to be continued
        json!({ "result": "continue" })
    }

    async fn add_htlc_subscriber(
        &mut self,
        mint_pubkey: XOnlyPublicKey,
    ) -> mpsc::Receiver<Result<SubscribeInterceptHtlcsResponse, Status>> {
        let (sender, receiver) =
            mpsc::channel::<Result<SubscribeInterceptHtlcsResponse, Status>>(100);
        self.subscriptions.lock().await.insert(mint_pubkey, sender);
        receiver
    }

    // TODO: Add a method to remove a HTLC subscriber
}
