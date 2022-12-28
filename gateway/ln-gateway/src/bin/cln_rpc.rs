use std::{path::PathBuf, sync::Arc, time::Duration};

use cln::{model, ClnRpc};
use cln_plugin::{anyhow, Builder, Error, Plugin};
use fedimint_api::{task::TaskGroup, Amount};
use fedimint_server::config::load_from_file;
use ln_gateway::{
    config::ClnRpcConfig,
    gwlightningrpc::{
        gateway_lightning_server::{GatewayLightning, GatewayLightningServer},
        GetPubKeyRequest, GetPubKeyResponse, PayInvoiceRequest, PayInvoiceResponse,
        SubscribeInterceptHtlcsRequest, SubscribeInterceptHtlcsResponse,
    },
    utils::try_read_gateway_dir,
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
    // Read configurations
    let dir = try_read_gateway_dir()?;
    let gw_cfg_path = dir.join("lnrpc.config");
    let ClnRpcConfig { lnrpc_bind_address } = load_from_file(&gw_cfg_path)
        .map_err(|_| ClnRpcError::ConfigurationError)
        .expect("Failed to parse config");

    let service = ClnRpcService::new()
        .await
        .expect("Failed to create cln rpc service");
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
    sender: mpsc::Sender<HtlcAccepted>,
    receiver: mpsc::Receiver<HtlcAccepted>,
    // CLN rpc plugin.
    client: Arc<Mutex<ClnRpc>>,
    task_group: TaskGroup,
}

impl ClnRpcService {
    pub async fn new() -> Result<Self, ClnRpcError> {
        // Create message channels
        let (sender, receiver) = mpsc::channel::<HtlcAccepted>(100);

        if let Some(plugin) = Builder::new(stdin(), stdout())
            .hook("htlc_accepted", |plugin, value| async move {
                /// Handle core-lightning "htlc_accepted" events by attempting to buy this preimage from the federation
                /// and completing the payment
                async fn htlc_accepted_hook(
                    _plugin: Plugin<mpsc::Sender<HtlcAccepted>>,
                    value: serde_json::Value,
                ) -> Result<serde_json::Value, Error> {
                    let HtlcAccepted { htlc, ..}= serde_json::from_value(value)?;

                    println!("CLN HTLC Intercepted------------");
                    println!(
                        "amount: {:?}\ncltv_expiry: {}\ncltv_expiry_relative: {}\npayment_hash: {:?}\n",
                        htlc.amount, htlc.cltv_expiry, htlc.cltv_expiry_relative, htlc.payment_hash
                    );

                    // TODO: Filter and send intercepted HTLCs to the gateway for processing.
                    // For now, we just log them and continue to the next hop
                    Ok(json!({ "result": "continue" }))
                }

                // This callback needs to be `Sync`, so we use tokio::spawn
                let handle = tokio::spawn(async move {
                    // FIXME: Test this potential fix for Issue 1018: Gateway channel force closures
                    //
                    // Timeout processing of intecepted HTLC after 30 seconds
                    // If the HTLC is not resolved, we continue and forward it to the next hop
                    tokio::time::timeout(Duration::from_secs(30), htlc_accepted_hook(plugin, value))
                        .await
                        .unwrap_or_else(|_| Err(anyhow!("htlc_accepted timeout")))
                        .or_else(|e| {
                            error!("htlc_accepted error {:?}", e);
                            // cln_plugin doesn't handle errors very well ... tell it to proceed normally
                            Ok(json!({ "result": "continue" }))
                        })
                });
                handle.await?
            })
            .dynamic() // Allow reloading the plugin
            .start(sender.clone())
            .await?
        {
            let config = plugin.configuration();
            let socket = PathBuf::from(config.lightning_dir).join(config.rpc_file);
            let client = ClnRpc::new(socket).await.expect("connect to ln_socket");

            Ok(Self {
                client: Arc::new(Mutex::new(client)),
                task_group: TaskGroup::new(),
                sender,
                receiver,
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
        _request: tonic::Request<SubscribeInterceptHtlcsRequest>,
    ) -> Result<tonic::Response<Self::SubscribeInterceptHtlcsStream>, Status> {
        Err(Status::unimplemented("not implemented"))
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
