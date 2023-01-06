use std::{collections::HashMap, path::PathBuf, sync::Arc};

use cln_plugin::{options, Builder, Plugin};
use cln_rpc::ClnRpc;
use fedimint_api::{task::TaskGroup, Amount};
use fedimint_server::config::load_from_file;
use ln_gateway::{
    config::ClnRpcConfig,
    gatewaylnrpc::{
        gateway_lightning_server::{GatewayLightning, GatewayLightningServer},
        CompleteHtlcsRequest, CompleteHtlcsResponse, GetPubKeyRequest, GetPubKeyResponse,
        PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
        SubscribeInterceptHtlcsResponse,
    },
};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tokio::{
    io::{stdin, stdout},
    sync::{mpsc, Mutex},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Status};
use tracing::error;

// Note: One this binary is stable, we should be able to remove current 'ln_gateway'
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
    pub short_channel_id: u64,
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
        unimplemented!()
    }

    async fn pay_invoice(
        &self,
        _request: tonic::Request<PayInvoiceRequest>,
    ) -> Result<tonic::Response<PayInvoiceResponse>, Status> {
        unimplemented!()
    }

    type SubscribeInterceptHtlcsStream =
        ReceiverStream<Result<SubscribeInterceptHtlcsResponse, Status>>;

    async fn subscribe_intercept_htlcs(
        &self,
        _request: tonic::Request<SubscribeInterceptHtlcsRequest>,
    ) -> Result<tonic::Response<Self::SubscribeInterceptHtlcsStream>, Status> {
        unimplemented!()
    }

    type CompleteHtlcsStream = tonic::Streaming<CompleteHtlcsResponse>;

    async fn complete_htlcs(
        &self,
        _request: tonic::Request<tonic::Streaming<CompleteHtlcsRequest>>,
    ) -> Result<tonic::Response<Self::CompleteHtlcsStream>, Status> {
        unimplemented!()
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
    subscriptions:
        Mutex<HashMap<u64, mpsc::Sender<Result<SubscribeInterceptHtlcsResponse, Status>>>>,
}

impl ClnHtlcInterceptor {
    fn new() -> Self {
        Self {
            subscriptions: Mutex::new(HashMap::new()),
        }
    }

    async fn intercept_htlc(&self, _payload: HtlcAccepted) -> serde_json::Value {
        unimplemented!("TODO: Implement HTLC filtering using short channel ids")
    }

    async fn add_htlc_subscriber(
        &mut self,
        _short_channel_id: u64,
    ) -> mpsc::Receiver<Result<SubscribeInterceptHtlcsResponse, Status>> {
        unimplemented!("TODO: Implement HTLC intercept subscription")
    }

    // TODO: Add a method to remove a HTLC subscriber
}
