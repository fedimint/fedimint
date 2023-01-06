use std::{collections::HashMap, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use anyhow::anyhow;
use clap::Parser;
use cln_plugin::{options, Builder, Plugin};
use cln_rpc::ClnRpc;
use fedimint_api::{task::TaskGroup, Amount};
use ln_gateway::gatewaylnrpc::{
    gateway_lightning_server::{GatewayLightning, GatewayLightningServer},
    CompleteHtlcsRequest, CompleteHtlcsResponse, GetPubKeyRequest, GetPubKeyResponse,
    PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
    SubscribeInterceptHtlcsResponse,
};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tokio::{
    io::{stdin, stdout},
    sync::{mpsc, Mutex},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Status};
use tracing::{debug, error};

#[derive(Parser)]
pub struct ClnExtensionOpts {
    /// Gateway CLN extension service bind address
    #[arg(long = "addr", env = "GW_CLN_EXTENSION_BIND_ADDRESS")]
    pub addr: SocketAddr,
}

// Note: Once this binary is stable, we should be able to remove current 'ln_gateway'
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let service = ClnRpcService::new()
        .await
        .expect("Failed to create cln rpc service");

    // Parse configurations
    let addr = match ClnExtensionOpts::try_parse() {
        Ok(opts) => opts.addr,
        Err(_) => service.addr,
    };

    debug!(
        "Starting gateway-cln-extension with bind address : {}",
        addr
    );

    Server::builder()
        .add_service(GatewayLightningServer::new(service))
        .serve(addr)
        .await
        .map_err(|_| ClnExtensionError::Error(anyhow!("Failed to start server")))?;

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
    pub payload: String,
    pub short_channel_id: u64,
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub forward_msat: Amount,
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
    interceptor: Arc<ClnHtlcInterceptor>,
    task_group: TaskGroup,
    pub addr: SocketAddr,
}

impl ClnRpcService {
    pub async fn new() -> Result<Self, ClnExtensionError> {
        let interceptor = Arc::new(ClnHtlcInterceptor::new());

        if let Some(plugin) = Builder::new(stdin(), stdout())
            .option(options::ConfigOption::new(
                "addr",
                // Set an invalid default address in the extension to force the extension plugin user
                // to supply a valid address via an environment variable or cln plugin config option.
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

            let addr = match plugin.option("addr") {
                Some(options::Value::String(address)) => SocketAddr::from_str(&address)
                    .map_err(|e| ClnExtensionError::Error(anyhow!("{}", e)))?,
                _ => unreachable!(),
            };

            Ok(Self {
                client: Arc::new(Mutex::new(client)),
                task_group: TaskGroup::new(),
                interceptor,
                addr,
            })
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
        unimplemented!()
    }

    type PayInvoiceStream = ReceiverStream<Result<PayInvoiceResponse, Status>>;

    async fn pay_invoice(
        &self,
        _request: tonic::Request<tonic::Streaming<PayInvoiceRequest>>,
    ) -> Result<tonic::Response<Self::PayInvoiceStream>, Status> {
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

#[derive(Debug, Error)]
pub enum ClnExtensionError {
    #[error("Gateway CLN Extension Error : {0:?}")]
    Error(#[from] anyhow::Error),
}

type HtlcSubscriptionSender = mpsc::Sender<Result<SubscribeInterceptHtlcsResponse, Status>>;

/// Functional structure to filter intercepted HTLCs into subscription streams.
/// Used as a CLN plugin
#[derive(Clone)]
struct ClnHtlcInterceptor {
    subscriptions: Arc<Mutex<HashMap<u64, HtlcSubscriptionSender>>>,
}

impl ClnHtlcInterceptor {
    fn new() -> Self {
        Self {
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn intercept_htlc(&self, _payload: HtlcAccepted) -> serde_json::Value {
        unimplemented!("TODO: Implement HTLC filtering using short channel ids")
    }

    async fn add_htlc_subscriber(
        &self,
        _short_channel_id: u64,
    ) -> mpsc::Receiver<Result<SubscribeInterceptHtlcsResponse, Status>> {
        unimplemented!("TODO: Implement HTLC intercept subscription")
    }

    // TODO: Add a method to remove a HTLC subscriber
}
