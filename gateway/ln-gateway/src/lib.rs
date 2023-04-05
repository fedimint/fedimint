pub mod actor;
pub mod client;
pub mod lnd;
pub mod lnrpc_client;
pub mod rpc;
pub mod types;
pub mod utils;

pub mod gatewaylnrpc {
    tonic::include_proto!("gatewaylnrpc");
}

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::Address;
use bitcoin_hashes::hex::ToHex;
use clap::Subcommand;
use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_core::api::{FederationError, WsClientConnectInfo};
use fedimint_core::config::FederationId;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{RwLock, TaskGroup};
use fedimint_core::{Amount, TransactionId};
use gatewaylnrpc::GetNodeInfoResponse;
use lnrpc_client::ILnRpcClient;
use mint_client::ln::PayInvoicePayload;
use mint_client::modules::ln::route_hints::RouteHint;
use mint_client::{ClientError, GatewayClient};
use rpc::{FederationInfo, LightningReconnectPayload};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};
use url::Url;

use crate::actor::GatewayActor;
use crate::client::DynGatewayClientBuilder;
use crate::lnd::GatewayLndClient;
use crate::lnrpc_client::NetworkLnRpcClient;
use crate::rpc::rpc_server::run_webserver;
use crate::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, DepositPayload,
    GatewayInfo, GatewayRequest, GatewayRpcSender, InfoPayload, RestorePayload, WithdrawPayload,
};

const ROUTE_HINT_RETRIES: usize = 10;
const ROUTE_HINT_RETRY_SLEEP: Duration = Duration::from_secs(2);
/// LND HTLC interceptor can't handle SCID of 0, so start from 1
const INITIAL_SCID: u64 = 1;

pub type Result<T> = std::result::Result<T, GatewayError>;

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum Mode {
    #[clap(name = "lnd")]
    Lnd {
        /// LND RPC address
        #[arg(long = "lnd-rpc-host", env = "FM_LND_RPC_ADDR")]
        lnd_rpc_addr: String,

        /// LND TLS cert file path
        #[arg(long = "lnd-tls-cert", env = "FM_LND_TLS_CERT")]
        lnd_tls_cert: String,

        /// LND macaroon file path
        #[arg(long = "lnd-macaroon", env = "FM_LND_MACAROON")]
        lnd_macaroon: String,
    },
    #[clap(name = "cln")]
    Cln {
        #[arg(long = "cln-extension-addr", env = "FM_GATEWAY_LIGHTNING_ADDR")]
        cln_extension_addr: Url,
    },
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Federation client operation error: {0:?}")]
    ClientError(#[from] ClientError),
    #[error("Lightning rpc operation error: {0:?}")]
    LnRpcError(#[from] tonic::Status),
    #[error("Federation error: {0:?}")]
    FederationError(#[from] FederationError),
    #[error("Other: {0:?}")]
    Other(#[from] anyhow::Error),
    #[error("Failed to fetch route hints")]
    FailedToFetchRouteHints,
}

impl GatewayError {
    pub fn other(msg: String) -> Self {
        error!(msg);
        GatewayError::Other(anyhow!(msg))
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let mut err = Cow::<'static, str>::Owned(format!("{self:?}")).into_response();
        *err.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        err
    }
}
pub struct Gateway {
    decoders: ModuleDecoderRegistry,
    module_gens: ClientModuleGenRegistry,
    lnrpc: Arc<RwLock<dyn ILnRpcClient>>,
    lightning_mode: Option<Mode>,
    actors: Mutex<HashMap<String, Arc<RwLock<GatewayActor>>>>,
    client_builder: DynGatewayClientBuilder,
    sender: mpsc::Sender<GatewayRequest>,
    receiver: mpsc::Receiver<GatewayRequest>,
    task_group: TaskGroup,
    channel_id_generator: AtomicU64,
}

impl Gateway {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        lightning_mode: Mode,
        client_builder: DynGatewayClientBuilder,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
        task_group: TaskGroup,
    ) -> Result<Self> {
        // Create message channels for the webserver
        let (sender, receiver) = mpsc::channel::<GatewayRequest>(100);

        let lnrpc =
            Self::create_lightning_client(lightning_mode.clone(), task_group.make_subgroup().await)
                .await?;

        let gw = Self {
            lnrpc,
            actors: Mutex::new(HashMap::new()),
            sender,
            receiver,
            client_builder,
            task_group,
            channel_id_generator: AtomicU64::new(INITIAL_SCID),
            decoders: decoders.clone(),
            module_gens: module_gens.clone(),
            lightning_mode: Some(lightning_mode),
        };

        gw.load_actors(decoders, module_gens).await?;

        Ok(gw)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_lightning_connection(
        lnrpc: Arc<RwLock<dyn ILnRpcClient>>,
        client_builder: DynGatewayClientBuilder,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
        task_group: TaskGroup,
    ) -> Result<Self> {
        // Create message channels for the webserver
        let (sender, receiver) = mpsc::channel::<GatewayRequest>(100);

        let gw = Self {
            lnrpc,
            actors: Mutex::new(HashMap::new()),
            sender,
            receiver,
            client_builder,
            task_group,
            channel_id_generator: AtomicU64::new(INITIAL_SCID),
            decoders: decoders.clone(),
            module_gens: module_gens.clone(),
            lightning_mode: None,
        };

        gw.load_actors(decoders, module_gens).await?;

        Ok(gw)
    }

    async fn create_lightning_client(
        mode: Mode,
        task_group: TaskGroup,
    ) -> Result<Arc<RwLock<dyn ILnRpcClient>>> {
        let lnrpc: Arc<RwLock<dyn ILnRpcClient>> = match mode {
            Mode::Cln { cln_extension_addr } => {
                info!(
                    "Gateway configured to connect to remote LnRpcClient at \n cln extension address: {:?} ",
                    cln_extension_addr
                );
                Arc::new(RwLock::new(
                    NetworkLnRpcClient::new(cln_extension_addr).await?,
                ))
            }
            Mode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            } => {
                info!(
                    "Gateway configured to connect to LND LnRpcClient at \n address: {:?},\n tls cert path: {:?},\n macaroon path: {} ",
                    lnd_rpc_addr, lnd_tls_cert, lnd_macaroon
                );
                Arc::new(RwLock::new(
                    GatewayLndClient::new(lnd_rpc_addr, lnd_tls_cert, lnd_macaroon, task_group)
                        .await?,
                ))
            }
        };

        Ok(lnrpc)
    }

    async fn load_actors(
        &self,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
    ) -> Result<()> {
        // Fetch route hints form the LN node
        let mut num_retries = 0;
        let route_hints = loop {
            let route_hints: Vec<RouteHint> = self
                .lnrpc
                .read()
                .await
                .routehints()
                .await
                .expect("Could not fetch route hints")
                .try_into()
                .expect("Could not parse route hints");

            if !route_hints.is_empty() || num_retries == ROUTE_HINT_RETRIES {
                break route_hints;
            }

            info!(
                ?num_retries,
                "LN node returned no route hints, trying again in {}s",
                ROUTE_HINT_RETRY_SLEEP.as_secs()
            );
            num_retries += 1;
            tokio::time::sleep(ROUTE_HINT_RETRY_SLEEP).await;
        };
        if let Ok(configs) = self.client_builder.load_configs() {
            let mut next_channel_id = self.channel_id_generator.load(Ordering::SeqCst);

            for config in configs {
                let client = self
                    .client_builder
                    .build(config.clone(), decoders.clone(), module_gens.clone())
                    .await
                    .expect("Could not build federation client");

                if let Err(e) = self.load_actor(Arc::new(client), route_hints.clone()).await {
                    error!("Failed to connect federation: {}", e);
                }

                if config.mint_channel_id > next_channel_id {
                    next_channel_id = config.mint_channel_id + 1;
                }
            }
            self.channel_id_generator
                .store(next_channel_id, Ordering::SeqCst);
        } else {
            warn!("Could not load any previous federation configs");
        }
        Ok(())
    }

    pub async fn load_actor(
        &self,
        client: Arc<GatewayClient>,
        route_hints: Vec<RouteHint>,
    ) -> Result<Arc<RwLock<GatewayActor>>> {
        let actor = Arc::new(RwLock::new(
            GatewayActor::new(
                client.clone(),
                self.lnrpc.clone(),
                route_hints,
                self.task_group.clone(),
                GatewayRpcSender::new(self.sender.clone()),
            )
            .await?,
        ));

        self.actors.lock().await.insert(
            client.config().client_config.federation_id.to_string(),
            actor.clone(),
        );
        Ok(actor)
    }

    async fn select_actor(&self, federation_id: FederationId) -> Result<Arc<RwLock<GatewayActor>>> {
        self.actors
            .lock()
            .await
            .get(&federation_id.to_string())
            .cloned()
            .ok_or(GatewayError::Other(anyhow::anyhow!(
                "No federation with id {}",
                federation_id.to_string()
            )))
    }

    async fn handle_connect_federation(
        &self,
        payload: ConnectFedPayload,
        route_hints: Vec<RouteHint>,
    ) -> Result<FederationInfo> {
        let connect = WsClientConnectInfo::from_str(&payload.connect).map_err(|e| {
            GatewayError::Other(anyhow::anyhow!("Invalid federation member string {}", e))
        })?;

        let GetNodeInfoResponse { pub_key, alias: _ } = self.lnrpc.read().await.info().await?;
        let node_pub_key = PublicKey::from_slice(&pub_key)
            .map_err(|e| GatewayError::Other(anyhow!("Invalid node pubkey {}", e)))?;

        // The gateway deterministically assigns a channel id (u64) to each federation
        // connected. TODO: explicitly handle the case where the channel id
        // overflows
        let channel_id = self.channel_id_generator.fetch_add(1, Ordering::SeqCst);

        let gw_client_cfg = self
            .client_builder
            .create_config(connect, channel_id, node_pub_key, self.module_gens.clone())
            .await?;

        let client = Arc::new(
            self.client_builder
                .build(
                    gw_client_cfg.clone(),
                    self.decoders.clone(),
                    self.module_gens.clone(),
                )
                .await
                .expect("Failed to build gateway client"),
        );

        let actor = self
            .load_actor(client.clone(), route_hints)
            .await
            .map_err(|e| {
                GatewayError::Other(anyhow::anyhow!("Failed to connect federation {}", e))
            })?;

        if let Err(e) = self.client_builder.save_config(client.config()) {
            warn!(
                "Failed to save default federation client configuration: {}",
                e
            );
        }

        let federation_info = actor.read().await.get_info()?;

        Ok(federation_info)
    }

    async fn handle_get_info(&self, _payload: InfoPayload) -> Result<GatewayInfo> {
        let actors = self.actors.lock().await;
        let mut federations: Vec<FederationInfo> = Vec::new();
        for actor in actors.values() {
            federations.push(actor.read().await.get_info()?);
        }

        let ln_info = self.lnrpc.read().await.info().await?;

        Ok(GatewayInfo {
            federations,
            version_hash: env!("CODE_VERSION").to_string(),
            lightning_pub_key: ln_info.pub_key.to_hex(),
            lightning_alias: ln_info.alias,
        })
    }

    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<()> {
        let PayInvoicePayload {
            federation_id,
            contract_id,
        } = payload;

        let actor_lock = self.select_actor(federation_id).await?;
        let actor = actor_lock.read().await;
        let outpoint = actor.pay_invoice(contract_id).await?;
        actor
            .await_outgoing_contract_claimed(contract_id, outpoint)
            .await?;
        Ok(())
    }

    async fn handle_balance_msg(&self, payload: BalancePayload) -> Result<Amount> {
        self.select_actor(payload.federation_id)
            .await?
            .read()
            .await
            .get_balance()
            .await
    }

    async fn handle_address_msg(&self, payload: DepositAddressPayload) -> Result<Address> {
        self.select_actor(payload.federation_id)
            .await?
            .read()
            .await
            .get_deposit_address()
            .await
    }

    async fn handle_deposit_msg(&self, payload: DepositPayload) -> Result<TransactionId> {
        let DepositPayload {
            txout_proof,
            transaction,
            federation_id,
        } = payload;

        self.select_actor(federation_id)
            .await?
            .read()
            .await
            .deposit(txout_proof, transaction)
            .await
    }

    async fn handle_withdraw_msg(&self, payload: WithdrawPayload) -> Result<TransactionId> {
        let WithdrawPayload {
            amount,
            address,
            federation_id,
        } = payload;

        self.select_actor(federation_id)
            .await?
            .read()
            .await
            .withdraw(amount, address)
            .await
    }

    async fn handle_backup_msg(
        &self,
        BackupPayload { federation_id }: BackupPayload,
    ) -> Result<()> {
        self.select_actor(federation_id)
            .await?
            .read()
            .await
            .backup()
            .await
    }

    async fn handle_restore_msg(
        &self,
        RestorePayload { federation_id }: RestorePayload,
    ) -> Result<()> {
        self.select_actor(federation_id)
            .await?
            .read()
            .await
            .restore()
            .await
    }

    async fn handle_lightning_reconnect(
        &mut self,
        payload: LightningReconnectPayload,
    ) -> Result<()> {
        let LightningReconnectPayload { node_type } = payload;

        let actors = self.actors.lock().await;

        // Stop all threads that are listening for HTLCs
        tracing::info!("Stopping all HTLC subscription threads.");
        for actor in actors.values() {
            actor.write().await.stop_subscribing_htlcs().await?;
        }

        self.lnrpc = match node_type {
            Some(node_type) => {
                Self::create_lightning_client(node_type, self.task_group.make_subgroup().await)
                    .await?
            }
            None => {
                // `lightning_mode` can be None during tests
                if self.lightning_mode.is_some() {
                    Self::create_lightning_client(
                        self.lightning_mode.clone().unwrap(),
                        self.task_group.make_subgroup().await,
                    )
                    .await?
                } else {
                    self.lnrpc.clone()
                }
            }
        };

        // Restart the subscription of HTLCs for each actor
        tracing::info!("Restarting HTLC subscription threads.");
        for actor in actors.values() {
            actor.write().await.subscribe_htlcs().await?;
        }

        Ok(())
    }

    pub async fn run(mut self, listen: SocketAddr, password: String) -> Result<()> {
        let mut tg = self.task_group.clone();

        let sender = GatewayRpcSender::new(self.sender.clone());
        tg.spawn("Gateway Webserver", move |server_ctrl| async move {
            let mut webserver = tokio::spawn(run_webserver(password, listen, sender));

            // Shut down webserver if requested
            if server_ctrl.is_shutting_down() {
                webserver.abort();
                let _ = futures::executor::block_on(&mut webserver);
            }
        })
        .await;

        // TODO: try to drive forward outgoing and incoming payments that were
        // interrupted
        let loop_ctrl = tg.make_handle();
        loop {
            // Shut down main loop if requested
            if loop_ctrl.is_shutting_down() {
                break;
            }

            let least_wait_until = Instant::now() + Duration::from_millis(100);

            // Handle messages from webserver and plugin
            while let Ok(msg) = self.receiver.try_recv() {
                tracing::trace!("Gateway received message {:?}", msg);
                match msg {
                    GatewayRequest::Info(inner) => {
                        inner
                            .handle(&mut self, |gateway, payload| {
                                gateway.handle_get_info(payload)
                            })
                            .await;
                    }
                    GatewayRequest::ConnectFederation(inner) => {
                        let route_hints: Vec<RouteHint> =
                            self.lnrpc.read().await.routehints().await?.try_into()?;
                        inner
                            .handle(&mut self, |gateway, payload| {
                                gateway.handle_connect_federation(payload, route_hints.clone())
                            })
                            .await;
                    }
                    GatewayRequest::PayInvoice(inner) => {
                        inner
                            .handle(&mut self, |gateway, payload| {
                                gateway.handle_pay_invoice_msg(payload)
                            })
                            .await;
                    }
                    GatewayRequest::Balance(inner) => {
                        inner
                            .handle(&mut self, |gateway, payload| {
                                gateway.handle_balance_msg(payload)
                            })
                            .await;
                    }
                    GatewayRequest::DepositAddress(inner) => {
                        inner
                            .handle(&mut self, |gateway, payload| {
                                gateway.handle_address_msg(payload)
                            })
                            .await;
                    }
                    GatewayRequest::Deposit(inner) => {
                        inner
                            .handle(&mut self, |gateway, payload| {
                                gateway.handle_deposit_msg(payload)
                            })
                            .await;
                    }
                    GatewayRequest::Withdraw(inner) => {
                        inner
                            .handle(&mut self, |gateway, payload| {
                                gateway.handle_withdraw_msg(payload)
                            })
                            .await;
                    }
                    GatewayRequest::Backup(inner) => {
                        inner
                            .handle(&mut self, |gateway, payload| {
                                gateway.handle_backup_msg(payload)
                            })
                            .await;
                    }
                    GatewayRequest::Restore(inner) => {
                        inner
                            .handle(&mut self, |gateway, payload| {
                                gateway.handle_restore_msg(payload)
                            })
                            .await;
                    }
                    GatewayRequest::LightningReconnect(inner) => {
                        inner
                            .handle(&mut self, |gateway, payload| {
                                gateway.handle_lightning_reconnect(payload)
                            })
                            .await;
                    }
                }
            }

            fedimint_core::task::sleep_until(least_wait_until).await;
        }
        Ok(())
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        futures::executor::block_on(self.task_group.shutdown());
    }
}
