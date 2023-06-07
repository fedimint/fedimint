pub mod actor;
pub mod client;
pub mod db;
pub mod lnd;
pub mod lnrpc_client;
pub mod ng;
pub mod rpc;
pub mod types;
pub mod utils;

pub mod gatewaylnrpc {
    tonic::include_proto!("gatewaylnrpc");
}

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::Address;
use bitcoin_hashes::hex::ToHex;
use clap::Subcommand;
use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_client_legacy::ln::PayInvoicePayload;
use fedimint_client_legacy::modules::ln::route_hints::RouteHint;
use fedimint_client_legacy::{ClientError, GatewayClient};
use fedimint_core::api::{FederationError, WsClientConnectInfo};
use fedimint_core::config::FederationId;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{self, RwLock, TaskGroup, TaskHandle};
use fedimint_core::{Amount, TransactionId};
use fedimint_ln_client::contracts::Preimage;
use futures::stream::StreamExt;
use gatewaylnrpc::intercept_htlc_response::Action;
use gatewaylnrpc::{GetNodeInfoResponse, InterceptHtlcResponse};
use lightning::routing::gossip::RoutingFees;
use lnrpc_client::{ILnRpcClient, RouteHtlcStream};
use rpc::FederationInfo;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use url::Url;

use crate::actor::GatewayActor;
use crate::client::DynGatewayClientBuilder;
use crate::gatewaylnrpc::intercept_htlc_response::Forward;
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

pub const DEFAULT_FEES: RoutingFees = RoutingFees {
    /// Base routing fee. Default is 0 msat
    base_msat: 0,
    /// Liquidity-based routing fee in millionths of a routed amount.
    /// In other words, 10000 is 1%. The default is 10000 (1%).
    proportional_millionths: 10000,
};

pub type Result<T> = std::result::Result<T, GatewayError>;

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum LightningMode {
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
    #[error("Failed to open the database")]
    DatabaseError,
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
    lnrpc: Arc<dyn ILnRpcClient>,
    lightning_mode: Option<LightningMode>,
    actors: Arc<RwLock<BTreeMap<FederationId, GatewayActor>>>,
    scid_to_federation: Arc<RwLock<BTreeMap<u64, FederationId>>>,
    client_builder: DynGatewayClientBuilder,
    sender: mpsc::Sender<GatewayRequest>,
    receiver: mpsc::Receiver<GatewayRequest>,
    channel_id_generator: AtomicU64,
    fees: RoutingFees,
    gatewayd_db: Database,
}

impl Gateway {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        lightning_mode: LightningMode,
        client_builder: DynGatewayClientBuilder,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
        task_group: &mut TaskGroup,
        fees: RoutingFees,
        gatewayd_db: Database,
    ) -> Result<Self> {
        // Create message channels for the webserver
        let (sender, receiver) = mpsc::channel::<GatewayRequest>(100);

        let lnrpc = Self::create_lightning_client(lightning_mode.clone()).await?;

        let mut gw = Self {
            lnrpc,
            actors: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            sender,
            receiver,
            client_builder,
            channel_id_generator: AtomicU64::new(INITIAL_SCID),
            decoders: decoders.clone(),
            module_gens: module_gens.clone(),
            lightning_mode: Some(lightning_mode),
            fees,
            gatewayd_db,
        };

        gw.load_actors(decoders, module_gens).await?;
        gw.route_htlcs(task_group).await?;

        Ok(gw)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_lightning_connection(
        lnrpc: Arc<dyn ILnRpcClient>,
        client_builder: DynGatewayClientBuilder,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
        fees: RoutingFees,
        gatewayd_db: Database,
        task_group: &mut TaskGroup,
    ) -> Result<Self> {
        // Create message channels for the webserver
        let (sender, receiver) = mpsc::channel::<GatewayRequest>(100);

        let mut gw = Self {
            lnrpc,
            actors: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            sender,
            receiver,
            client_builder,
            channel_id_generator: AtomicU64::new(INITIAL_SCID),
            decoders: decoders.clone(),
            module_gens: module_gens.clone(),
            lightning_mode: None,
            fees,
            gatewayd_db,
        };

        gw.load_actors(decoders, module_gens).await?;
        gw.route_htlcs(task_group).await?;

        Ok(gw)
    }

    async fn create_lightning_client(mode: LightningMode) -> Result<Arc<dyn ILnRpcClient>> {
        let lnrpc: Arc<dyn ILnRpcClient> = match mode {
            LightningMode::Cln { cln_extension_addr } => {
                info!(
                    "Gateway configured to connect to remote LnRpcClient at \n cln extension address: {:?} ",
                    cln_extension_addr
                );
                Arc::new(NetworkLnRpcClient::new(cln_extension_addr).await?)
            }
            LightningMode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            } => {
                info!(
                    "Gateway configured to connect to LND LnRpcClient at \n address: {:?},\n tls cert path: {:?},\n macaroon path: {} ",
                    lnd_rpc_addr, lnd_tls_cert, lnd_macaroon
                );
                Arc::new(GatewayLndClient::new(lnd_rpc_addr, lnd_tls_cert, lnd_macaroon).await?)
            }
        };

        Ok(lnrpc)
    }

    pub async fn route_htlcs(&mut self, task_group: &mut TaskGroup) -> Result<()> {
        // Create a stream used to communicate with the Lightning implementation
        let (sender, ln_receiver) = mpsc::channel::<InterceptHtlcResponse>(100);

        let mut lnrpc: Box<dyn ILnRpcClient> = match &self.lightning_mode {
            Some(LightningMode::Cln { cln_extension_addr }) => {
                info!(
                    "Gateway configured to connect to remote LnRpcClient at \n cln extension address: {:?} ",
                    cln_extension_addr
                );
                Box::new(NetworkLnRpcClient::new(cln_extension_addr.clone()).await?)
            }
            Some(LightningMode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            }) => Box::new(
                GatewayLndClient::new(
                    lnd_rpc_addr.clone(),
                    lnd_tls_cert.clone(),
                    lnd_macaroon.clone(),
                )
                .await?,
            ),
            _ => return Ok(()),
        };

        let mut stream: RouteHtlcStream = lnrpc.route_htlcs(ln_receiver.into(), task_group).await?;

        let scid_to_federation = self.scid_to_federation.clone();
        let actors = self.actors.clone();
        task_group
            .spawn(
                "Subscribe to intercepted HTLCs in stream",
                move |handle| async move {
                    // TODO: Need to recreate the lightning connection if it breaks while processing
                    // HTLCs
                    while let Some(Ok(htlc)) = stream.next().await {
                        if handle.is_shutting_down() {
                            break;
                        }

                        let scid_to_feds = scid_to_federation.read().await;
                        let federation_id = scid_to_feds.get(&htlc.short_channel_id);
                        let outcome = {
                            // Just forward the HTLC if we do not have a federation that
                            // corresponds to the short channel id
                            if let Some(federation_id) = federation_id {
                                let actors = actors.read().await;
                                let actor = actors.get(federation_id);
                                // Just forward the HTLC if we do not have an actor that
                                // corresponds to the federation id
                                if let Some(actor) = actor {
                                    actor.handle_intercepted_htlc(htlc).await
                                } else {
                                    InterceptHtlcResponse {
                                        action: Some(Action::Forward(Forward {})),
                                        incoming_chan_id: htlc.incoming_chan_id,
                                        htlc_id: htlc.htlc_id,
                                    }
                                }
                            } else {
                                InterceptHtlcResponse {
                                    action: Some(Action::Forward(Forward {})),
                                    incoming_chan_id: htlc.incoming_chan_id,
                                    htlc_id: htlc.htlc_id,
                                }
                            }
                        };

                        if let Err(error) = sender.send(outcome).await {
                            error!("Error sending HTLC response to lightning node: {error:?}");
                        }
                    }
                },
            )
            .await;
        Ok(())
    }

    async fn load_actors(
        &mut self,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
    ) -> Result<()> {
        // Fetch route hints form the LN node
        let mut num_retries = 0;
        let (route_hints, node_pub_key) = loop {
            let route_hints: Vec<RouteHint> = self
                .lnrpc
                .routehints()
                .await
                .expect("Could not fetch route hints")
                .try_into()
                .expect("Could not parse route hints");

            let GetNodeInfoResponse { pub_key, alias: _ } = self.lnrpc.info().await?;
            let node_pub_key = PublicKey::from_slice(&pub_key)
                .map_err(|e| GatewayError::Other(anyhow!("Invalid node pubkey {}", e)))?;

            if !route_hints.is_empty() || num_retries == ROUTE_HINT_RETRIES {
                break (route_hints, node_pub_key);
            }

            info!(
                ?num_retries,
                "LN node returned no route hints, trying again in {}s",
                ROUTE_HINT_RETRY_SLEEP.as_secs()
            );
            num_retries += 1;
            task::sleep(ROUTE_HINT_RETRY_SLEEP).await;
        };

        let dbtx = self.gatewayd_db.begin_transaction().await;
        if let Ok(configs) = self.client_builder.load_configs(dbtx, node_pub_key).await {
            let mut next_channel_id = self.channel_id_generator.load(Ordering::SeqCst);

            for config in configs {
                let client = self
                    .client_builder
                    .build(config.clone(), decoders.clone(), module_gens.clone())
                    .await
                    .expect("Could not build federation client");

                if let Err(e) = self
                    .load_actor(
                        Arc::new(client),
                        route_hints.clone(),
                        config.mint_channel_id,
                    )
                    .await
                {
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
        &mut self,
        client: Arc<GatewayClient>,
        route_hints: Vec<RouteHint>,
        scid: u64,
    ) -> Result<GatewayActor> {
        let actor = GatewayActor::new(
            client.clone(),
            self.lnrpc.clone(),
            route_hints,
            // TODO: This task group will go away with the new client
            &mut TaskGroup::new(),
        )
        .await?;

        self.actors
            .write()
            .await
            .insert(client.config().client_config.federation_id, actor.clone());
        self.scid_to_federation
            .write()
            .await
            .insert(scid, client.config().client_config.federation_id);
        Ok(actor)
    }

    async fn select_actor(&self, federation_id: FederationId) -> Result<GatewayActor> {
        self.actors
            .read()
            .await
            .get(&federation_id)
            .cloned()
            .ok_or(GatewayError::Other(anyhow::anyhow!(
                "No federation with id {}",
                federation_id.to_string()
            )))
    }

    async fn handle_connect_federation(
        &mut self,
        payload: ConnectFedPayload,
        route_hints: Vec<RouteHint>,
        fees: RoutingFees,
    ) -> Result<FederationInfo> {
        let connect = WsClientConnectInfo::from_str(&payload.connect).map_err(|e| {
            GatewayError::Other(anyhow::anyhow!("Invalid federation member string {}", e))
        })?;

        if let Ok(actor) = self.select_actor(connect.id).await {
            info!("Federation {} already connected", connect.id);
            return actor.get_info();
        }

        let GetNodeInfoResponse { pub_key, alias: _ } = self.lnrpc.info().await?;
        let node_pub_key = PublicKey::from_slice(&pub_key)
            .map_err(|e| GatewayError::Other(anyhow!("Invalid node pubkey {}", e)))?;

        // The gateway deterministically assigns a channel id (u64) to each federation
        // connected. TODO: explicitly handle the case where the channel id
        // overflows
        let channel_id = self.channel_id_generator.fetch_add(1, Ordering::SeqCst);

        let gw_client_cfg = self
            .client_builder
            .create_config(connect, channel_id, node_pub_key, fees)
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
            .load_actor(client.clone(), route_hints, channel_id)
            .await
            .map_err(|e| {
                GatewayError::Other(anyhow::anyhow!("Failed to connect federation {}", e))
            })?;

        let dbtx = self.gatewayd_db.begin_transaction().await;
        if let Err(e) = self
            .client_builder
            .save_config(client.config(), payload.connect, dbtx)
            .await
        {
            warn!(
                "Failed to save default federation client configuration: {}",
                e
            );
        }

        let federation_info = actor.get_info()?;

        Ok(federation_info)
    }

    async fn handle_get_info(&self, _payload: InfoPayload) -> Result<GatewayInfo> {
        let actors = self.actors.read().await;
        let mut federations: Vec<FederationInfo> = Vec::new();
        for actor in actors.values() {
            federations.push(actor.get_info()?);
        }

        let ln_info = self.lnrpc.info().await?;

        Ok(GatewayInfo {
            federations,
            version_hash: env!("CODE_VERSION").to_string(),
            lightning_pub_key: ln_info.pub_key.to_hex(),
            lightning_alias: ln_info.alias,
            fees: self.fees,
        })
    }

    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<Preimage> {
        let PayInvoicePayload {
            federation_id,
            contract_id,
        } = payload;

        let actor = self.select_actor(federation_id).await?;
        let (outpoint, preimage) = actor.pay_invoice(contract_id).await?;
        actor
            .await_outgoing_contract_claimed(contract_id, outpoint)
            .await?;
        Ok(preimage)
    }

    async fn handle_balance_msg(&self, payload: BalancePayload) -> Result<Amount> {
        self.select_actor(payload.federation_id)
            .await?
            .get_balance()
            .await
    }

    async fn handle_address_msg(&self, payload: DepositAddressPayload) -> Result<Address> {
        self.select_actor(payload.federation_id)
            .await?
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
            .withdraw(amount, address)
            .await
    }

    async fn handle_backup_msg(
        &self,
        BackupPayload { federation_id }: BackupPayload,
    ) -> Result<()> {
        self.select_actor(federation_id).await?.backup().await
    }

    async fn handle_restore_msg(
        &self,
        RestorePayload { federation_id }: RestorePayload,
    ) -> Result<()> {
        self.select_actor(federation_id).await?.restore().await
    }

    pub async fn spawn_webserver(
        &self,
        listen: SocketAddr,
        password: String,
        task_group: &mut TaskGroup,
    ) {
        let sender = GatewayRpcSender::new(self.sender.clone());
        let tx = run_webserver(password, listen, sender, task_group)
            .await
            .expect("Failed to start webserver");

        // TODO: try to drive forward outgoing and incoming payments that were
        // interrupted
        let loop_ctrl = task_group.make_handle();
        let shutdown_sender = self.sender.clone();
        loop_ctrl
            .on_shutdown(Box::new(|| {
                Box::pin(async move {
                    // Send shutdown signal to the webserver
                    let _ = tx.send(());

                    // Send shutdown signal to the handler loop
                    let _ = shutdown_sender.send(GatewayRequest::Shutdown).await;
                })
            }))
            .await;
    }

    pub async fn run(mut self, loop_ctrl: TaskHandle) -> Result<()> {
        // Handle messages from webserver and plugin
        while let Some(msg) = self.receiver.recv().await {
            tracing::trace!("Gateway received message {:?}", msg);

            // Shut down main loop if requested
            if loop_ctrl.is_shutting_down() {
                break;
            }

            match msg {
                GatewayRequest::Info(inner) => {
                    inner
                        .handle(&mut self, |gateway, payload| {
                            gateway.handle_get_info(payload)
                        })
                        .await;
                }
                GatewayRequest::ConnectFederation(inner) => {
                    let route_hints: Vec<RouteHint> = self.lnrpc.routehints().await?.try_into()?;
                    let fees = self.fees;

                    inner
                        .handle(&mut self, |gateway, payload| {
                            gateway.handle_connect_federation(payload, route_hints.clone(), fees)
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
                GatewayRequest::Shutdown => {
                    info!("Gatewayd received shutdown request");
                    break;
                }
            }
        }

        Ok(())
    }
}
