pub mod client;
pub mod db;
pub mod lnd;
pub mod lnrpc_client;
pub mod ng;
pub mod rpc;
pub mod types;
pub mod utils;

pub mod gateway_lnrpc {
    tonic::include_proto!("gateway_lnrpc");
}

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::{Address, Txid};
use bitcoin_hashes::hex::ToHex;
use clap::{Parser, Subcommand};
use client::StandardGatewayClientBuilder;
use db::{FederationRegistrationKey, GatewayPublicKey};
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitRegistry};
use fedimint_client::Client;
use fedimint_core::api::{FederationError, InviteCode};
use fedimint_core::config::FederationId;
use fedimint_core::core::{
    ModuleInstanceId, ModuleKind, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::Database;
use fedimint_core::module::CommonModuleInit;
use fedimint_core::task::{sleep, RwLock, TaskGroup, TaskHandle, TaskShutdownToken};
use fedimint_core::time::now;
use fedimint_core::Amount;
use fedimint_ln_client::contracts::Preimage;
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_ln_common::config::GatewayFee;
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_mint_client::{MintClientGen, MintCommonGen};
use fedimint_wallet_client::{WalletClientExt, WalletClientGen, WalletCommonGen, WithdrawState};
use futures::stream::StreamExt;
use gateway_lnrpc::intercept_htlc_response::Action;
use gateway_lnrpc::{GetNodeInfoResponse, InterceptHtlcResponse};
use lightning::routing::gossip::RoutingFees;
use lnrpc_client::{ILnRpcClient, LightningBuilder, LightningRpcError, RouteHtlcStream};
use ng::pay::OutgoingPaymentError;
use ng::GatewayClientExt;
use rand::rngs::OsRng;
use rand::Rng;
use rpc::FederationInfo;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::gateway_lnrpc::intercept_htlc_response::Forward;
use crate::lnrpc_client::GatewayLightningBuilder;
use crate::ng::GatewayExtPayStates;
use crate::rpc::rpc_server::run_webserver;
use crate::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, GatewayInfo,
    InfoPayload, RestorePayload, WithdrawPayload,
};

/// LND HTLC interceptor can't handle SCID of 0, so start from 1
pub const INITIAL_SCID: u64 = 1;

/// How long a gateway announcement stays valid
pub const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

const ROUTE_HINT_RETRIES: usize = 30;
const ROUTE_HINT_RETRY_SLEEP: Duration = Duration::from_secs(2);

pub const DEFAULT_FEES: RoutingFees = RoutingFees {
    /// Base routing fee. Default is 0 msat
    base_msat: 0,
    /// Liquidity-based routing fee in millionths of a routed amount.
    /// In other words, 10000 is 1%. The default is 10000 (1%).
    proportional_millionths: 10000,
};

pub type Result<T> = std::result::Result<T, GatewayError>;

const DB_FILE: &str = "gatewayd.db";

const DEFAULT_MODULE_KINDS: [(ModuleInstanceId, &ModuleKind); 2] = [
    (LEGACY_HARDCODED_INSTANCE_ID_MINT, &MintCommonGen::KIND),
    (LEGACY_HARDCODED_INSTANCE_ID_WALLET, &WalletCommonGen::KIND),
];

#[derive(Parser)]
pub struct GatewayOpts {
    #[clap(subcommand)]
    mode: LightningMode,

    /// Path to folder containing gateway config and data files
    #[arg(long = "data-dir", env = "FM_GATEWAY_DATA_DIR")]
    pub data_dir: PathBuf,

    /// Gateway webserver listen address
    #[arg(long = "listen", env = "FM_GATEWAY_LISTEN_ADDR")]
    pub listen: SocketAddr,

    /// Public URL from which the webserver API is reachable
    #[arg(long = "api-addr", env = "FM_GATEWAY_API_ADDR")]
    pub api_addr: Url,

    /// Gateway webserver authentication password
    #[arg(long = "password", env = "FM_GATEWAY_PASSWORD")]
    pub password: String,

    /// Configured gateway routing fees
    /// Format: <base_msat>,<proportional_millionths>
    #[arg(long = "fees", env = "FM_GATEWAY_FEES")]
    pub fees: Option<GatewayFee>,

    /// Number of route hints to return in invoices
    #[arg(long = "num-route-hints", env = "FM_NUMBER_OF_ROUTE_HINTS")]
    pub num_route_hints: Option<usize>,
}

/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///    Initializing -- begin intercepting HTLCs --> Running
///    Running -- disconnected from lightning node --> Disconnected
///    Disconnected -- re-established lightning connection --> Running
/// ```
#[derive(Clone)]
pub enum GatewayState {
    Initializing,
    Running {
        lnrpc: Arc<dyn ILnRpcClient>,
        lightning_public_key: PublicKey,
        lightning_alias: String,
    },
    Disconnected,
}

#[derive(Clone)]
pub struct Gateway {
    lightning_builder: Arc<dyn LightningBuilder + Send + Sync>,
    listen: SocketAddr,
    api_addr: Url,
    password: String,
    num_route_hints: usize,
    pub state: Arc<RwLock<GatewayState>>,
    client_builder: StandardGatewayClientBuilder,
    gateway_db: Database,
    clients: Arc<RwLock<BTreeMap<FederationId, fedimint_client::Client>>>,
    scid_to_federation: Arc<RwLock<BTreeMap<u64, FederationId>>>,
    pub gateway_id: secp256k1::PublicKey,
    channel_id_generator: Arc<Mutex<AtomicU64>>,
    fees: RoutingFees,
}

impl Gateway {
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_custom_registry(
        lightning_builder: Arc<dyn LightningBuilder + Send + Sync>,
        client_builder: StandardGatewayClientBuilder,
        listen: SocketAddr,
        api_addr: Url,
        password: String,
        fees: RoutingFees,
        num_route_hints: usize,
        gateway_db: Database,
    ) -> anyhow::Result<Gateway> {
        Ok(Gateway {
            lightning_builder,
            listen,
            api_addr,
            password,
            num_route_hints,
            state: Arc::new(RwLock::new(GatewayState::Initializing)),
            client_builder,
            gateway_db: gateway_db.clone(),
            clients: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            gateway_id: Gateway::get_gateway_id(gateway_db).await,
            channel_id_generator: Arc::new(Mutex::new(AtomicU64::new(INITIAL_SCID))),
            fees,
        })
    }

    pub async fn new_with_default_modules() -> anyhow::Result<Gateway> {
        let mut args = std::env::args();

        if let Some(ref arg) = args.nth(1) {
            if arg.as_str() == "version-hash" {
                println!("{}", env!("FEDIMINT_BUILD_CODE_VERSION"));
                std::process::exit(0);
            }
        }

        // Read configurations
        let GatewayOpts {
            mode,
            data_dir,
            listen,
            api_addr,
            password,
            fees,
            num_route_hints,
        } = GatewayOpts::parse();

        // Gateway module will be attached when the federation clients are created
        // because the LN RPC will be injected with `GatewayClientGen`.
        let mut registry = ClientModuleInitRegistry::new();
        registry.attach(MintClientGen);
        registry.attach(WalletClientGen::default());

        let decoders = registry.available_decoders(DEFAULT_MODULE_KINDS.iter().cloned())?;

        let gateway_db = Database::new(
            fedimint_rocksdb::RocksDb::open(data_dir.join(DB_FILE))?,
            decoders.clone(),
        );

        let client_builder = StandardGatewayClientBuilder::new(
            data_dir.clone(),
            registry.clone(),
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
        );

        info!(
            "Starting gatewayd (version: {})",
            env!("FEDIMINT_BUILD_CODE_VERSION")
        );

        Ok(Self {
            lightning_builder: Arc::new(GatewayLightningBuilder {
                lightning_mode: mode,
            }),
            listen,
            api_addr,
            password,
            channel_id_generator: Arc::new(Mutex::new(AtomicU64::new(INITIAL_SCID))),
            fees: fees.unwrap_or(GatewayFee(DEFAULT_FEES)).0,
            num_route_hints: num_route_hints.unwrap_or(0),
            state: Arc::new(RwLock::new(GatewayState::Initializing)),
            client_builder,
            gateway_id: Self::get_gateway_id(gateway_db.clone()).await,
            gateway_db,
            clients: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }

    pub async fn get_gateway_id(gateway_db: Database) -> secp256k1::PublicKey {
        let mut dbtx = gateway_db.begin_transaction().await;
        if let Some(key_pair) = dbtx.get_value(&GatewayPublicKey {}).await {
            key_pair.public_key()
        } else {
            let context = secp256k1::Secp256k1::new();
            let (secret, public) = context.generate_keypair(&mut OsRng);
            let key_pair = secp256k1::KeyPair::from_secret_key(&context, &secret);
            dbtx.insert_new_entry(&GatewayPublicKey, &key_pair).await;
            dbtx.commit_tx().await;
            public
        }
    }

    pub async fn run(self) -> anyhow::Result<TaskShutdownToken> {
        let mut tg = TaskGroup::new();

        run_webserver(self.password.clone(), self.listen, self.clone(), &mut tg)
            .await
            .expect("Failed to start webserver");
        info!("Successfully started webserver");

        self.start_gateway(&mut tg).await?;
        let handle = tg.make_handle();
        let shutdown_receiver = handle.make_shutdown_rx().await;
        Ok(shutdown_receiver)
    }

    async fn start_gateway(mut self, task_group: &mut TaskGroup) -> Result<()> {
        let mut tg = task_group.make_subgroup().await;
        task_group
            .spawn(
                "Subscribe to intercepted HTLCs in stream",
                move |handle| async move {
                    loop {
                        if handle.is_shutting_down() {
                            break;
                        }

                        let lnrpc_route = self.lightning_builder.build().await;

                        // Re-create the HTLC stream if the connection breaks
                        match lnrpc_route
                            .route_htlcs(&mut tg)
                            .await
                        {
                            Ok((stream, ln_client)) => {
                                info!("Established HTLC stream");

                                match Self::fetch_lightning_node_info(ln_client.clone()).await {
                                    Ok((lightning_public_key, lightning_alias)) => {
                                        self.register_clients_timer(&mut tg).await;
                                        self.set_gateway_state(GatewayState::Running {
                                            lnrpc: ln_client,
                                            lightning_public_key,
                                            lightning_alias,

                                        }).await;
                                        self.load_clients().await.expect("Failed to load gateway clients");
                                        info!("Successfully loaded Gateway clients.");

                                        // Blocks until the connection to the lightning node breaks
                                        self.handle_htlc_stream(stream, handle.clone()).await;
                                        self.set_gateway_state(GatewayState::Disconnected).await;
                                        warn!("HTLC Stream Lightning connection broken. Gateway is disconnected");
                                    }
                                    Err(e) => {
                                        error!("Failed to retrieve Lightning info: {e:?}");
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("Failed to open HTLC stream: {e:?}");
                            }
                        }

                        error!("Disconnected from Lightning Node. Waiting 5 seconds and trying again");
                        sleep(Duration::from_secs(5)).await;
                    }
                },
            )
            .await;

        Ok(())
    }

    pub async fn handle_htlc_stream(&self, mut stream: RouteHtlcStream<'_>, handle: TaskHandle) {
        if let GatewayState::Running {
            lnrpc,
            lightning_public_key: _,
            lightning_alias: _,
        } = self.state.read().await.clone()
        {
            while let Some(Ok(htlc_request)) = stream.next().await {
                if handle.is_shutting_down() {
                    break;
                }

                let scid_to_feds = self.scid_to_federation.read().await;
                let federation_id = scid_to_feds.get(&htlc_request.short_channel_id);
                // Just forward the HTLC if we do not have a federation that
                // corresponds to the short channel id
                if let Some(federation_id) = federation_id {
                    let clients = self.clients.read().await;
                    let client = clients.get(federation_id);
                    // Just forward the HTLC if we do not have a client that
                    // corresponds to the federation id
                    if let Some(client) = client {
                        let htlc = htlc_request.clone().try_into();
                        if let Ok(htlc) = htlc {
                            if client.gateway_handle_intercepted_htlc(htlc).await.is_ok() {
                                continue;
                            }
                        }
                    }
                }

                let outcome = InterceptHtlcResponse {
                    action: Some(Action::Forward(Forward {})),
                    incoming_chan_id: htlc_request.incoming_chan_id,
                    htlc_id: htlc_request.htlc_id,
                };

                if let Err(error) = lnrpc.complete_htlc(outcome).await {
                    error!("Error sending HTLC response to lightning node: {error:?}");
                }
            }
        }
    }

    async fn fetch_lightning_node_info(
        lnrpc: Arc<dyn ILnRpcClient>,
    ) -> Result<(PublicKey, String)> {
        let GetNodeInfoResponse { pub_key, alias } = lnrpc.info().await?;
        let node_pub_key = PublicKey::from_slice(&pub_key)
            .map_err(|e| GatewayError::InvalidMetadata(format!("Invalid node pubkey {e}")))?;
        Ok((node_pub_key, alias))
    }

    async fn set_gateway_state(&mut self, state: GatewayState) {
        let mut lock = self.state.write().await;
        *lock = state;
    }

    pub async fn handle_get_info(&self, _payload: InfoPayload) -> Result<GatewayInfo> {
        if let GatewayState::Running {
            lnrpc,
            lightning_public_key,
            lightning_alias,
        } = self.state.read().await.clone()
        {
            let mut federations = Vec::new();
            let federation_clients = self.clients.read().await.clone().into_iter();
            let route_hints =
                Self::fetch_lightning_route_hints(lnrpc.clone(), self.num_route_hints).await?;
            for (federation_id, client) in federation_clients {
                federations.push(self.make_federation_info(&client, federation_id).await);
            }

            return Ok(GatewayInfo {
                federations,
                version_hash: env!("FEDIMINT_BUILD_CODE_VERSION").to_string(),
                lightning_pub_key: Some(lightning_public_key.to_hex()),
                lightning_alias: Some(lightning_alias.clone()),
                fees: self.fees,
                route_hints,
                gateway_id: self.gateway_id,
            });
        }

        Ok(GatewayInfo {
            federations: vec![],
            version_hash: env!("FEDIMINT_BUILD_CODE_VERSION").to_string(),
            lightning_pub_key: None,
            lightning_alias: None,
            fees: self.fees,
            route_hints: vec![],
            gateway_id: self.gateway_id,
        })
    }

    pub async fn handle_balance_msg(&self, payload: BalancePayload) -> Result<Amount> {
        Ok(self
            .select_client(payload.federation_id)
            .await?
            .get_balance()
            .await)
    }

    pub async fn handle_address_msg(&self, payload: DepositAddressPayload) -> Result<Address> {
        let (_, address) = self
            .select_client(payload.federation_id)
            .await?
            .get_deposit_address(now() + Duration::from_secs(86400 * 365))
            .await?;
        Ok(address)
    }

    pub async fn handle_withdraw_msg(&self, payload: WithdrawPayload) -> Result<Txid> {
        let WithdrawPayload {
            amount,
            address,
            federation_id,
        } = payload;

        let client = self.select_client(federation_id).await?;
        // TODO: This should probably be passed in as a parameter
        let fees = client.get_withdraw_fee(address.clone(), amount).await?;

        let operation_id = client.withdraw(address, amount, fees).await?;
        let mut updates = client
            .subscribe_withdraw_updates(operation_id)
            .await?
            .into_stream();

        while let Some(update) = updates.next().await {
            match update {
                WithdrawState::Succeeded(txid) => {
                    return Ok(txid);
                }
                WithdrawState::Failed(e) => {
                    return Err(GatewayError::UnexpectedState(e));
                }
                _ => {}
            }
        }

        Err(GatewayError::UnexpectedState(
            "Ran out of state updates while withdrawing".to_string(),
        ))
    }

    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<Preimage> {
        if let GatewayState::Running {
            lnrpc: _,
            lightning_public_key: _,
            lightning_alias: _,
        } = self.state.read().await.clone()
        {
            let PayInvoicePayload {
                federation_id,
                contract_id,
            } = payload;

            let client = self.select_client(federation_id).await?;
            let operation_id = client.gateway_pay_bolt11_invoice(contract_id).await?;
            let mut updates = client
                .gateway_subscribe_ln_pay(operation_id)
                .await?
                .into_stream();

            while let Some(update) = updates.next().await {
                match update {
                    GatewayExtPayStates::Success {
                        preimage,
                        outpoint: _,
                    } => return Ok(preimage),
                    GatewayExtPayStates::Fail {
                        error,
                        error_message,
                    } => {
                        error!(error_message);
                        return Err(GatewayError::OutgoingPaymentError(Box::new(error)));
                    }
                    GatewayExtPayStates::Canceled { error } => {
                        return Err(GatewayError::OutgoingPaymentError(Box::new(error)));
                    }
                    _ => {}
                };
            }

            return Err(GatewayError::UnexpectedState(
                "Ran out of state updates while paying invoice".to_string(),
            ));
        }

        Err(GatewayError::Disconnected)
    }

    async fn handle_connect_federation(
        &mut self,
        payload: ConnectFedPayload,
    ) -> Result<FederationInfo> {
        if let GatewayState::Running {
            lnrpc,
            lightning_public_key,
            lightning_alias: _,
        } = self.state.read().await.clone()
        {
            let invite_code = InviteCode::from_str(&payload.invite_code).map_err(|e| {
                GatewayError::InvalidMetadata(format!("Invalid federation member string {e:?}"))
            })?;

            // The gateway deterministically assigns a channel id (u64) to each federation
            // connected. TODO: explicitly handle the case where the channel id
            // overflows
            let channel_id = self
                .channel_id_generator
                .lock()
                .await
                .fetch_add(1, Ordering::SeqCst);

            // Downloading the config can fail if another user tries to download at the same
            // time. Just retry after a small delay
            let gw_client_cfg = loop {
                match self
                    .client_builder
                    .create_config(invite_code.clone(), channel_id, self.fees)
                    .await
                {
                    Ok(gw_client_cfg) => break gw_client_cfg,
                    Err(_) => {
                        let random_delay: f64 = rand::thread_rng().gen();
                        tracing::warn!(
                            "Error downloading client config, trying again in {random_delay}"
                        );
                        sleep(Duration::from_secs_f64(random_delay)).await;
                    }
                }
            };

            let federation_id = gw_client_cfg.config.global.federation_id;
            let route_hints =
                Self::fetch_lightning_route_hints(lnrpc.clone(), self.num_route_hints).await?;
            let old_client = self.clients.read().await.get(&federation_id).cloned();

            let client = self
                .client_builder
                .build(
                    gw_client_cfg.clone(),
                    lightning_public_key,
                    lnrpc.clone(),
                    old_client,
                )
                .await?;

            let federation_info = self.make_federation_info(&client, federation_id).await;

            client
                .register_with_federation(
                    self.api_addr.clone(),
                    route_hints,
                    GW_ANNOUNCEMENT_TTL,
                    self.gateway_id,
                )
                .await?;
            self.clients.write().await.insert(federation_id, client);
            self.scid_to_federation
                .write()
                .await
                .insert(channel_id, federation_id);

            let dbtx = self.gateway_db.begin_transaction().await;
            self.client_builder
                .save_config(gw_client_cfg.clone(), dbtx)
                .await?;

            return Ok(federation_info);
        }

        Err(GatewayError::Disconnected)
    }

    pub async fn handle_backup_msg(
        &self,
        BackupPayload { federation_id: _ }: BackupPayload,
    ) -> Result<()> {
        unimplemented!("Backup is not currently supported");
    }

    pub async fn handle_restore_msg(
        &self,
        RestorePayload { federation_id: _ }: RestorePayload,
    ) -> Result<()> {
        unimplemented!("Restore is not currently supported");
    }

    pub async fn remove_client(
        &self,
        federation_id: FederationId,
    ) -> Result<fedimint_client::Client> {
        let client = self.clients.write().await.remove(&federation_id).ok_or(
            GatewayError::InvalidMetadata(format!("No federation with id {federation_id}")),
        )?;
        let mut dbtx = self.gateway_db.begin_transaction().await;
        dbtx.remove_entry(&FederationRegistrationKey { id: federation_id })
            .await;
        dbtx.commit_tx().await;
        Ok(client)
    }

    pub async fn select_client(
        &self,
        federation_id: FederationId,
    ) -> Result<fedimint_client::Client> {
        self.clients
            .read()
            .await
            .get(&federation_id)
            .cloned()
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))
    }

    async fn load_clients(&mut self) -> Result<()> {
        if let GatewayState::Running {
            lnrpc,
            lightning_public_key,
            lightning_alias: _,
        } = self.state.read().await.clone()
        {
            let dbtx = self.gateway_db.begin_transaction().await;
            if let Ok(configs) = self.client_builder.load_configs(dbtx).await {
                let channel_id_generator = self.channel_id_generator.lock().await;
                let mut next_channel_id = channel_id_generator.load(Ordering::SeqCst);

                for config in configs {
                    let federation_id = config.config.global.federation_id;
                    let old_client = self.clients.read().await.get(&federation_id).cloned();
                    let client = self
                        .client_builder
                        .build(
                            config.clone(),
                            lightning_public_key,
                            lnrpc.clone(),
                            old_client,
                        )
                        .await?;

                    // Registering each client happens in the background, since we're loading the
                    // clients for the first time, just add them to the in-memory
                    // maps
                    let scid = config.mint_channel_id;
                    self.clients.write().await.insert(federation_id, client);
                    self.scid_to_federation
                        .write()
                        .await
                        .insert(scid, federation_id);

                    if config.mint_channel_id > next_channel_id {
                        next_channel_id = config.mint_channel_id + 1;
                    }
                }
                channel_id_generator.store(next_channel_id, Ordering::SeqCst);
            }
            return Ok(());
        }

        Err(GatewayError::Disconnected)
    }

    async fn register_clients_timer(&mut self, task_group: &mut TaskGroup) {
        if let GatewayState::Running {
            lnrpc,
            lightning_public_key: _,
            lightning_alias: _,
        } = self.state.read().await.clone()
        {
            let clients = self.clients.clone();
            let api = self.api_addr.clone();
            let gateway_id = self.gateway_id;
            let num_route_hints = self.num_route_hints;
            task_group
                .spawn("register clients", move |handle| async move {
                    while !handle.is_shutting_down() {
                        // Allow a 15% buffer of the TTL before the re-registering gateway
                        // with the federations.
                        let registration_delay = GW_ANNOUNCEMENT_TTL.mul_f32(0.85);
                        sleep(registration_delay).await;

                        match Self::fetch_lightning_route_hints(lnrpc.clone(), num_route_hints).await {
                            Ok(route_hints) => {
                                for (federation_id, client) in clients.read().await.iter() {
                                    if let Err(e) = client
                                        .register_with_federation(
                                            api.clone(),
                                            route_hints.clone(),
                                            GW_ANNOUNCEMENT_TTL,
                                            gateway_id,
                                        )
                                        .await
                                    {
                                        error!("Error registering federation {federation_id}: {e:?}");
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    "Could not retrieve route hints, gateway will not be registered: {e:?}"
                                );
                            }
                        }
                    }
                })
                .await;
        }
    }

    async fn fetch_lightning_route_hints_try(
        lnrpc: &dyn ILnRpcClient,
        num_route_hints: usize,
    ) -> Result<Vec<RouteHint>> {
        let route_hints = lnrpc
            .routehints(num_route_hints)
            .await?
            .try_into()
            .expect("Could not parse route hints");

        Ok(route_hints)
    }

    async fn fetch_lightning_route_hints(
        lnrpc: Arc<dyn ILnRpcClient>,
        num_route_hints: usize,
    ) -> Result<Vec<RouteHint>> {
        if num_route_hints == 0 {
            return Ok(vec![]);
        }

        for num_retries in 0.. {
            let route_hints = match Self::fetch_lightning_route_hints_try(
                lnrpc.as_ref(),
                num_route_hints,
            )
            .await
            {
                Ok(res) => res,
                Err(e) => {
                    if num_retries == ROUTE_HINT_RETRIES {
                        return Err(e);
                    }
                    warn!("Could not fetch route hints: {e}");
                    sleep(ROUTE_HINT_RETRY_SLEEP).await;
                    continue;
                }
            };

            if !route_hints.is_empty() || num_retries == ROUTE_HINT_RETRIES {
                return Ok(route_hints);
            }

            info!(
                ?num_retries,
                "LN node returned no route hints, trying again in {}s",
                ROUTE_HINT_RETRY_SLEEP.as_secs()
            );
            sleep(ROUTE_HINT_RETRY_SLEEP).await;
        }

        unreachable!();
    }

    async fn make_federation_info(
        &self,
        client: &Client,
        federation_id: FederationId,
    ) -> FederationInfo {
        let balance_msat = client.get_balance().await;
        let config = client.get_config().clone();

        FederationInfo {
            federation_id,
            balance_msat,
            config,
        }
    }
}

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
    #[error("Federation error: {0:?}")]
    FederationError(#[from] FederationError),
    #[error("Other: {0:?}")]
    ClientStateMachineError(#[from] anyhow::Error),
    #[error("Failed to open the database: {0:?}")]
    DatabaseError(anyhow::Error),
    #[error("Federation client error")]
    LightningRpcError(#[from] LightningRpcError),
    #[error("Outgoing Payment Error {0:?}")]
    OutgoingPaymentError(#[from] Box<OutgoingPaymentError>),
    #[error("Invalid Metadata: {0}")]
    InvalidMetadata(String),
    #[error("Unexpected state: {0}")]
    UnexpectedState(String),
    #[error("The gateway is disconnected")]
    Disconnected,
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        // For privacy reasons, we do not return too many details about the failure of
        // the request back to the client to prevent malicious clients from
        // deducing state about the gateway/lightning node.
        let (error_message, status_code) = match self {
            GatewayError::OutgoingPaymentError(_) => (
                "Error while paying lightning invoice. Outgoing contract will be refunded."
                    .to_string(),
                StatusCode::BAD_REQUEST,
            ),
            GatewayError::Disconnected => (
                "The gateway is disconnected from the Lightning Node".to_string(),
                StatusCode::NOT_FOUND,
            ),
            _ => (
                "An internal gateway error occurred".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        };

        let mut err = Cow::<'static, str>::Owned(error_message).into_response();
        *err.status_mut() = status_code;
        err
    }
}
