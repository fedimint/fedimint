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
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::{Address, Txid};
use bitcoin_hashes::hex::ToHex;
use clap::{Parser, Subcommand};
use client::StandardGatewayClientBuilder;
use db::{FederationRegistrationKey, GatewayPublicKey};
use fedimint_client::module::gen::{ClientModuleGen, ClientModuleGenRegistry};
use fedimint_core::api::{FederationError, WsClientConnectInfo};
use fedimint_core::config::FederationId;
use fedimint_core::core::{
    ModuleInstanceId, ModuleKind, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::Database;
use fedimint_core::module::CommonModuleGen;
use fedimint_core::task::{sleep, RwLock, TaskGroup, TaskHandle};
use fedimint_core::time::now;
use fedimint_core::Amount;
use fedimint_ln_client::contracts::Preimage;
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_ln_common::config::GatewayFee;
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_logging::TracingSetup;
use fedimint_mint_client::{MintClientGen, MintCommonGen};
use fedimint_wallet_client::{WalletClientExt, WalletClientGen, WalletCommonGen, WithdrawState};
use futures::stream::StreamExt;
use gatewaylnrpc::intercept_htlc_response::Action;
use gatewaylnrpc::{GetNodeInfoResponse, InterceptHtlcResponse};
use lightning::routing::gossip::RoutingFees;
use lnrpc_client::{ILnRpcClient, RouteHtlcStream};
use ng::GatewayClientExt;
use rand::rngs::OsRng;
use rand::Rng;
use rpc::FederationInfo;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, error, info, warn};
use url::Url;

use crate::gatewaylnrpc::intercept_htlc_response::Forward;
use crate::lnd::GatewayLndClient;
use crate::lnrpc_client::NetworkLnRpcClient;
use crate::ng::{GatewayExtPayStates, Htlc};
use crate::rpc::rpc_server::run_webserver;
use crate::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, GatewayInfo,
    InfoPayload, RestorePayload, WithdrawPayload,
};

/// LND HTLC interceptor can't handle SCID of 0, so start from 1
const INITIAL_SCID: u64 = 1;

/// How long a gateway announcement stays valid
pub const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

const ROUTE_HINT_RETRIES: usize = 10;
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
}

pub struct Gatewayd {
    registry: ClientModuleGenRegistry,
    lightning_mode: LightningMode,
    data_dir: PathBuf,
    listen: SocketAddr,
    api_addr: Url,
    password: String,
    fees: Option<GatewayFee>,
}

impl Gatewayd {
    pub fn new() -> anyhow::Result<Gatewayd> {
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
        } = GatewayOpts::parse();

        info!(
            "Starting gatewayd (version: {})",
            env!("FEDIMINT_BUILD_CODE_VERSION")
        );

        Ok(Self {
            registry: ClientModuleGenRegistry::new(),
            lightning_mode: mode,
            data_dir,
            listen,
            api_addr,
            password,
            fees,
        })
    }

    pub fn with_module<T>(mut self, gen: T) -> Self
    where
        T: ClientModuleGen + 'static + Send + Sync,
    {
        self.registry.attach(gen);
        self
    }

    pub fn with_default_modules(self) -> Self {
        // Gateway module will be attached when the federation clients are created
        // because the LN RPC will be injected with `GatewayClientGen`.
        self.with_module(MintClientGen)
            .with_module(WalletClientGen::default())
    }

    pub async fn run(self) -> anyhow::Result<()> {
        TracingSetup::default().init()?;

        let decoders = self
            .registry
            .decoders(DEFAULT_MODULE_KINDS.iter().cloned())?;

        let client_builder = StandardGatewayClientBuilder::new(
            self.data_dir.clone(),
            self.registry.clone(),
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
        );

        let db = Database::new(
            fedimint_rocksdb::RocksDb::open(self.data_dir.join(DB_FILE))?,
            decoders.clone(),
        );

        let mut tg = TaskGroup::new();
        let rx = self.start_gateway(&mut tg, client_builder, db).await?;
        rx.await?;
        info!("Gatewayd exiting...");
        Ok(())
    }

    async fn start_gateway(
        self,
        task_group: &mut TaskGroup,
        client_builder: StandardGatewayClientBuilder,
        database: Database,
    ) -> Result<oneshot::Receiver<()>> {
        let mut tg = task_group.make_subgroup().await;
        task_group
            .spawn(
                "Subscribe to intercepted HTLCs in stream",
                move |handle| async move {
                    let clients =  Arc::new(RwLock::new(BTreeMap::new()));
                    let scid_to_federation = Arc::new(RwLock::new(BTreeMap::new()));

                    loop {
                        if handle.is_shutting_down() {
                            break;
                        }

                        let lnrpc_route = Self::create_boxed_lightning_client(self.lightning_mode.clone()).await;

                        // Re-create the HTLC stream if the connection breaks
                        match lnrpc_route
                            .route_htlcs(&mut tg)
                            .await
                        {
                            Ok((stream, ln_client)) => {
                                // Blocks until the connection to the lightning node breaks
                                info!("Established HTLC stream");

                                // Re-create gateway
                                let gateway = Gateway::new(
                                    ln_client.clone(),
                                    client_builder.clone(),
                                    self.fees.clone().unwrap_or(GatewayFee(DEFAULT_FEES)).0,
                                    database.clone(),
                                    self.api_addr.clone(),
                                    clients.clone(),
                                    scid_to_federation.clone(),
                                    tg.clone(),
                                )
                                .await.expect("Failed to created Gateway");

                                info!("Successfully created Gateway");

                                let tx = run_webserver(self.password.clone(), self.listen, gateway)
                                    .await
                                    .expect("Failed to start webserver");
                                info!("Successfully started webserver");

                                Gateway::handle_htlc_stream(stream, ln_client, handle.clone(), scid_to_federation.clone(), clients.clone()).await;
                                warn!("HTLC Stream Lightning connection broken. Stopping webserver...");
                                if let Err(e) = tx.send(()).await {
                                    error!("Error shutting down gatewayd webserver: {e:?}");
                                }
                            }
                            Err(e) => {
                                error!("Failed to open HTLC stream. Waiting 5 seconds and trying again");
                                debug!("Error: {e:?}");
                                sleep(Duration::from_secs(5)).await;
                            }
                        }
                    }
                },
            )
            .await;

        let handle = task_group.make_handle();
        handle
            .on_shutdown(Box::new(|| {
                Box::pin(async move {
                    info!("Gatewayd received exit signal");
                })
            }))
            .await;
        let shutdown_receiver = handle.make_shutdown_rx().await;
        Ok(shutdown_receiver)
    }

    async fn create_boxed_lightning_client(mode: LightningMode) -> Box<dyn ILnRpcClient> {
        match mode {
            LightningMode::Cln { cln_extension_addr } => {
                Box::new(NetworkLnRpcClient::new(cln_extension_addr).await)
            }
            LightningMode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            } => Box::new(
                GatewayLndClient::new(lnd_rpc_addr, lnd_tls_cert, lnd_macaroon, None).await,
            ),
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
    #[error("Lightning rpc operation error: {0:?}")]
    LnRpcError(#[from] tonic::Status),
    #[error("Federation error: {0:?}")]
    FederationError(#[from] FederationError),
    #[error("Other: {0:?}")]
    Other(#[from] anyhow::Error),
    #[error("Failed to fetch route hints")]
    FailedToFetchRouteHints,
    #[error("Failed to open the database: {0:?}")]
    DatabaseError(anyhow::Error),
    #[error("Federation client error")]
    ClientNgError,
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

#[derive(Clone)]
pub struct Gateway {
    lnrpc: Arc<dyn ILnRpcClient>,
    clients: Arc<RwLock<BTreeMap<FederationId, fedimint_client::Client>>>,
    scid_to_federation: Arc<RwLock<BTreeMap<u64, FederationId>>>,
    client_builder: StandardGatewayClientBuilder,
    channel_id_generator: Arc<Mutex<AtomicU64>>,
    fees: RoutingFees,
    gatewayd_db: Database,
    api: Url,
    task_group: TaskGroup,
    pub gateway_id: secp256k1::PublicKey,
}

impl Gateway {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        lnrpc: Arc<dyn ILnRpcClient>,
        client_builder: StandardGatewayClientBuilder,
        fees: RoutingFees,
        gatewayd_db: Database,
        api: Url,
        clients: Arc<RwLock<BTreeMap<FederationId, fedimint_client::Client>>>,
        scid_to_federation: Arc<RwLock<BTreeMap<u64, FederationId>>>,
        task_group: TaskGroup,
    ) -> Result<Self> {
        let mut gw = Self {
            lnrpc,
            clients,
            scid_to_federation,
            client_builder,
            channel_id_generator: Arc::new(Mutex::new(AtomicU64::new(INITIAL_SCID))),
            fees,
            gatewayd_db: gatewayd_db.clone(),
            api,
            task_group,
            gateway_id: Self::get_gateway_id(gatewayd_db).await,
        };

        gw.register_clients_timer().await;
        gw.load_clients().await?;
        Ok(gw)
    }

    async fn get_gateway_id(gatewayd_db: Database) -> secp256k1::PublicKey {
        let mut dbtx = gatewayd_db.begin_transaction().await;
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

    pub async fn handle_htlc_stream(
        mut stream: RouteHtlcStream<'_>,
        lnrpc: Arc<dyn ILnRpcClient>,
        handle: TaskHandle,
        scid_to_federation: Arc<RwLock<BTreeMap<u64, FederationId>>>,
        clients: Arc<RwLock<BTreeMap<FederationId, fedimint_client::Client>>>,
    ) {
        while let Some(Ok(htlc_request)) = stream.next().await {
            if handle.is_shutting_down() {
                break;
            }

            let scid_to_feds = scid_to_federation.read().await;
            let federation_id = scid_to_feds.get(&htlc_request.short_channel_id);
            // Just forward the HTLC if we do not have a federation that
            // corresponds to the short channel id
            if let Some(federation_id) = federation_id {
                let clients = clients.read().await;
                let client = clients.get(federation_id);
                // Just forward the HTLC if we do not have a client that
                // corresponds to the federation id
                if let Some(client) = client {
                    let htlc: Result<Htlc> = htlc_request
                        .clone()
                        .try_into()
                        .map_err(|_| GatewayError::ClientNgError);
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

    async fn fetch_lightning_route_info(
        lnrpc: Arc<dyn ILnRpcClient>,
    ) -> Result<(Vec<RouteHint>, PublicKey, String)> {
        let mut num_retries = 0;
        let (route_hints, node_pub_key, alias) = loop {
            let route_hints: Vec<RouteHint> = lnrpc
                .routehints()
                .await?
                .try_into()
                .expect("Could not parse route hints");

            let GetNodeInfoResponse { pub_key, alias } = lnrpc.info().await?;
            let node_pub_key = PublicKey::from_slice(&pub_key)
                .map_err(|e| GatewayError::Other(anyhow!("Invalid node pubkey {}", e)))?;

            if !route_hints.is_empty() || num_retries == ROUTE_HINT_RETRIES {
                break (route_hints, node_pub_key, alias);
            }

            info!(
                ?num_retries,
                "LN node returned no route hints, trying again in {}s",
                ROUTE_HINT_RETRY_SLEEP.as_secs()
            );
            num_retries += 1;
            sleep(ROUTE_HINT_RETRY_SLEEP).await;
        };

        Ok((route_hints, node_pub_key, alias))
    }

    async fn register_clients_timer(&mut self) {
        let clients = self.clients.clone();
        let api = self.api.clone();
        let lnrpc = self.lnrpc.clone();
        let gateway_id = self.gateway_id;
        self.task_group
            .spawn("register clients", move |handle| async move {
                while !handle.is_shutting_down() {
                    match Self::fetch_lightning_route_info(lnrpc.clone()).await {
                        Ok((route_hints, _, _)) => {
                            for (federation_id, client) in clients.read().await.iter() {
                                if client
                                    .register_with_federation(
                                        api.clone(),
                                        route_hints.clone(),
                                        GW_ANNOUNCEMENT_TTL,
                                        gateway_id,
                                    )
                                    .await
                                    .is_err()
                                {
                                    error!("Error registering federation {federation_id}");
                                }
                            }
                        }
                        Err(_) => {
                            error!(
                                "Could not retrieve route hints, gateway will not be registered."
                            );
                        }
                    }

                    // Allow a 15% buffer of the TTL before the re-registering gateway
                    // with the federations.
                    let registration_delay = GW_ANNOUNCEMENT_TTL.mul_f32(0.85);
                    sleep(registration_delay).await;
                }
            })
            .await;
    }

    async fn load_clients(&mut self) -> Result<()> {
        let (_, node_pub_key, _) = Self::fetch_lightning_route_info(self.lnrpc.clone()).await?;
        let dbtx = self.gatewayd_db.begin_transaction().await;
        if let Ok(configs) = self.client_builder.load_configs(dbtx).await {
            let channel_id_generator = self.channel_id_generator.lock().await;
            let mut next_channel_id = channel_id_generator.load(Ordering::SeqCst);

            for config in configs {
                let federation_id = config.config.federation_id;
                let old_client = self.clients.read().await.get(&federation_id).cloned();
                let client = self
                    .client_builder
                    .build(
                        config.clone(),
                        node_pub_key,
                        self.lnrpc.clone(),
                        self.task_group.make_subgroup().await,
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
        Ok(())
    }

    pub async fn register_client(
        &mut self,
        client: fedimint_client::Client,
        federation_id: FederationId,
        scid: u64,
        route_hints: Vec<RouteHint>,
    ) -> Result<()> {
        client
            .register_with_federation(
                self.api.clone(),
                route_hints,
                GW_ANNOUNCEMENT_TTL,
                self.gateway_id,
            )
            .await?;
        self.clients.write().await.insert(federation_id, client);
        self.scid_to_federation
            .write()
            .await
            .insert(scid, federation_id);
        Ok(())
    }

    pub async fn remove_client(
        &self,
        federation_id: FederationId,
    ) -> Result<fedimint_client::Client> {
        let client =
            self.clients
                .write()
                .await
                .remove(&federation_id)
                .ok_or(GatewayError::Other(anyhow::anyhow!(
                    "No federation with id {}",
                    federation_id.to_string()
                )))?;
        let mut dbtx = self.gatewayd_db.begin_transaction().await;
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
            .ok_or(GatewayError::Other(anyhow::anyhow!(
                "No federation with id {}",
                federation_id.to_string()
            )))
    }

    async fn handle_connect_federation(
        &mut self,
        payload: ConnectFedPayload,
    ) -> Result<FederationInfo> {
        let connect = WsClientConnectInfo::from_str(&payload.connect).map_err(|e| {
            GatewayError::Other(anyhow::anyhow!("Invalid federation member string {}", e))
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
                .create_config(connect.clone(), channel_id, self.fees)
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

        let federation_id = gw_client_cfg.config.federation_id;
        let (route_hints, node_pub_key, _) =
            Self::fetch_lightning_route_info(self.lnrpc.clone()).await?;
        let old_client = self.clients.read().await.get(&federation_id).cloned();

        let client = self
            .client_builder
            .build(
                gw_client_cfg.clone(),
                node_pub_key,
                self.lnrpc.clone(),
                self.task_group.make_subgroup().await,
                old_client,
            )
            .await?;

        let balance_msat = client.get_balance().await;

        self.register_client(client, federation_id, channel_id, route_hints)
            .await?;

        let dbtx = self.gatewayd_db.begin_transaction().await;
        self.client_builder
            .save_config(gw_client_cfg.clone(), dbtx)
            .await?;

        Ok(FederationInfo {
            federation_id,
            balance_msat,
        })
    }

    pub async fn handle_get_info(&self, _payload: InfoPayload) -> Result<GatewayInfo> {
        let mut federations = Vec::new();
        let federation_clients = self.clients.read().await.clone().into_iter();
        let (route_hints, node_pub_key, alias) =
            Self::fetch_lightning_route_info(self.lnrpc.clone()).await?;
        for (federation_id, client) in federation_clients {
            let balance_msat = client.get_balance().await;

            federations.push(FederationInfo {
                federation_id,
                balance_msat,
            });
        }

        Ok(GatewayInfo {
            federations,
            version_hash: env!("FEDIMINT_BUILD_CODE_VERSION").to_string(),
            lightning_pub_key: node_pub_key.to_hex(),
            lightning_alias: alias,
            fees: self.fees,
            route_hints,
            gateway_id: self.gateway_id,
        })
    }

    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<Preimage> {
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
                GatewayExtPayStates::Fail => {
                    return Err(GatewayError::Other(anyhow!("Payment failed")))
                }
                GatewayExtPayStates::Canceled => {
                    return Err(GatewayError::Other(anyhow!("Outgoing contract canceled")))
                }
                _ => {}
            };
        }

        return Err(GatewayError::Other(anyhow!(
            "Unexpected error occurred while paying the invoice"
        )));
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

        let operation_id = self
            .select_client(federation_id)
            .await?
            .withdraw(address, amount, fees)
            .await?;
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
                    return Err(GatewayError::Other(anyhow!(e)));
                }
                _ => {}
            }
        }

        return Err(GatewayError::Other(anyhow!(
            "Unexpected error occurred while withdrawing"
        )));
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
}
