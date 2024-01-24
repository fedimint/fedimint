pub mod client;
pub mod db;
pub mod lightning;
pub mod rpc;
pub mod state_machine;
pub mod types;
pub mod utils;

pub mod gateway_lnrpc {
    tonic::include_proto!("gateway_lnrpc");
}

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::env;
use std::fmt::Display;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::{Address, Network, Txid};
use bitcoin_hashes::hex::ToHex;
use clap::Parser;
use client::GatewayClientBuilder;
use db::{
    DbKeyPrefix, FederationIdKey, GatewayConfiguration, GatewayConfigurationKey, GatewayPublicKey,
};
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::ClientArc;
use fedimint_core::api::{FederationError, InviteCode};
use fedimint_core::config::FederationId;
use fedimint_core::core::{
    ModuleInstanceId, ModuleKind, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_core::module::CommonModuleInit;
use fedimint_core::task::{sleep, RwLock, TaskGroup, TaskHandle, TaskShutdownToken};
use fedimint_core::time::now;
use fedimint_core::util::SafeUrl;
use fedimint_core::{push_db_pair_items, Amount, BitcoinAmountOrAll};
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_ln_common::config::{GatewayFee, LightningClientConfig};
use fedimint_ln_common::contracts::Preimage;
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::LightningCommonInit;
use fedimint_mint_client::{MintClientInit, MintCommonInit};
use fedimint_wallet_client::{
    WalletClientInit, WalletClientModule, WalletCommonInit, WithdrawState,
};
use futures::stream::StreamExt;
use gateway_lnrpc::intercept_htlc_response::Action;
use gateway_lnrpc::{GetNodeInfoResponse, InterceptHtlcResponse};
use lightning::{ILnRpcClient, LightningBuilder, LightningMode, LightningRpcError};
use lightning_invoice::RoutingFees;
use rand::rngs::OsRng;
use rpc::{
    FederationConnectionInfo, FederationInfo, GatewayFedConfig, GatewayInfo, LeaveFedPayload,
    SetConfigurationPayload, V1_API_ENDPOINT,
};
use secp256k1::PublicKey;
use state_machine::pay::OutgoingPaymentError;
use state_machine::GatewayClientModule;
use strum::IntoEnumIterator;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::db::{FederationConfig, FederationIdKeyPrefix};
use crate::gateway_lnrpc::intercept_htlc_response::Forward;
use crate::lightning::cln::RouteHtlcStream;
use crate::lightning::GatewayLightningBuilder;
use crate::rpc::rpc_server::run_webserver;
use crate::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, RestorePayload,
    WithdrawPayload,
};
use crate::state_machine::GatewayExtPayStates;

/// LND HTLC interceptor can't handle SCID of 0, so start from 1
pub const INITIAL_SCID: u64 = 1;

/// How long a gateway announcement stays valid
pub const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

const ROUTE_HINT_RETRIES: usize = 30;
const ROUTE_HINT_RETRY_SLEEP: Duration = Duration::from_secs(2);
const DEFAULT_NUM_ROUTE_HINTS: u32 = 1;
pub const DEFAULT_NETWORK: Network = Network::Regtest;

pub const DEFAULT_FEES: RoutingFees = RoutingFees {
    // Base routing fee. Default is 0 msat
    base_msat: 0,
    // Liquidity-based routing fee in millionths of a routed amount.
    // In other words, 10000 is 1%. The default is 10000 (1%).
    proportional_millionths: 10000,
};

pub type Result<T> = std::result::Result<T, GatewayError>;

const DB_FILE: &str = "gatewayd.db";

const DEFAULT_MODULE_KINDS: [(ModuleInstanceId, &ModuleKind); 2] = [
    (LEGACY_HARDCODED_INSTANCE_ID_MINT, &MintCommonInit::KIND),
    (LEGACY_HARDCODED_INSTANCE_ID_WALLET, &WalletCommonInit::KIND),
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
    pub api_addr: SafeUrl,

    /// Gateway webserver authentication password
    #[arg(long = "password", env = "FM_GATEWAY_PASSWORD")]
    pub password: Option<String>,

    /// Bitcoin network this gateway will be running on
    #[arg(long = "network", env = "FM_GATEWAY_NETWORK")]
    pub network: Option<Network>,

    /// Configured gateway routing fees
    /// Format: <base_msat>,<proportional_millionths>
    #[arg(long = "fees", env = "FM_GATEWAY_FEES")]
    pub fees: Option<GatewayFee>,

    /// Number of route hints to return in invoices
    #[arg(
        long = "num-route-hints",
        env = "FM_NUMBER_OF_ROUTE_HINTS",
        default_value_t = DEFAULT_NUM_ROUTE_HINTS
    )]
    pub num_route_hints: u32,
}

impl GatewayOpts {
    fn to_gateway_parameters(&self) -> anyhow::Result<GatewayParameters> {
        let versioned_api = self.api_addr.join(V1_API_ENDPOINT).map_err(|e| {
            anyhow::anyhow!(
                "Failed to version gateway API address: {api_addr:?}, error: {e:?}",
                api_addr = self.api_addr,
            )
        })?;
        Ok(GatewayParameters {
            listen: self.listen,
            versioned_api,
            password: self.password.clone(),
            network: self.network,
            num_route_hints: self.num_route_hints,
            fees: self.fees.clone(),
        })
    }
}

/// `GatewayParameters` is a helper struct that can be derived from
/// `GatewayOpts` that holds the CLI or environment variables that are specified
/// by the user.
///
/// If `GatewayConfiguration is set in the database, that takes precedence and
/// the optional parameters will have no affect.
#[derive(Clone, Debug)]
struct GatewayParameters {
    listen: SocketAddr,
    versioned_api: SafeUrl,
    password: Option<String>,
    network: Option<Network>,
    num_route_hints: u32,
    fees: Option<GatewayFee>,
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    Initializing -- begin intercepting HTLCs --> Connected
///    Initializing -- gateway needs config --> Configuring
///    Configuring -- configuration set --> Connected
///    Connected -- load federation clients --> Running
///    Running -- disconnected from lightning node --> Disconnected
///    Disconnected -- re-established lightning connection --> Connected
/// ```
#[derive(Clone, Debug)]
pub enum GatewayState {
    Initializing,
    Configuring,
    Connected,
    Running { lightning_context: LightningContext },
    Disconnected,
}

impl Display for GatewayState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GatewayState::Initializing => write!(f, "Initializing"),
            GatewayState::Configuring => write!(f, "Configuring"),
            GatewayState::Connected => write!(f, "Connected"),
            GatewayState::Running { .. } => write!(f, "Running"),
            GatewayState::Disconnected => write!(f, "Disconnected"),
        }
    }
}

pub type ScidToFederationMap = Arc<RwLock<BTreeMap<u64, FederationId>>>;
pub type FederationToClientMap = Arc<RwLock<BTreeMap<FederationId, fedimint_client::ClientArc>>>;

/// Represents an active connection to the lightning node.
#[derive(Clone, Debug)]
pub struct LightningContext {
    pub lnrpc: Arc<dyn ILnRpcClient>,
    pub lightning_public_key: PublicKey,
    pub lightning_alias: String,
    pub lightning_network: Network,
}

#[derive(Clone)]
pub struct Gateway {
    // Builder struct that allows the gateway to build a `ILnRpcClient`, which represents a
    // connection to a lightning node.
    lightning_builder: Arc<dyn LightningBuilder + Send + Sync>,

    // CLI or environment parameters that the operator has set.
    gateway_parameters: GatewayParameters,

    // The current state of the Gateway.
    pub state: Arc<RwLock<GatewayState>>,

    // Builder struct that allows the gateway to build a Fedimint client, which handles the
    // communication with a federation.
    client_builder: GatewayClientBuilder,

    // Database for Gateway metadata.
    gateway_db: Database,

    // Map of `FederationId` -> `Client`. Used for efficient retrieval of the client while handling
    // incoming HTLCs.
    clients: FederationToClientMap,

    // Map of short channel ids to `FederationId`. Use for efficient retrieval of the client while
    // handling incoming HTLCs.
    scid_to_federation: ScidToFederationMap,

    // A public key representing the identity of the gateway. Private key is not used.
    pub gateway_id: secp256k1::PublicKey,

    // ID generator that atomically increments. Used for creation of new short channel ids that
    // represent federations.
    channel_id_generator: Arc<Mutex<u64>>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("gateway_parameters", &self.gateway_parameters)
            .field("state", &self.state)
            .field("client_builder", &self.client_builder)
            .field("gateway_db", &self.gateway_db)
            .field("clients", &self.clients)
            .field("scid_to_federation", &self.scid_to_federation)
            .field("gateway_id", &self.gateway_id)
            .field("channel_id_generator", &self.channel_id_generator)
            .finish()
    }
}

impl Gateway {
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_custom_registry(
        lightning_builder: Arc<dyn LightningBuilder + Send + Sync>,
        client_builder: GatewayClientBuilder,
        listen: SocketAddr,
        api_addr: SafeUrl,
        cli_password: Option<String>,
        network: Option<Network>,
        fees: RoutingFees,
        num_route_hints: u32,
        gateway_db: Database,
    ) -> anyhow::Result<Gateway> {
        let versioned_api = api_addr
            .join(V1_API_ENDPOINT)
            .expect("Failed to version gateway API address");
        Ok(Gateway {
            lightning_builder,
            gateway_parameters: GatewayParameters {
                listen,
                versioned_api,
                password: cli_password,
                num_route_hints,
                fees: Some(GatewayFee(fees)),
                network,
            },
            state: Arc::new(RwLock::new(GatewayState::Initializing)),
            client_builder,
            gateway_db: gateway_db.clone(),
            clients: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            gateway_id: Gateway::get_gateway_id(gateway_db).await,
            channel_id_generator: Arc::new(Mutex::new(INITIAL_SCID)),
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

        let opts = GatewayOpts::parse();

        // Gateway module will be attached when the federation clients are created
        // because the LN RPC will be injected with `GatewayClientGen`.
        let mut registry = ClientModuleInitRegistry::new();
        registry.attach(MintClientInit);
        registry.attach(WalletClientInit::default());

        let decoders = registry.available_decoders(DEFAULT_MODULE_KINDS.iter().cloned())?;

        let gateway_db = Database::new(
            fedimint_rocksdb::RocksDb::open(opts.data_dir.join(DB_FILE))?,
            decoders.clone(),
        );

        let client_builder = GatewayClientBuilder::new(
            opts.data_dir.clone(),
            registry.clone(),
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
        );

        info!(
            "Starting gatewayd (version: {})",
            env!("FEDIMINT_BUILD_CODE_VERSION")
        );

        Ok(Self {
            lightning_builder: Arc::new(GatewayLightningBuilder {
                lightning_mode: opts.mode.clone(),
            }),
            channel_id_generator: Arc::new(Mutex::new(INITIAL_SCID)),
            gateway_parameters: opts.to_gateway_parameters()?,
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

    pub async fn dump_database<'a>(
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + 'a> {
        let mut gateway_items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> =
            BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::FederationConfig => {
                    push_db_pair_items!(
                        dbtx,
                        FederationIdKeyPrefix,
                        FederationIdKey,
                        FederationConfig,
                        gateway_items,
                        "Federation Config"
                    );
                }
                DbKeyPrefix::GatewayConfiguration => {
                    if let Some(gateway_config) = dbtx.get_value(&GatewayConfigurationKey).await {
                        gateway_items.insert(
                            "Gateway Configuration".to_string(),
                            Box::new(gateway_config),
                        );
                    }
                }
                DbKeyPrefix::GatewayPublicKey => {
                    if let Some(public_key) = dbtx.get_value(&GatewayPublicKey).await {
                        gateway_items
                            .insert("Gateway Public Key".to_string(), Box::new(public_key));
                    }
                }
                _ => {}
            }
        }

        Box::new(gateway_items.into_iter())
    }

    pub async fn run(mut self, tg: &mut TaskGroup) -> anyhow::Result<TaskShutdownToken> {
        self.start_webserver(tg).await;
        self.register_clients_timer(tg).await;
        self.load_clients().await;
        self.start_gateway(tg).await?;
        let handle = tg.make_handle();
        let shutdown_receiver = handle.make_shutdown_rx().await;
        Ok(shutdown_receiver)
    }

    async fn start_webserver(&mut self, task_group: &mut TaskGroup) {
        let gateway_db = self.gateway_db.clone();

        let gateway = self.clone();
        let subgroup = task_group.make_subgroup().await;
        task_group
            .spawn("Webserver", move |handle| async move {
                while !handle.is_shutting_down() {
                    // Re-fetch the configuration because the password has changed.
                    let gateway_config = gateway.get_gateway_configuration().await;
                    let mut webserver_group = subgroup.make_subgroup().await;
                    run_webserver(
                        gateway_config.clone(),
                        gateway.gateway_parameters.listen,
                        gateway.clone(),
                        &mut webserver_group,
                    )
                    .await
                    .expect("Failed to start webserver");
                    info!("Successfully started webserver");
                    tokio::select! {
                        _ = wait_for_new_password(&gateway_db, gateway_config) => {
                            info!("GatewayConfiguration has been updated, restarting webserver...");
                            if let Err(e) = webserver_group.shutdown_join_all(None).await {
                                panic!("Error shutting down server: {e:?}");
                            }
                        },
                        _ = handle.make_shutdown_rx().await => {
                            info!("Received shutdown signal, exiting....");
                            break;
                        }
                    }
                }
            })
            .await;

        let gateway_config = self.get_gateway_configuration().await;
        if gateway_config.is_none() {
            self.set_gateway_state(GatewayState::Configuring).await;
            info!("Waiting for gateway to be configured...");
            self.gateway_db
                .wait_key_exists(&GatewayConfigurationKey)
                .await;
        }
    }

    async fn start_gateway(mut self, task_group: &mut TaskGroup) -> Result<()> {
        let tg = task_group.clone();
        task_group
            .spawn(
                "Subscribe to intercepted HTLCs in stream",
                move |handle| async move {
                    loop {
                        if handle.is_shutting_down() {
                            info!("Gateway HTLC handler loop is shutting down");
                            break;
                        }

                        let mut htlc_task_group = tg.make_subgroup().await;
                        let lnrpc_route = self.lightning_builder.build().await;

                        debug!("Will try to intercept HTLC stream...");
                        // Re-create the HTLC stream if the connection breaks
                        match lnrpc_route
                            .route_htlcs(&mut htlc_task_group)
                            .await
                        {
                            Ok((stream, ln_client)) => {
                                // Successful calls to route_htlcs establish a connection
                                self.set_gateway_state(GatewayState::Connected).await;
                                info!("Established HTLC stream");

                                match fetch_lightning_node_info(ln_client.clone()).await {
                                    Ok((lightning_public_key, lightning_alias, lightning_network)) => {
                                        if let Some(config) = self.get_gateway_configuration().await {
                                            if config.network != lightning_network {
                                                warn!("Lightning node does not match previously configured gateway network : ({:?})", config.network);
                                                info!("Changing gateway network to match lightning node network : ({:?})", lightning_network);
                                                self.handle_disconnect(htlc_task_group).await;
                                                self.handle_set_configuration_msg(SetConfigurationPayload {
                                                    password: Some(config.password),
                                                    network: Some(lightning_network),
                                                    num_route_hints: None,
                                                    routing_fees: None,
                                                }).await.expect("Failed to set gateway configuration");
                                                continue;
                                            }
                                        }

                                        info!("Successfully loaded Gateway clients.");
                                        let lightning_context = LightningContext {
                                            lnrpc: ln_client,
                                            lightning_public_key,
                                            lightning_alias,
                                            lightning_network,
                                        };
                                        self.set_gateway_state(GatewayState::Running {
                                            lightning_context
                                        }).await;

                                        // Blocks until the connection to the lightning node breaks or we receive the shutdown signal
                                        tokio::select! {
                                            _ = self.handle_htlc_stream(stream, handle.clone()) => {
                                                warn!("HTLC Stream Lightning connection broken. Gateway is disconnected");
                                            },
                                            _ = handle.make_shutdown_rx().await => {
                                                info!("Received shutdown signal");
                                                self.handle_disconnect(htlc_task_group).await;
                                                break;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to retrieve Lightning info: {e:?}");
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("Failed to open HTLC stream: {e:?}");
                            }
                        }

                        self.handle_disconnect(htlc_task_group).await;

                        warn!("Disconnected from Lightning Node. Waiting 5 seconds and trying again");
                        sleep(Duration::from_secs(5)).await;
                    }
                },
            )
            .await;

        Ok(())
    }

    async fn handle_disconnect(&mut self, htlc_task_group: TaskGroup) {
        self.set_gateway_state(GatewayState::Disconnected).await;
        if let Err(e) = htlc_task_group.shutdown_join_all(None).await {
            error!("HTLC task group shutdown errors: {}", e);
        }
    }

    pub async fn handle_htlc_stream(&self, mut stream: RouteHtlcStream<'_>, handle: TaskHandle) {
        let GatewayState::Running { lightning_context } = self.state.read().await.clone() else {
            panic!("Gateway isn't in a running state")
        };
        loop {
            match stream.next().await {
                Some(Ok(htlc_request)) => {
                    info!(
                        "Intercepting HTLC {}",
                        PrettyInterceptHtlcRequest(&htlc_request)
                    );
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
                                match client
                                    .get_first_module::<GatewayClientModule>()
                                    .gateway_handle_intercepted_htlc(htlc)
                                    .await
                                {
                                    Ok(_) => continue,
                                    Err(e) => {
                                        info!("Got error intercepting HTLC: {e:?}, will retry...")
                                    }
                                }
                            } else {
                                info!("Got no HTLC result")
                            }
                        } else {
                            info!("Got no client result")
                        }
                    }

                    let outcome = InterceptHtlcResponse {
                        action: Some(Action::Forward(Forward {})),
                        incoming_chan_id: htlc_request.incoming_chan_id,
                        htlc_id: htlc_request.htlc_id,
                    };

                    if let Err(error) = lightning_context.lnrpc.complete_htlc(outcome).await {
                        error!("Error sending HTLC response to lightning node: {error:?}");
                    }
                }
                other => {
                    info!("Got {other:?} while handling HTLC stream, exiting from loop...");
                    break;
                }
            }
        }
    }

    async fn set_gateway_state(&mut self, state: GatewayState) {
        let mut lock = self.state.write().await;
        *lock = state;
    }

    pub async fn handle_get_info(&self) -> Result<GatewayInfo> {
        if let GatewayState::Running { lightning_context } = self.state.read().await.clone() {
            // `GatewayConfiguration` should always exist in the database when we are in the
            // `Running` state.
            let gateway_config = self
                .get_gateway_configuration()
                .await
                .expect("Gateway configuration should be set");
            let mut federations = Vec::new();
            let federation_clients = self.clients.read().await.clone().into_iter();
            let route_hints = Self::fetch_lightning_route_hints(
                lightning_context.lnrpc.clone(),
                gateway_config.num_route_hints,
            )
            .await?;
            for (federation_id, client) in federation_clients {
                federations.push(self.make_federation_info(&client, federation_id).await);
            }

            return Ok(GatewayInfo {
                federations,
                version_hash: env!("FEDIMINT_BUILD_CODE_VERSION").to_string(),
                lightning_pub_key: Some(lightning_context.lightning_public_key.to_hex()),
                lightning_alias: Some(lightning_context.lightning_alias.clone()),
                fees: Some(gateway_config.routing_fees),
                route_hints,
                gateway_id: self.gateway_id,
                gateway_state: self.state.read().await.to_string(),
                network: Some(gateway_config.network),
            });
        }

        Ok(GatewayInfo {
            federations: vec![],
            version_hash: env!("FEDIMINT_BUILD_CODE_VERSION").to_string(),
            lightning_pub_key: None,
            lightning_alias: None,
            fees: None,
            route_hints: vec![],
            gateway_id: self.gateway_id,
            gateway_state: self.state.read().await.to_string(),
            network: None,
        })
    }
    pub async fn handle_get_federation_config(
        &self,
        federation_id: Option<FederationId>,
    ) -> Result<GatewayFedConfig> {
        if let GatewayState::Running { .. } = self.state.read().await.clone() {
            let mut federations = BTreeMap::new();
            if let Some(federation_id) = federation_id {
                let client = self.select_client(federation_id).await?;
                federations.insert(federation_id, client.get_config_json());
            } else {
                let federation_clients = self.clients.read().await.clone().into_iter();
                for (federation_id, client) in federation_clients {
                    federations.insert(federation_id, client.get_config_json());
                }
            }
            return Ok(GatewayFedConfig { federations });
        }
        Ok(GatewayFedConfig {
            federations: BTreeMap::new(),
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
            .get_first_module::<WalletClientModule>()
            .get_deposit_address(now() + Duration::from_secs(86400 * 365), ())
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
        let wallet_module = client.get_first_module::<WalletClientModule>();

        // TODO: Fees should probably be passed in as a parameter
        let (amount, fees) = match amount {
            // If the amount is "all", then we need to subtract the fees from
            // the amount we are withdrawing
            BitcoinAmountOrAll::All => {
                let balance = bitcoin::Amount::from_sat(client.get_balance().await.msats / 1000);
                let fees = wallet_module
                    .get_withdraw_fees(address.clone(), balance)
                    .await?;
                let withdraw_amount = balance.checked_sub(fees.amount());
                if withdraw_amount.is_none() {
                    return Err(GatewayError::InsufficientFunds);
                }
                (withdraw_amount.unwrap(), fees)
            }
            BitcoinAmountOrAll::Amount(amount) => (
                amount,
                wallet_module
                    .get_withdraw_fees(address.clone(), amount)
                    .await?,
            ),
        };

        let operation_id = wallet_module
            .withdraw(address.clone(), amount, fees, ())
            .await?;
        let mut updates = wallet_module
            .subscribe_withdraw_updates(operation_id)
            .await?
            .into_stream();

        while let Some(update) = updates.next().await {
            match update {
                WithdrawState::Succeeded(txid) => {
                    info!("Sent {amount} funds to address {address}");
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
        if let GatewayState::Running { .. } = self.state.read().await.clone() {
            debug!("Handling pay invoice message: {payload:?}");
            let client = self.select_client(payload.federation_id).await?;
            let contract_id = payload.contract_id;
            let gateway_module = &client.get_first_module::<GatewayClientModule>();
            let operation_id = gateway_module.gateway_pay_bolt11_invoice(payload).await?;
            let mut updates = gateway_module
                .gateway_subscribe_ln_pay(operation_id)
                .await?
                .into_stream();
            while let Some(update) = updates.next().await {
                match update {
                    GatewayExtPayStates::Success { preimage, .. } => {
                        debug!("Successfully paid invoice: {contract_id}");
                        return Ok(preimage);
                    }
                    GatewayExtPayStates::Fail {
                        error,
                        error_message,
                    } => {
                        error!("{error_message} while paying invoice: {contract_id}");
                        return Err(GatewayError::OutgoingPaymentError(Box::new(error)));
                    }
                    GatewayExtPayStates::Canceled { error } => {
                        error!("Cancelled with {error} while paying invoice: {contract_id}");
                        return Err(GatewayError::OutgoingPaymentError(Box::new(error)));
                    }
                    GatewayExtPayStates::Created => {
                        debug!("Got initial state Created while paying invoice: {contract_id}");
                    }
                    other => {
                        info!("Got state {other:?} while paying invoice: {contract_id}");
                    }
                };
            }

            return Err(GatewayError::UnexpectedState(
                "Ran out of state updates while paying invoice".to_string(),
            ));
        }

        warn!("Gateway is not connected, cannot handle {payload:?}");
        Err(GatewayError::Disconnected)
    }

    async fn handle_connect_federation(
        &mut self,
        payload: ConnectFedPayload,
    ) -> Result<FederationConnectionInfo> {
        if let GatewayState::Running { lightning_context } = self.state.read().await.clone() {
            let invite_code = InviteCode::from_str(&payload.invite_code).map_err(|e| {
                GatewayError::InvalidMetadata(format!("Invalid federation member string {e:?}"))
            })?;

            // Check if this federation has already been registered
            if self
                .clients
                .read()
                .await
                .get(&invite_code.federation_id())
                .is_some()
            {
                return Err(GatewayError::FederationAlreadyConnected);
            }

            // `GatewayConfiguration` should always exist in the database when we are in the
            // `Running` state.
            let gateway_config = self
                .get_gateway_configuration()
                .await
                .expect("Gateway configuration should be set");

            // The gateway deterministically assigns a channel id (u64) to each federation
            // connected.
            let mut channel_id_generator = self.channel_id_generator.lock().await;
            let mint_channel_id = channel_id_generator.checked_add(1).ok_or(
                GatewayError::GatewayConfigurationError(
                    "Too many connected federations".to_string(),
                ),
            )?;
            *channel_id_generator = mint_channel_id;

            let federation_id = invite_code.federation_id();
            let gw_client_cfg = FederationConfig {
                invite_code,
                mint_channel_id,
                timelock_delta: 10,
                // TODO: Today we use a global routing fees setting. When the gateway supports
                // per-federation routing fees, this value will need to be updated.
                fees: gateway_config.routing_fees,
            };

            let route_hints = Self::fetch_lightning_route_hints(
                lightning_context.lnrpc.clone(),
                gateway_config.num_route_hints,
            )
            .await?;

            let client = self
                .client_builder
                .build(gw_client_cfg.clone(), self.clone())
                .await?;

            let federation_config = FederationConnectionInfo {
                federation_id,
                config: client.get_config().clone(),
            };

            self.check_federation_network(&federation_config, gateway_config.network)
                .await?;

            client
                .get_first_module::<GatewayClientModule>()
                .register_with_federation(
                    route_hints,
                    GW_ANNOUNCEMENT_TTL,
                    gw_client_cfg.fees,
                    lightning_context,
                )
                .await?;
            self.clients.write().await.insert(federation_id, client);
            self.scid_to_federation
                .write()
                .await
                .insert(mint_channel_id, federation_id);

            let dbtx = self.gateway_db.begin_transaction().await;
            self.client_builder
                .save_config(gw_client_cfg.clone(), dbtx)
                .await?;

            return Ok(federation_config);
        }

        Err(GatewayError::Disconnected)
    }

    pub async fn handle_leave_federation(&mut self, payload: LeaveFedPayload) -> Result<()> {
        // TODO: This should optimistically try to contact the federation to remove the
        // registration record
        self.remove_client(payload.federation_id).await?;
        let mut dbtx = self.gateway_db.begin_transaction().await;
        dbtx.remove_entry(&FederationIdKey {
            id: payload.federation_id,
        })
        .await;
        dbtx.commit_tx_result()
            .await
            .map_err(GatewayError::DatabaseError)
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

    pub async fn handle_set_configuration_msg(
        &self,
        SetConfigurationPayload {
            password,
            network,
            num_route_hints,
            routing_fees,
        }: SetConfigurationPayload,
    ) -> Result<()> {
        let gw_state = self.state.read().await.clone();
        let lightning_network = match gw_state {
            GatewayState::Running { lightning_context } => {
                if network.is_some() && network != Some(lightning_context.lightning_network) {
                    return Err(GatewayError::GatewayConfigurationError(
                        "Cannot change network while connected to a lightning node".to_string(),
                    ));
                }
                lightning_context.lightning_network
            }
            // In the case the gateway is not yet running and not yet connected to a lightning node,
            // we start off with a default network configuration. This default gets replaced later
            // when the gateway connects to a lightning node, or when a user sets a different
            // configuration
            _ => DEFAULT_NETWORK,
        };

        let mut dbtx = self.gateway_db.begin_transaction().await;

        let gateway_config = if let Some(mut prev_config) = self.get_gateway_configuration().await {
            if let Some(password) = password {
                prev_config.password = password;
            }

            if let Some(network) = network {
                if self.clients.read().await.len() > 0 {
                    return Err(GatewayError::GatewayConfigurationError(
                        "Cannot change network while connected to a federation".to_string(),
                    ));
                }
                prev_config.network = network;
            }

            if let Some(num_route_hints) = num_route_hints {
                prev_config.num_route_hints = num_route_hints;
            }

            // TODO: Today, the gateway only supports a single routing fee configuration.
            // We will eventually support per-federation routing fees. This configuration
            // will be deprecated when per-federation routing fees are
            // supported.
            if let Some(fees_str) = routing_fees.clone() {
                let routing_fees = GatewayFee::from_str(fees_str.as_str())?.0;
                prev_config.routing_fees = routing_fees;
            }

            prev_config
        } else {
            if password.is_none() {
                return Err(GatewayError::GatewayConfigurationError(
                    "The password field is required when initially configuring the gateway"
                        .to_string(),
                ));
            }

            GatewayConfiguration {
                password: password.unwrap(),
                network: lightning_network,
                num_route_hints: DEFAULT_NUM_ROUTE_HINTS,
                routing_fees: DEFAULT_FEES,
            }
        };

        dbtx.insert_entry(&GatewayConfigurationKey, &gateway_config)
            .await;
        dbtx.commit_tx().await;

        self.update_federation_routing_fees(routing_fees, &gateway_config)
            .await?;
        info!("Set GatewayConfiguration successfully.");

        Ok(())
    }

    /// Updates the routing fees for every federation configuration. Also
    /// triggers a re-register of the gateway with all federations.
    ///
    /// TODO: Once per-federation fees are supported, this function should only
    /// update a single federation's routing fees at a time.
    async fn update_federation_routing_fees(
        &self,
        routing_fees: Option<String>,
        gateway_config: &GatewayConfiguration,
    ) -> Result<()> {
        if let Some(fees_str) = routing_fees {
            let routing_fees = GatewayFee::from_str(fees_str.as_str())?.0;
            let mut dbtx = self.gateway_db.begin_transaction().await;
            let configs = dbtx
                .find_by_prefix(&FederationIdKeyPrefix)
                .await
                .collect::<Vec<_>>()
                .await;

            for (id_key, mut fed_config) in configs {
                fed_config.fees = routing_fees;
                dbtx.insert_entry(&id_key, &fed_config).await;
            }

            dbtx.commit_tx().await;

            Self::register_all_federations(self, gateway_config).await;
        }

        Ok(())
    }

    /// Iterates through all of the federation configurations and registers the
    /// gateway with each federation.
    async fn register_all_federations(gateway: &Gateway, gateway_config: &GatewayConfiguration) {
        let gateway_state = gateway.state.read().await.clone();
        if let GatewayState::Running { lightning_context } = gateway_state {
            match Self::fetch_lightning_route_hints(
                lightning_context.lnrpc.clone(),
                gateway_config.num_route_hints,
            )
            .await
            {
                Ok(route_hints) => {
                    for (federation_id, client) in gateway.clients.read().await.iter() {
                        // Load the federation config to get the routing fees
                        let mut dbtx = gateway.gateway_db.begin_transaction().await.into_nc();
                        if let Some(federation_config) = dbtx
                            .get_value(&FederationIdKey { id: *federation_id })
                            .await
                        {
                            if let Err(e) = client
                                .get_first_module::<GatewayClientModule>()
                                .register_with_federation(
                                    route_hints.clone(),
                                    GW_ANNOUNCEMENT_TTL,
                                    federation_config.fees,
                                    lightning_context.clone(),
                                )
                                .await
                            {
                                warn!("Error registering federation {federation_id}: {e:?}");
                            }
                        } else {
                            warn!("Could not retrieve federation config for {federation_id}");
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Could not retrieve route hints, gateway will not be registered for now: {e:?}"
                    );
                }
            }
        }
    }

    /// This function will return a `GatewayConfiguration` one of two
    /// ways. To avoid conflicting configs, the below order is the
    /// order in which the gateway will respect configurations:
    /// - `GatewayConfiguration` is read from the database.
    /// - All cli or environment variables are set such that we can create a
    ///   `GatewayConfiguration`
    pub async fn get_gateway_configuration(&self) -> Option<GatewayConfiguration> {
        let mut dbtx = self.gateway_db.begin_transaction().await;

        // Always use the gateway configuration from the database if it exists.
        if let Some(gateway_config) = dbtx.get_value(&GatewayConfigurationKey).await {
            return Some(gateway_config);
        }

        // If the DB does not have the gateway configuration, we can construct one from
        // the provided password (required) and the defaults.
        self.gateway_parameters.password.as_ref()?;

        // Use gateway parameters provided by the environment or CLI
        let num_route_hints = self.gateway_parameters.num_route_hints;
        let routing_fees = self
            .gateway_parameters
            .fees
            .clone()
            .unwrap_or(GatewayFee(DEFAULT_FEES));
        let network = self.gateway_parameters.network.unwrap_or(DEFAULT_NETWORK);
        let gateway_config = GatewayConfiguration {
            password: self.gateway_parameters.password.clone().unwrap(),
            network,
            num_route_hints,
            routing_fees: routing_fees.0,
        };

        Some(gateway_config)
    }

    pub async fn remove_client(
        &self,
        federation_id: FederationId,
    ) -> Result<fedimint_client::ClientArc> {
        let client = self.clients.write().await.remove(&federation_id).ok_or(
            GatewayError::InvalidMetadata(format!("No federation with id {federation_id}")),
        )?;
        Ok(client)
    }

    pub async fn select_client(
        &self,
        federation_id: FederationId,
    ) -> Result<fedimint_client::ClientArc> {
        self.clients
            .read()
            .await
            .get(&federation_id)
            .cloned()
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))
    }

    async fn load_clients(&mut self) {
        let dbtx = self.gateway_db.begin_transaction().await;
        let configs = self.client_builder.load_configs(dbtx.into_nc()).await;
        let mut channel_id_generator = self.channel_id_generator.lock().await;
        let mut next_channel_id = *channel_id_generator;

        for config in configs {
            let federation_id = config.invite_code.federation_id();

            if let Ok(client) = self
                .client_builder
                .build(config.clone(), self.clone())
                .await
            {
                // Registering each client happens in the background, since we're loading
                // the clients for the first time, just add them to
                // the in-memory maps
                let scid = config.mint_channel_id;
                self.clients.write().await.insert(federation_id, client);
                self.scid_to_federation
                    .write()
                    .await
                    .insert(scid, federation_id);
            } else {
                warn!("Failed to load client for federation: {federation_id}");
            }

            if config.mint_channel_id > next_channel_id {
                next_channel_id = config.mint_channel_id + 1;
            }
        }

        *channel_id_generator = next_channel_id;
    }

    async fn register_clients_timer(&mut self, task_group: &mut TaskGroup) {
        let gateway = self.clone();
        task_group
            .spawn("register clients", move |handle| async move {
                let registration_loop = async {
                    loop {
                        if let Some(gateway_config) = gateway.get_gateway_configuration().await {
                            let gateway_state = gateway.state.read().await.clone();
                            if let GatewayState::Running { .. } = &gateway_state {
                                Self::register_all_federations(&gateway, &gateway_config).await;
                            } else {
                                // We need to retry more often if the gateway is not in the Running state
                                const NOT_RUNNING_RETRY: Duration = Duration::from_secs(10);
                                info!("Will not register federation yet because gateway still not in Running state. Current state: {gateway_state:?}. Will keep waiting, next retry in {NOT_RUNNING_RETRY:?}...");
                                sleep(NOT_RUNNING_RETRY).await;
                                continue;
                            }
                        } else {
                            warn!("Cannot register clients because gateway configuration is not set.");
                        }

                        // Allow a 15% buffer of the TTL before the re-registering gateway
                        // with the federations.
                        let registration_delay = GW_ANNOUNCEMENT_TTL.mul_f32(0.85);
                        sleep(registration_delay).await;
                    }
                };

                // The registration loop will sleep for long periods, so we allow shutdown
                // signals to interrupt waiting for the rest of the loop to finish.
                //
                // If the loop is interrupted while in the middle of registering clients,
                // start_gateway will spawn another task to register clients once a connection
                // with the LN node is reestablished.
                tokio::select! {
                    _ = handle.make_shutdown_rx().await => {
                        info!("register clients task received shutdown signal")
                    }
                    _ = registration_loop => {}
                }
            })
            .await;
    }

    async fn fetch_lightning_route_hints_try(
        lnrpc: &dyn ILnRpcClient,
        num_route_hints: u32,
    ) -> Result<Vec<RouteHint>> {
        let route_hints = lnrpc
            .routehints(num_route_hints as usize)
            .await?
            .try_into()
            .expect("Could not parse route hints");

        Ok(route_hints)
    }

    async fn fetch_lightning_route_hints(
        lnrpc: Arc<dyn ILnRpcClient>,
        num_route_hints: u32,
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
        client: &ClientArc,
        federation_id: FederationId,
    ) -> FederationInfo {
        let balance_msat = client.get_balance().await;

        FederationInfo {
            federation_id,
            balance_msat,
        }
    }

    async fn check_federation_network(
        &self,
        info: &FederationConnectionInfo,
        network: Network,
    ) -> Result<()> {
        let cfg = info
            .config
            .modules
            .values()
            .find(|m| LightningCommonInit::KIND == m.kind.clone())
            .ok_or_else(|| {
                GatewayError::InvalidMetadata(format!(
                    "Federation {} does not have a lightning module",
                    info.federation_id
                ))
            })?;
        let ln_cfg: &LightningClientConfig = cfg.cast()?;

        if ln_cfg.network != network {
            error!(
                "Federation {} runs on {} but this gateway supports {}",
                info.federation_id, ln_cfg.network, network,
            );
            return Err(GatewayError::UnsupportedNetwork(ln_cfg.network));
        }

        Ok(())
    }

    /// Checks the Gateway's current state and returns the proper
    /// `LightningContext` if it is available. Sometimes the lightning node
    /// will not be connected and this will return an error.
    pub async fn get_lightning_context(
        &self,
    ) -> std::result::Result<LightningContext, LightningRpcError> {
        match self.state.read().await.clone() {
            GatewayState::Running { lightning_context } => Ok(lightning_context),
            _ => Err(LightningRpcError::FailedToConnect),
        }
    }
}

pub(crate) async fn fetch_lightning_node_info(
    lnrpc: Arc<dyn ILnRpcClient>,
) -> Result<(PublicKey, String, Network)> {
    let GetNodeInfoResponse {
        pub_key,
        alias,
        network,
    } = lnrpc.info().await?;
    let node_pub_key = PublicKey::from_slice(&pub_key)
        .map_err(|e| GatewayError::InvalidMetadata(format!("Invalid node pubkey {e}")))?;
    // TODO: create a fedimint Network that understands "mainnet"
    let network = match network.as_str() {
        "mainnet" => "bitcoin", // it seems LND will use "mainnet", but rust-bitcoin uses "bitcoin"
        other => other,
    };
    let network = Network::from_str(network)
        .map_err(|e| GatewayError::InvalidMetadata(format!("Invalid network {network}: {e}")))?;
    Ok((node_pub_key, alias, network))
}

async fn wait_for_new_password(
    gateway_db: &Database,
    gateway_config: Option<GatewayConfiguration>,
) {
    gateway_db
        .wait_key_check(&GatewayConfigurationKey, |v| {
            v.filter(|cfg| {
                if let Some(old_config) = gateway_config.clone() {
                    old_config.password != cfg.clone().password
                } else {
                    true
                }
            })
        })
        .await;
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Federation error: {}", OptStacktrace(.0))]
    FederationError(#[from] FederationError),
    #[error("Other: {}", OptStacktrace(.0))]
    ClientStateMachineError(#[from] anyhow::Error),
    #[error("Failed to open the database: {}", OptStacktrace(.0))]
    DatabaseError(anyhow::Error),
    #[error("Federation client error")]
    LightningRpcError(#[from] LightningRpcError),
    #[error("Outgoing Payment Error {}", OptStacktrace(.0))]
    OutgoingPaymentError(#[from] Box<OutgoingPaymentError>),
    #[error("Invalid Metadata: {}", OptStacktrace(.0))]
    InvalidMetadata(String),
    #[error("Unexpected state: {}", OptStacktrace(.0))]
    UnexpectedState(String),
    #[error("The gateway is disconnected")]
    Disconnected,
    #[error("Error configuring the gateway: {}", OptStacktrace(.0))]
    GatewayConfigurationError(String),
    #[error("Unsupported Network: {0}")]
    UnsupportedNetwork(Network),
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Federation already connected")]
    FederationAlreadyConnected,
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

pub struct PrettyInterceptHtlcRequest<'a>(&'a crate::gateway_lnrpc::InterceptHtlcRequest);
impl Display for PrettyInterceptHtlcRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PrettyInterceptHtlcRequest(htlc_request) = self;
        write!(
            f,
            "InterceptHtlcRequest {{ payment_hash: {}, incoming_amount_msat: {:?}, outgoing_amount_msat: {:?}, incoming_expiry: {:?}, short_channel_id: {:?}, incoming_chan_id: {:?}, htlc_id: {:?} }}",
            htlc_request.payment_hash.to_hex(),
            htlc_request.incoming_amount_msat,
            htlc_request.outgoing_amount_msat,
            htlc_request.incoming_expiry,
            htlc_request.short_channel_id,
            htlc_request.incoming_chan_id,
            htlc_request.htlc_id,
        )
    }
}
