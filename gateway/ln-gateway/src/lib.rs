pub mod client;
mod db;
pub mod envs;
pub mod gateway_module_v2;
pub mod lightning;
pub mod rpc;
pub mod state_machine;
mod types;

pub mod gateway_lnrpc {
    tonic::include_proto!("gateway_lnrpc");
}

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::env;
use std::fmt::Display;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::{Address, Network, Txid};
use bitcoin_hashes::sha256;
use clap::Parser;
use client::GatewayClientBuilder;
use db::{
    DbKeyPrefix, FederationIdKey, GatewayConfiguration, GatewayConfigurationKey, GatewayPublicKey,
    GATEWAYD_DATABASE_VERSION,
};
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::ClientHandleArc;
use fedimint_core::api::{FederationError, InviteCode};
use fedimint_core::bitcoin_migration::{
    bitcoin29_to_bitcoin30_address, bitcoin29_to_bitcoin30_amount, bitcoin29_to_bitcoin30_network,
    bitcoin29_to_bitcoin30_txid, bitcoin30_to_bitcoin29_amount, bitcoin30_to_bitcoin29_network,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::{
    ModuleInstanceId, ModuleKind, OperationId, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::{
    apply_migrations_server, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::Encodable;
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_core::module::CommonModuleInit;
use fedimint_core::task::{sleep, TaskGroup, TaskHandle, TaskShutdownToken};
use fedimint_core::time::{duration_since_epoch, now};
use fedimint_core::util::{SafeUrl, Spanned};
use fedimint_core::{
    fedimint_build_code_version_env, push_db_pair_items, Amount, BitcoinAmountOrAll, BitcoinHash,
};
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_ln_common::config::{GatewayFee, LightningClientConfig};
use fedimint_ln_common::contracts::Preimage;
use fedimint_ln_common::route_hints::RouteHint;
use fedimint_ln_common::LightningCommonInit;
use fedimint_lnv2_client::api::LnFederationApi;
use fedimint_lnv2_client::{
    CreateInvoicePayload, PaymentFee, PaymentFees, PaymentInfo, SendPaymentPayload,
};
use fedimint_mint_client::{MintClientInit, MintCommonInit};
use fedimint_wallet_client::{
    WalletClientInit, WalletClientModule, WalletCommonInit, WithdrawState,
};
use futures::stream::StreamExt;
use gateway_lnrpc::intercept_htlc_response::Action;
use gateway_lnrpc::{GetNodeInfoResponse, InterceptHtlcResponse};
use hex::ToHex;
use lightning::{ILnRpcClient, LightningBuilder, LightningMode, LightningRpcError};
use lightning_invoice::{Bolt11Invoice, RoutingFees};
use rand::rngs::OsRng;
use rand::Rng;
use rpc::{
    FederationInfo, GatewayFedConfig, GatewayInfo, LeaveFedPayload, SetConfigurationPayload,
    V1_API_ENDPOINT,
};
use secp256k1::schnorr::Signature;
use secp256k1::PublicKey;
use state_machine::pay::OutgoingPaymentError;
use state_machine::GatewayClientModule;
use strum::IntoEnumIterator;
use thiserror::Error;
use tokio::sync::{Mutex, MutexGuard, RwLock};
use tracing::{debug, error, info, info_span, warn, Instrument};

use crate::db::{
    get_gatewayd_database_migrations, CreateInvoicePayloadKey, FederationConfig,
    FederationIdKeyPrefix,
};
use crate::gateway_lnrpc::intercept_htlc_response::Forward;
use crate::gateway_lnrpc::CreateInvoiceRequest;
use crate::gateway_module_v2::GatewayClientModuleV2;
use crate::lightning::cln::RouteHtlcStream;
use crate::lightning::GatewayLightningBuilder;
use crate::rpc::rpc_server::{hash_password, run_webserver};
use crate::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, RestorePayload,
    WithdrawPayload,
};
use crate::state_machine::GatewayExtPayStates;
/// This initial SCID is considered invalid by LND HTLC interceptor,
/// So we should always increment the value before assigning a new SCID.
const INITIAL_SCID: u64 = 0;

/// How long a gateway announcement stays valid
const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

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

const OUTGOING_CLTV_DELTA_V2: u64 = 144;

pub type Result<T> = std::result::Result<T, GatewayError>;

const DB_FILE: &str = "gatewayd.db";

const DEFAULT_MODULE_KINDS: [(ModuleInstanceId, &ModuleKind); 2] = [
    (LEGACY_HARDCODED_INSTANCE_ID_MINT, &MintCommonInit::KIND),
    (LEGACY_HARDCODED_INSTANCE_ID_WALLET, &WalletCommonInit::KIND),
];

#[derive(Parser)]
#[command(version)]
struct GatewayOpts {
    #[clap(subcommand)]
    mode: LightningMode,

    /// Path to folder containing gateway config and data files
    #[arg(long = "data-dir", env = envs::FM_GATEWAY_DATA_DIR_ENV)]
    pub data_dir: PathBuf,

    /// Gateway webserver listen address
    #[arg(long = "listen", env = envs::FM_GATEWAY_LISTEN_ADDR_ENV)]
    pub listen: SocketAddr,

    /// Public URL from which the webserver API is reachable
    #[arg(long = "api-addr", env = envs::FM_GATEWAY_API_ADDR_ENV)]
    pub api_addr: SafeUrl,

    /// Gateway webserver authentication password
    #[arg(long = "password", env = envs::FM_GATEWAY_PASSWORD_ENV)]
    pub password: Option<String>,

    /// Bitcoin network this gateway will be running on
    #[arg(long = "network", env = envs::FM_GATEWAY_NETWORK_ENV)]
    pub network: Option<Network>,

    /// Configured gateway routing fees
    /// Format: <base_msat>,<proportional_millionths>
    #[arg(long = "fees", env = envs::FM_GATEWAY_FEES_ENV)]
    pub fees: Option<GatewayFee>,

    /// Number of route hints to return in invoices
    #[arg(
        long = "num-route-hints",
        env = envs::FM_NUMBER_OF_ROUTE_HINTS_ENV,
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
pub struct GatewayParameters {
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

type ScidToFederationMap = Arc<RwLock<BTreeMap<u64, FederationId>>>;
type FederationToClientMap =
    Arc<RwLock<BTreeMap<FederationId, Spanned<fedimint_client::ClientHandleArc>>>>;

/// Represents an active connection to the lightning node.
#[derive(Clone, Debug)]
pub struct LightningContext {
    pub lnrpc: Arc<dyn ILnRpcClient>,
    pub lightning_public_key: PublicKey,
    pub lightning_alias: String,
    pub lightning_network: Network,
}

// A marker struct, to distinguish lock over `Gateway::clients`.
struct ClientsJoinLock;

#[derive(Clone)]
pub struct Gateway {
    // Builder struct that allows the gateway to build a `ILnRpcClient`, which represents a
    // connection to a lightning node.
    lightning_builder: Arc<dyn LightningBuilder + Send + Sync>,

    // The gateway's current configuration
    pub gateway_config: Arc<RwLock<Option<GatewayConfiguration>>>,

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

    /// Joining or leaving Federation is protected by this lock to prevent
    /// trying to use same database at the same time from multiple threads.
    /// Could be more granular (per id), but shouldn't matter in practice.
    client_joining_lock: Arc<tokio::sync::Mutex<ClientsJoinLock>>,

    // Map of short channel ids to `FederationId`. Use for efficient retrieval of the client while
    // handling incoming HTLCs.
    scid_to_federation: ScidToFederationMap,

    // A public key representing the identity of the gateway. Private key is not used.
    pub gateway_id: secp256k1::PublicKey,

    // Tracker for short channel ID assignments. When connecting a new federation,
    // this value is incremented and assigned to the federation as the `mint_channel_id`
    max_used_scid: Arc<Mutex<u64>>,

    // The Gateway's API URL.
    versioned_api: SafeUrl,

    // The socket the gateway listens on.
    listen: SocketAddr,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("gateway_config", &self.gateway_config)
            .field("state", &self.state)
            .field("client_builder", &self.client_builder)
            .field("gateway_db", &self.gateway_db)
            .field("clients", &self.clients)
            .field("scid_to_federation", &self.scid_to_federation)
            .field("gateway_id", &self.gateway_id)
            .field("max_used_scid", &self.max_used_scid)
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
        Gateway::new(
            lightning_builder,
            GatewayParameters {
                listen,
                versioned_api,
                password: cli_password,
                num_route_hints,
                fees: Some(GatewayFee(fees)),
                network,
            },
            gateway_db,
            client_builder,
        )
        .await
    }

    pub async fn new_with_default_modules() -> anyhow::Result<Gateway> {
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
            fedimint_build_code_version_env!()
        );

        Gateway::new(
            Arc::new(GatewayLightningBuilder {
                lightning_mode: opts.mode.clone(),
            }),
            opts.to_gateway_parameters()?,
            gateway_db,
            client_builder,
        )
        .await
    }

    pub async fn new(
        lightning_builder: Arc<dyn LightningBuilder + Send + Sync>,
        gateway_parameters: GatewayParameters,
        gateway_db: Database,
        client_builder: GatewayClientBuilder,
    ) -> anyhow::Result<Gateway> {
        // Apply database migrations before using the database
        apply_migrations_server(
            &gateway_db,
            "gatewayd".to_string(),
            GATEWAYD_DATABASE_VERSION,
            get_gatewayd_database_migrations(),
        )
        .await?;

        let gateway_config =
            Self::get_gateway_configuration(gateway_db.clone(), &gateway_parameters).await;

        Ok(Self {
            lightning_builder,
            max_used_scid: Arc::new(Mutex::new(INITIAL_SCID)),
            gateway_config: Arc::new(RwLock::new(gateway_config)),
            state: Arc::new(RwLock::new(GatewayState::Initializing)),
            client_builder,
            gateway_id: Self::get_gateway_id(gateway_db.clone()).await,
            gateway_db,
            clients: Arc::new(RwLock::new(BTreeMap::new())),
            scid_to_federation: Arc::new(RwLock::new(BTreeMap::new())),
            client_joining_lock: Arc::new(Mutex::new(ClientsJoinLock)),
            versioned_api: gateway_parameters.versioned_api,
            listen: gateway_parameters.listen,
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
        self.register_clients_timer(tg).await;
        self.load_clients().await;
        self.start_gateway(tg).await?;
        // start webserver last to avoid handling requests before fully initialized
        run_webserver(self.clone(), tg).await?;
        let handle = tg.make_handle();
        let shutdown_receiver = handle.make_shutdown_rx().await;
        Ok(shutdown_receiver)
    }

    async fn start_gateway(&self, task_group: &mut TaskGroup) -> Result<()> {
        let mut self_copy = self.clone();
        let tg = task_group.clone();
        task_group.spawn("Subscribe to intercepted HTLCs in stream", move |handle| async move {
            loop {
                if handle.is_shutting_down() {
                    info!("Gateway HTLC handler loop is shutting down");
                    break;
                }

                let mut htlc_task_group = tg.make_subgroup();
                let lnrpc_route = self_copy.lightning_builder.build().await;

                debug!("Will try to intercept HTLC stream...");
                // Re-create the HTLC stream if the connection breaks
                match lnrpc_route
                    .route_htlcs(&mut htlc_task_group)
                    .await
                {
                    Ok((stream, ln_client)) => {
                        // Successful calls to route_htlcs establish a connection
                        self_copy.set_gateway_state(GatewayState::Connected).await;
                        info!("Established HTLC stream");

                        match fetch_lightning_node_info(ln_client.clone()).await {
                            Ok((lightning_public_key, lightning_alias, lightning_network)) => {
                                let gateway_config = self_copy.gateway_config.read().await.clone();
                                let gateway_config = if let Some(config) = gateway_config {
                                    config
                                } else {
                                    self_copy.set_gateway_state(GatewayState::Configuring).await;
                                    info!("Waiting for gateway to be configured...");
                                    self_copy.gateway_db
                                        .wait_key_exists(&GatewayConfigurationKey)
                                        .await
                                };

                                if gateway_config.network != bitcoin30_to_bitcoin29_network(lightning_network) {
                                    warn!("Lightning node does not match previously configured gateway network : ({:?})", gateway_config.network);
                                    info!("Changing gateway network to match lightning node network : ({:?})", lightning_network);
                                    self_copy.handle_disconnect(htlc_task_group).await;
                                    self_copy.handle_set_configuration_msg(SetConfigurationPayload {
                                        password: None,
                                        network: Some(bitcoin30_to_bitcoin29_network(lightning_network)),
                                        num_route_hints: None,
                                        routing_fees: None,
                                        per_federation_routing_fees: None,
                                    }).await.expect("Failed to set gateway configuration");
                                    continue;
                                }

                                info!("Successfully loaded Gateway clients.");
                                let lightning_context = LightningContext {
                                    lnrpc: ln_client,
                                    lightning_public_key,
                                    lightning_alias,
                                    lightning_network,
                                };
                                self_copy.set_gateway_state(GatewayState::Running {
                                    lightning_context
                                }).await;

                                // Blocks until the connection to the lightning node breaks or we receive the shutdown signal
                                match handle.cancel_on_shutdown(self_copy.handle_htlc_stream(stream, handle.clone())).await {
                                    Ok(_) => {
                                        warn!("HTLC Stream Lightning connection broken. Gateway is disconnected");
                                    },
                                    Err(_) => {
                                        info!("Received shutdown signal");
                                        self_copy.handle_disconnect(htlc_task_group).await;
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
                        warn!("Failed to open HTLC stream: {e:?}");
                    }
                }

                self_copy.handle_disconnect(htlc_task_group).await;

                warn!("Disconnected from Lightning Node. Waiting 5 seconds and trying again");
                sleep(Duration::from_secs(5)).await;
            }
        });

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
                            let cf = client
                                .borrow()
                                .with(|client| async {
                                    let htlc = htlc_request.clone().try_into();
                                    if let Ok(htlc) = htlc {
                                        match client
                                            .get_first_module::<GatewayClientModule>()
                                            .gateway_handle_intercepted_htlc(htlc)
                                            .await
                                        {
                                            Ok(_) => {
                                                return Some(ControlFlow::<(), ()>::Continue(()))
                                            }
                                            Err(e) => {
                                                info!(
                                                "Got error intercepting HTLC: {e:?}, will retry..."
                                            )
                                            }
                                        }
                                    } else {
                                        info!("Got no HTLC result")
                                    }
                                    None
                                })
                                .await;
                            if let Some(ControlFlow::Continue(())) = cf {
                                continue;
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
                .gateway_config
                .read()
                .await
                .clone()
                .expect("Gateway configuration should be set");
            let mut federations = Vec::new();
            let federation_clients = self.clients.read().await.clone().into_iter();
            let route_hints = Self::fetch_lightning_route_hints(
                lightning_context.lnrpc.clone(),
                gateway_config.num_route_hints,
            )
            .await?;
            for (federation_id, client) in federation_clients {
                federations.push(
                    client
                        .borrow()
                        .with(|client| self.make_federation_info(client, federation_id))
                        .await,
                );
            }

            return Ok(GatewayInfo {
                federations,
                channels: Some(self.scid_to_federation.read().await.clone()),
                version_hash: fedimint_build_code_version_env!().to_string(),
                lightning_pub_key: Some(lightning_context.lightning_public_key.to_string()),
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
            channels: None,
            version_hash: fedimint_build_code_version_env!().to_string(),
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
                federations.insert(
                    federation_id,
                    client.borrow().with_sync(|client| client.get_config_json()),
                );
            } else {
                let federation_clients = self.clients.read().await.clone().into_iter();
                for (federation_id, client) in federation_clients {
                    federations.insert(
                        federation_id,
                        client.borrow().with_sync(|client| client.get_config_json()),
                    );
                }
            }
            return Ok(GatewayFedConfig { federations });
        }
        Ok(GatewayFedConfig {
            federations: BTreeMap::new(),
        })
    }

    pub async fn handle_balance_msg(&self, payload: BalancePayload) -> Result<Amount> {
        // no need for instrument, it is done on api layer
        Ok(self
            .select_client(payload.federation_id)
            .await?
            .value()
            .get_balance()
            .await)
    }

    pub async fn handle_address_msg(&self, payload: DepositAddressPayload) -> Result<Address> {
        let (_, address) = self
            .select_client(payload.federation_id)
            .await?
            .value()
            .get_first_module::<WalletClientModule>()
            .get_deposit_address(now() + Duration::from_secs(86400 * 365), ())
            .await?;
        Ok(bitcoin29_to_bitcoin30_address(address).assume_checked())
    }

    pub async fn handle_withdraw_msg(&self, payload: WithdrawPayload) -> Result<Txid> {
        let WithdrawPayload {
            amount,
            address,
            federation_id,
        } = payload;
        let client = self.select_client(federation_id).await?;
        let wallet_module = client.value().get_first_module::<WalletClientModule>();

        // TODO: Fees should probably be passed in as a parameter
        let (amount, fees) = match amount {
            // If the amount is "all", then we need to subtract the fees from
            // the amount we are withdrawing
            BitcoinAmountOrAll::All => {
                let balance =
                    bitcoin::Amount::from_sat(client.value().get_balance().await.msats / 1000);
                let fees = wallet_module
                    .get_withdraw_fees(address.clone(), bitcoin30_to_bitcoin29_amount(balance))
                    .await?;
                let withdraw_amount =
                    balance.checked_sub(bitcoin29_to_bitcoin30_amount(fees.amount()));
                if withdraw_amount.is_none() {
                    return Err(GatewayError::InsufficientFunds);
                }
                (withdraw_amount.unwrap(), fees)
            }
            BitcoinAmountOrAll::Amount(amount) => (
                bitcoin29_to_bitcoin30_amount(amount),
                wallet_module
                    .get_withdraw_fees(address.clone(), amount)
                    .await?,
            ),
        };

        let operation_id = wallet_module
            .withdraw(
                address.clone(),
                bitcoin30_to_bitcoin29_amount(amount),
                fees,
                (),
            )
            .await?;
        let mut updates = wallet_module
            .subscribe_withdraw_updates(operation_id)
            .await?
            .into_stream();

        while let Some(update) = updates.next().await {
            match update {
                WithdrawState::Succeeded(txid) => {
                    info!("Sent {amount} funds to address {address}");
                    return Ok(bitcoin29_to_bitcoin30_txid(txid));
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
            let gateway_module = &client.value().get_first_module::<GatewayClientModule>();
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
    ) -> Result<FederationInfo> {
        if let GatewayState::Running { lightning_context } = self.state.read().await.clone() {
            let invite_code = InviteCode::from_str(&payload.invite_code).map_err(|e| {
                GatewayError::InvalidMetadata(format!("Invalid federation member string {e:?}"))
            })?;
            let federation_id = invite_code.federation_id();

            let _join_federation = self.client_joining_lock.lock().await;

            // Check if this federation has already been registered
            if self.clients.read().await.get(&federation_id).is_some() {
                return Err(GatewayError::FederationAlreadyConnected);
            }

            // `GatewayConfiguration` should always exist in the database when we are in the
            // `Running` state.
            let gateway_config = self
                .gateway_config
                .read()
                .await
                .clone()
                .expect("Gateway configuration should be set");

            // The gateway deterministically assigns a channel id (u64) to each federation
            // connected.
            let mut max_used_scid = self.max_used_scid.lock().await;
            let mint_channel_id =
                max_used_scid
                    .checked_add(1)
                    .ok_or(GatewayError::GatewayConfigurationError(
                        "Too many connected federations".to_string(),
                    ))?;
            *max_used_scid = mint_channel_id;

            let gw_client_cfg = FederationConfig {
                invite_code,
                mint_channel_id,
                timelock_delta: 10,
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

            // Instead of using `make_federation_info`, we manually create federation info
            // here because short channel id is not yet persisted
            let federation_info = FederationInfo {
                federation_id,
                balance_msat: client.get_balance().await,
                config: client.get_config().clone(),
                channel_id: Some(mint_channel_id),
                routing_fees: Some(gateway_config.routing_fees.into()),
            };

            self.check_federation_network(
                &federation_info,
                bitcoin29_to_bitcoin30_network(gateway_config.network),
            )
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
            // no need to enter span earlier, because connect-fed has a span
            self.clients.write().await.insert(
                federation_id,
                Spanned::new(
                    info_span!("client", federation_id=%federation_id.clone()),
                    async move { client },
                )
                .await,
            );
            self.scid_to_federation
                .write()
                .await
                .insert(mint_channel_id, federation_id);

            let dbtx = self.gateway_db.begin_transaction().await;
            self.client_builder
                .save_config(gw_client_cfg.clone(), dbtx)
                .await?;
            debug!("Federation with ID: {federation_id} connected and assigned channel id: {mint_channel_id}");

            return Ok(federation_info);
        }

        Err(GatewayError::Disconnected)
    }

    pub async fn handle_leave_federation(
        &mut self,
        payload: LeaveFedPayload,
    ) -> Result<FederationInfo> {
        let client_joining_lock = self.client_joining_lock.lock().await;
        let mut dbtx = self.gateway_db.begin_transaction().await;

        let federation_info = {
            let client = self.select_client(payload.federation_id).await?;
            let federation_info = self
                .make_federation_info(client.value(), payload.federation_id)
                .await;

            let keypair = dbtx
                .get_value(&GatewayPublicKey)
                .await
                .expect("Gateway keypair does not exist");
            client
                .value()
                .get_first_module::<GatewayClientModule>()
                .remove_from_federation(keypair)
                .await;
            federation_info
        };

        self.remove_client(payload.federation_id, &client_joining_lock)
            .await?;
        dbtx.remove_entry(&FederationIdKey {
            id: payload.federation_id,
        })
        .await;
        dbtx.commit_tx_result()
            .await
            .map_err(GatewayError::DatabaseError)?;
        Ok(federation_info)
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
            per_federation_routing_fees,
        }: SetConfigurationPayload,
    ) -> Result<()> {
        let gw_state = self.state.read().await.clone();
        let lightning_network = match gw_state {
            GatewayState::Running { lightning_context } => {
                if network.is_some()
                    && network
                        != Some(bitcoin30_to_bitcoin29_network(
                            lightning_context.lightning_network,
                        ))
                {
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

        let prev_gateway_config = self.gateway_config.read().await.clone();
        let new_gateway_config = if let Some(mut prev_config) = prev_gateway_config {
            if let Some(password) = password {
                let hashed_password = hash_password(password, prev_config.password_salt);
                prev_config.hashed_password = hashed_password;
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

            // Using this routing fee config as a default for all federation that has none
            // routing fees specified.
            if let Some(fees_str) = routing_fees.clone() {
                let routing_fees = GatewayFee::from_str(fees_str.as_str())?.0;
                prev_config.routing_fees = routing_fees;
            }

            prev_config
        } else {
            let password = password.ok_or(GatewayError::GatewayConfigurationError(
                "The password field is required when initially configuring the gateway".to_string(),
            ))?;
            let password_salt: [u8; 16] = rand::thread_rng().gen();
            let hashed_password = hash_password(password, password_salt);

            GatewayConfiguration {
                hashed_password,
                network: bitcoin30_to_bitcoin29_network(lightning_network),
                num_route_hints: DEFAULT_NUM_ROUTE_HINTS,
                routing_fees: DEFAULT_FEES,
                password_salt,
            }
        };
        dbtx.insert_entry(&GatewayConfigurationKey, &new_gateway_config)
            .await;

        let mut register_federations: Vec<(FederationId, FederationConfig)> = Vec::new();
        if let Some(per_federation_routing_fees) = per_federation_routing_fees {
            for (federation_id, routing_fees) in per_federation_routing_fees.iter() {
                let federation_key = FederationIdKey { id: *federation_id };
                if let Some(mut federation_config) = dbtx.get_value(&federation_key).await {
                    federation_config.fees = routing_fees.clone().into();
                    dbtx.insert_entry(&federation_key, &federation_config).await;
                    register_federations.push((*federation_id, federation_config));
                } else {
                    warn!("Given federation {federation_id} not found for updating routing fees");
                }
            }
        }

        // If 'num_route_hints' is provided, all federations must be re-registered.
        // Otherwise, only those affected by the new fees need to be re-registered.
        if num_route_hints.is_some() {
            let all_federations_configs: Vec<_> = dbtx
                .find_by_prefix(&FederationIdKeyPrefix)
                .await
                .map(|(key, config)| (key.id, config))
                .collect()
                .await;
            self.register_federations(&new_gateway_config, &all_federations_configs)
                .await?;
        } else {
            self.register_federations(&new_gateway_config, &register_federations)
                .await?;
        }

        dbtx.commit_tx().await;

        let mut curr_gateway_config = self.gateway_config.write().await;
        *curr_gateway_config = Some(new_gateway_config.clone());

        info!("Set GatewayConfiguration successfully.");

        Ok(())
    }

    /// Registers the gateway with each specified federation.
    async fn register_federations(
        &self,
        gateway_config: &GatewayConfiguration,
        federations: &[(FederationId, FederationConfig)],
    ) -> Result<()> {
        if let Ok(lightning_context) = self.get_lightning_context().await {
            match Self::fetch_lightning_route_hints(
                lightning_context.lnrpc.clone(),
                gateway_config.num_route_hints
            )
            .await
            {
                Ok(route_hints) => {
                    for (federation_id, federation_config) in federations {
                        if let Some(client) = self.clients.read().await.get(federation_id) {
                            if let Err(e) = async {
                                client
                                    .value()
                                    .get_first_module::<GatewayClientModule>()
                                    .register_with_federation(
                                        route_hints.clone(),
                                        GW_ANNOUNCEMENT_TTL,
                                        federation_config.fees,
                                        lightning_context.clone(),
                                    )
                                    .await
                            }
                            .instrument(client.span())
                            .await
                            {
                                Err(GatewayError::FederationError(FederationError::general(
                                    anyhow::anyhow!(
                                        "Error registering federation {federation_id}: {e:?}"
                                    ),
                                )))?
                            }
                        }
                    }
                }
                Err(e) => Err(GatewayError::LightningRpcError(
                    LightningRpcError::FailedToGetRouteHints {
                        failure_reason: format!(
                            "Could not retrieve route hints, gateway will not be registered for now: {e:?}"
                        ),
                    },
                ))?,
            }
        }
        Ok(())
    }

    /// This function will return a `GatewayConfiguration` one of two
    /// ways. To avoid conflicting configs, the below order is the
    /// order in which the gateway will respect configurations:
    /// - `GatewayConfiguration` is read from the database.
    /// - All cli or environment variables are set such that we can create a
    ///   `GatewayConfiguration`
    async fn get_gateway_configuration(
        gateway_db: Database,
        gateway_parameters: &GatewayParameters,
    ) -> Option<GatewayConfiguration> {
        let mut dbtx = gateway_db.begin_transaction().await;

        // Always use the gateway configuration from the database if it exists.
        if let Some(gateway_config) = dbtx.get_value(&GatewayConfigurationKey).await {
            return Some(gateway_config);
        }

        // If the password is not provided, return None
        let password = gateway_parameters.password.as_ref()?;

        // If the DB does not have the gateway configuration, we can construct one from
        // the provided password (required) and the defaults.
        // Use gateway parameters provided by the environment or CLI
        let num_route_hints = gateway_parameters.num_route_hints;
        let routing_fees = gateway_parameters
            .fees
            .clone()
            .unwrap_or(GatewayFee(DEFAULT_FEES));
        let network = gateway_parameters.network.unwrap_or(DEFAULT_NETWORK);
        let password_salt: [u8; 16] = rand::thread_rng().gen();
        let hashed_password = hash_password(password.clone(), password_salt);
        let gateway_config = GatewayConfiguration {
            hashed_password,
            network: bitcoin30_to_bitcoin29_network(network),
            num_route_hints,
            routing_fees: routing_fees.0,
            password_salt,
        };

        Some(gateway_config)
    }

    async fn remove_client(
        &self,
        federation_id: FederationId,
        // Note: MUST be protected by a lock, to keep
        // `clients` and opened databases in sync
        _lock: &MutexGuard<'_, ClientsJoinLock>,
    ) -> Result<()> {
        let client = self
            .clients
            .write()
            .await
            .remove(&federation_id)
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))?
            .into_value();

        if let Some(client) = Arc::into_inner(client) {
            client.shutdown().await;
        } else {
            error!("client is not unique, failed to remove client");
        }

        // Remove previously assigned scid from `scid_to_federation` map
        self.scid_to_federation
            .write()
            .await
            .retain(|_, fid| *fid != federation_id);
        Ok(())
    }

    pub async fn remove_client_hack(
        &self,
        federation_id: FederationId,
    ) -> Result<Spanned<fedimint_client::ClientHandleArc>> {
        let client = self.clients.write().await.remove(&federation_id).ok_or(
            GatewayError::InvalidMetadata(format!("No federation with id {federation_id}")),
        )?;
        Ok(client)
    }

    pub async fn select_client(
        &self,
        federation_id: FederationId,
    ) -> Result<Spanned<fedimint_client::ClientHandleArc>> {
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

        let _join_federation = self.client_joining_lock.lock().await;

        for config in configs.clone() {
            let federation_id = config.invite_code.federation_id();
            let scid = config.mint_channel_id;

            if let Ok(client) = Spanned::try_new(
                info_span!("client", federation_id  = %federation_id.clone()),
                self.client_builder.build(config.clone(), self.clone()),
            )
            .await
            {
                // Registering each client happens in the background, since we're loading
                // the clients for the first time, just add them to
                // the in-memory maps
                self.clients.write().await.insert(federation_id, client);
                self.scid_to_federation
                    .write()
                    .await
                    .insert(scid, federation_id);
            } else {
                warn!("Failed to load client for federation: {federation_id}");
            }
        }

        if let Some(max_mint_channel_id) = configs.iter().map(|cfg| cfg.mint_channel_id).max() {
            let mut max_used_scid = self.max_used_scid.lock().await;
            *max_used_scid = max_mint_channel_id;
        }
    }

    async fn register_clients_timer(&mut self, task_group: &mut TaskGroup) {
        let gateway = self.clone();
        task_group.spawn_cancellable("register clients", async move {
            loop {
                let mut registration_result: Option<Result<()>> = None;
                let gateway_config = gateway.gateway_config.read().await.clone();
                if let Some(gateway_config) = gateway_config {
                    let gateway_state = gateway.state.read().await.clone();
                    if let GatewayState::Running { .. } = &gateway_state {
                        let mut dbtx = gateway.gateway_db.begin_transaction_nc().await;
                        let all_federations_configs: Vec<_> = dbtx.find_by_prefix(&FederationIdKeyPrefix).await.map(|(key, config)| (key.id, config)).collect().await;
                        let result = gateway.register_federations(&gateway_config, &all_federations_configs).await;
                        registration_result = Some(result);
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

                let registration_delay: Duration = if let Some(Err(GatewayError::FederationError(_))) = registration_result {
                    // Retry to register gateway with federations in 10 seconds since it failed
                    Duration::from_secs(10)
                } else {
                // Allow a 15% buffer of the TTL before the re-registering gateway
                // with the federations.
                    GW_ANNOUNCEMENT_TTL.mul_f32(0.85)
                };

                sleep(registration_delay).await;
            }
        });
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
        client: &ClientHandleArc,
        federation_id: FederationId,
    ) -> FederationInfo {
        let balance_msat = client.get_balance().await;
        let config = client.get_config().clone();
        let channel_id = self
            .scid_to_federation
            .read()
            .await
            .iter()
            .find_map(|(scid, fid)| {
                if *fid == federation_id {
                    Some(*scid)
                } else {
                    None
                }
            });

        let mut dbtx = self.gateway_db.begin_transaction_nc().await;
        let federation_key = FederationIdKey { id: federation_id };
        let routing_fees = dbtx
            .get_value(&federation_key)
            .await
            .map(|config| config.fees.into());

        FederationInfo {
            federation_id,
            balance_msat,
            config,
            channel_id,
            routing_fees,
        }
    }

    async fn check_federation_network(
        &self,
        info: &FederationInfo,
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

        if bitcoin29_to_bitcoin30_network(ln_cfg.network) != network {
            error!(
                "Federation {} runs on {} but this gateway supports {}",
                info.federation_id, ln_cfg.network, network,
            );
            return Err(GatewayError::UnsupportedNetwork(
                bitcoin29_to_bitcoin30_network(ln_cfg.network),
            ));
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

    /// Iterates through all of the federations the gateway is registered with
    /// and requests to remove the registration record.
    pub async fn leave_all_federations(&self) {
        let mut dbtx = self.gateway_db.begin_transaction_nc().await;
        let keypair = dbtx
            .get_value(&GatewayPublicKey)
            .await
            .expect("Gateway keypair does not exist");
        for (_, client) in self.clients.read().await.iter() {
            client
                .value()
                .get_first_module::<GatewayClientModule>()
                .remove_from_federation(keypair)
                .await;
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

impl Gateway {
    async fn public_key_v2(&self, federation_id: &FederationId) -> Option<PublicKey> {
        self.clients.read().await.get(federation_id).map(|client| {
            client
                .value()
                .get_first_module::<GatewayClientModuleV2>()
                .keypair
                .public_key()
        })
    }

    pub async fn payment_info_v2(&self, federation_id: &FederationId) -> Option<PaymentInfo> {
        Some(PaymentInfo {
            public_key: self.public_key_v2(federation_id).await?,
            payment_fees: self.payment_fees_v2(),
            outgoing_cltv_delta: OUTGOING_CLTV_DELTA_V2,
        })
    }

    pub fn payment_fees_v2(&self) -> PaymentFees {
        PaymentFees {
            // we take a fee of one percent for outgoing contracts
            send: PaymentFee::default(),
            // we take a fee of one percent for incoming contracts
            receive: PaymentFee::default(),
        }
    }

    async fn send_payment_v2(
        &self,
        payload: SendPaymentPayload,
    ) -> std::result::Result<std::result::Result<[u8; 32], Signature>, SendPaymentErrorV2> {
        let clients = self.clients.read().await;

        let client = clients
            .get(&payload.federation_id)
            .ok_or(SendPaymentErrorV2::UnknownFederationId)?
            .value();

        let operation_id = OperationId(payload.contract.contract_id().0.into_inner());

        let module = client.get_first_module::<GatewayClientModuleV2>();

        if client.operation_exists(operation_id).await {
            return Ok(module.subscribe_send(operation_id, payload.contract).await);
        }

        if payload.contract.claim_pk != module.keypair.public_key() {
            return Err(SendPaymentErrorV2::NotOurKey);
        }

        if payload.invoice.consensus_hash::<sha256::Hash>() != payload.contract.invoice_hash {
            return Err(SendPaymentErrorV2::InvalidInvoiceHash);
        }

        let max_delay = module
            .module_api
            .outgoing_contract_expiration(&payload.contract.contract_id())
            .await
            .map_err(|_| SendPaymentErrorV2::FederationUnreachable)?
            .ok_or(SendPaymentErrorV2::UnconfirmedContract)?
            .saturating_sub(OUTGOING_CLTV_DELTA_V2);

        if max_delay == 0 {
            return Err(SendPaymentErrorV2::TimeoutTooClose);
        }

        let invoice_msats = payload
            .invoice
            .amount_milli_satoshis()
            .ok_or(SendPaymentErrorV2::InvoiceMissingAmount)?;

        let min_contract_amount = self.payment_fees_v2().send.add_fee(invoice_msats);

        if payload.contract.amount < min_contract_amount {
            return Err(SendPaymentErrorV2::Underfunded);
        }

        let additional_fee = payload.contract.amount - min_contract_amount;
        let max_ln_fee = additional_fee.msats + (min_contract_amount.msats - invoice_msats) / 2;

        module
            .start_send_state_machine(
                operation_id,
                max_delay,
                max_ln_fee,
                payload.invoice,
                payload.contract.clone(),
            )
            .await
            .ok();

        Ok(module.subscribe_send(operation_id, payload.contract).await)
    }

    async fn create_invoice_v2(
        &self,
        payload: CreateInvoicePayload,
    ) -> std::result::Result<Bolt11Invoice, CreateInvoiceErrorV2> {
        if !payload.contract.verify() {
            return Err(CreateInvoiceErrorV2::InvalidContract);
        }

        let our_pk = self
            .public_key_v2(&payload.federation_id)
            .await
            .ok_or(CreateInvoiceErrorV2::UnknownFederation)?;

        if payload.contract.commitment.refund_pk != our_pk {
            return Err(CreateInvoiceErrorV2::NotOurKey);
        }

        let contract_amount = self
            .payment_fees_v2()
            .receive
            .subtract_fee(payload.invoice_amount.msats);

        if contract_amount != payload.contract.commitment.amount {
            return Err(CreateInvoiceErrorV2::Unbalanced);
        }

        if payload.contract.commitment.expiration <= duration_since_epoch().as_secs() {
            return Err(CreateInvoiceErrorV2::ContractExpired);
        }

        let invoice = self
            .create_invoice_via_lnrpc_v2(
                payload.contract.commitment.payment_hash,
                payload.invoice_amount,
                payload.description.clone(),
                payload.expiry_time,
            )
            .await
            .map_err(CreateInvoiceErrorV2::NodeError)?;

        let mut dbtx = self.gateway_db.begin_transaction().await;

        if dbtx
            .insert_entry(
                &CreateInvoicePayloadKey(payload.contract.commitment.payment_hash.into_inner()),
                &payload,
            )
            .await
            .is_some()
        {
            return Err(CreateInvoiceErrorV2::HashAlreadyRegistered);
        }

        dbtx.commit_tx_result()
            .await
            .map_err(|_| CreateInvoiceErrorV2::HashAlreadyRegistered)?;

        Ok(invoice)
    }

    pub async fn create_invoice_via_lnrpc_v2(
        &self,
        payment_hash: sha256::Hash,
        amount: Amount,
        description: String,
        expiry_time: u32,
    ) -> std::result::Result<Bolt11Invoice, String> {
        let lnrpc = self
            .get_lightning_context()
            .await
            .map_err(|e| e.to_string())?
            .lnrpc;

        let response = lnrpc
            .create_invoice(CreateInvoiceRequest {
                payment_hash: payment_hash.into_inner().to_vec(),
                amount_msat: amount.msats,
                expiry: expiry_time,
                description,
            })
            .await
            .map_err(|e| e.to_string())?;

        Bolt11Invoice::from_str(&response.invoice).map_err(|e| e.to_string())
    }

    pub async fn receive_v2(
        &self,
        payment_hash: [u8; 32],
        amount: Amount,
    ) -> std::result::Result<[u8; 32], ReceiveErrorV2> {
        let operation_id = OperationId(payment_hash);

        let payload = self
            .gateway_db
            .begin_transaction_nc()
            .await
            .get_value(&CreateInvoicePayloadKey(payment_hash))
            .await
            .ok_or(ReceiveErrorV2::UnknownDecryptionContract)?;

        let clients = self.clients.read().await;

        let client = clients
            .get(&payload.federation_id)
            .ok_or(ReceiveErrorV2::UnknownFederationId)?
            .value();

        let module = client.get_first_module::<GatewayClientModuleV2>();

        if client.operation_exists(operation_id).await {
            return module
                .subscribe_receive(operation_id)
                .await
                .ok_or(ReceiveErrorV2::Failure);
        }

        if payload.invoice_amount != amount {
            return Err(ReceiveErrorV2::IncorrectAmount);
        }

        module
            .start_receive_state_machine(operation_id, payload.contract)
            .await
            .map_err(ReceiveErrorV2::FinalizationError)?;

        module
            .subscribe_receive(operation_id)
            .await
            .ok_or(ReceiveErrorV2::Failure)
    }
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

struct PrettyInterceptHtlcRequest<'a>(&'a crate::gateway_lnrpc::InterceptHtlcRequest);

impl Display for PrettyInterceptHtlcRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PrettyInterceptHtlcRequest(htlc_request) = self;
        write!(
            f,
            "InterceptHtlcRequest {{ payment_hash: {}, incoming_amount_msat: {:?}, outgoing_amount_msat: {:?}, incoming_expiry: {:?}, short_channel_id: {:?}, incoming_chan_id: {:?}, htlc_id: {:?} }}",
            htlc_request.payment_hash.encode_hex::<String>(),
            htlc_request.incoming_amount_msat,
            htlc_request.outgoing_amount_msat,
            htlc_request.incoming_expiry,
            htlc_request.short_channel_id,
            htlc_request.incoming_chan_id,
            htlc_request.htlc_id,
        )
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SendPaymentErrorV2 {
    #[error("The federation id is unknown")]
    UnknownFederationId,
    #[error("The outgoing contract has not been confirmed by the federation")]
    UnconfirmedContract,
    #[error("The invoice's hash does not match the commitment in the contract")]
    InvalidInvoiceHash,
    #[error("The outgoing contract keyed to another gateway")]
    NotOurKey,
    #[error("Invoice is missing amount")]
    InvoiceMissingAmount,
    #[error("Outgoing contract is underfunded")]
    Underfunded,
    #[error("The gateway can not reach the federation to confirm contract")]
    FederationUnreachable,
    #[error("The contract's timeout is in the past or does not allow for a safety margin")]
    TimeoutTooClose,
    #[error("The invoice is expired.")]
    InvoiceExpired,
}

#[derive(Error, Debug)]
pub enum ReceiveErrorV2 {
    #[error("The federation id is unknown")]
    UnknownFederationId,
    #[error("There is no corresponding decryption contract available")]
    UnknownDecryptionContract,
    #[error("The available decryption contract's amount does not match the amount in the request")]
    IncorrectAmount,
    #[error("The funding transaction could not be finalized {0}")]
    FinalizationError(anyhow::Error),
    #[error("The internal send failed")]
    Failure,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum CreateInvoiceErrorV2 {
    #[error("The contract is invalid")]
    InvalidContract,
    #[error("The contract is keyed to another gateway")]
    NotOurKey,
    #[error("The gateway is not connected to the Federation")]
    UnknownFederation,
    #[error("A different decryption contract with this hash is already registered")]
    HashAlreadyRegistered,
    #[error("The contract is already expired")]
    ContractExpired,
    #[error("Incoming contract would be underfunded")]
    Unbalanced,
    #[error("The lightning node failed to create an invoice")]
    NodeError(String),
}
