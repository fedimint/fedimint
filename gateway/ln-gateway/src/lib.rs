#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::wildcard_imports)]

pub mod client;
mod db;
pub mod envs;
mod federation_manager;
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

use anyhow::{anyhow, bail};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::{Address, Network, Txid};
use bitcoin_hashes::sha256;
use clap::Parser;
use client::GatewayClientBuilder;
use db::{
    DbKeyPrefix, FederationIdKey, GatewayConfiguration, GatewayConfigurationKey,
    GatewayDatabaseExt, GatewayPublicKey, GATEWAYD_DATABASE_VERSION,
};
use federation_manager::FederationManager;
use fedimint_api_client::api::FederationError;
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::ClientHandleArc;
use fedimint_core::config::FederationId;
use fedimint_core::core::{
    ModuleInstanceId, ModuleKind, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::{
    apply_migrations_server, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::endpoint_constants::REGISTER_GATEWAY_ENDPOINT;
use fedimint_core::fmt_utils::OptStacktrace;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::CommonModuleInit;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{KeyPair, PublicKey, Secp256k1};
use fedimint_core::task::{sleep, TaskGroup, TaskHandle, TaskShutdownToken};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::{SafeUrl, Spanned};
use fedimint_core::{
    fedimint_build_code_version_env, push_db_pair_items, Amount, BitcoinAmountOrAll, BitcoinHash,
};
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_ln_common::config::{GatewayFee, LightningClientConfig};
use fedimint_ln_common::contracts::Preimage;
use fedimint_ln_common::LightningCommonInit;
use fedimint_lnv2_client::{
    Bolt11InvoiceDescription, CreateBolt11InvoicePayload, PaymentFee, RoutingInfo,
    SendPaymentPayload,
};
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_mint_client::{MintClientInit, MintCommonInit};
use fedimint_wallet_client::{
    WalletClientInit, WalletClientModule, WalletCommonInit, WithdrawState,
};
use futures::stream::StreamExt;
use gateway_lnrpc::intercept_htlc_response::{Action, Cancel};
use gateway_lnrpc::{CloseChannelsWithPeerResponse, InterceptHtlcResponse};
use hex::ToHex;
use lightning::{ILnRpcClient, LightningBuilder, LightningMode, LightningRpcError};
use lightning_invoice::{Bolt11Invoice, RoutingFees};
use rand::rngs::OsRng;
use rand::Rng;
use rpc::{
    CloseChannelsWithPeerPayload, FederationInfo, GatewayFedConfig, GatewayInfo, LeaveFedPayload,
    OpenChannelPayload, SetConfigurationPayload, V1_API_ENDPOINT,
};
use state_machine::pay::OutgoingPaymentError;
use state_machine::GatewayClientModule;
use strum::IntoEnumIterator;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, info_span, warn, Instrument};

use crate::db::{get_gatewayd_database_migrations, FederationConfig, FederationIdKeyPrefix};
use crate::gateway_lnrpc::create_invoice_request::Description;
use crate::gateway_lnrpc::intercept_htlc_response::Forward;
use crate::gateway_lnrpc::CreateInvoiceRequest;
use crate::gateway_module_v2::GatewayClientModuleV2;
use crate::lightning::{GatewayLightningBuilder, RouteHtlcStream};
use crate::rpc::rpc_server::{hash_password, run_webserver};
use crate::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, RestorePayload,
    WithdrawPayload,
};
use crate::state_machine::GatewayExtPayStates;

/// How long a gateway announcement stays valid
const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

/// The default number of route hints that the legacy gateway provides for
/// invoice creation.
const DEFAULT_NUM_ROUTE_HINTS: u32 = 1;

/// Default Bitcoin network for testing purposes.
pub const DEFAULT_NETWORK: Network = Network::Regtest;

/// The default routing fees that the gateway charges for incoming and outgoing
/// payments. Identical to the Lightning Network.
pub const DEFAULT_FEES: RoutingFees = RoutingFees {
    // Base routing fee. Default is 0 msat
    base_msat: 0,
    // Liquidity-based routing fee in millionths of a routed amount.
    // In other words, 10000 is 1%. The default is 10000 (1%).
    proportional_millionths: 10000,
};

/// LNv2 CLTV Delta in blocks
const EXPIRATION_DELTA_MINIMUM_V2: u64 = 144;

pub type Result<T> = std::result::Result<T, GatewayError>;

/// Name of the gateway's database that is used for metadata and configuration
/// storage.
const DB_FILE: &str = "gatewayd.db";

/// The non-lightning default module types that the Gateway supports.
const DEFAULT_MODULE_KINDS: [(ModuleInstanceId, &ModuleKind); 2] = [
    (LEGACY_HARDCODED_INSTANCE_ID_MINT, &MintCommonInit::KIND),
    (LEGACY_HARDCODED_INSTANCE_ID_WALLET, &WalletCommonInit::KIND),
];

/// Command line parameters for starting the gateway. `mode`, `data_dir`,
/// `listen`, and `api_addr` are all required.
#[derive(Parser)]
#[command(version)]
struct GatewayOpts {
    #[clap(subcommand)]
    mode: LightningMode,

    /// Path to folder containing gateway config and data files
    #[arg(long = "data-dir", env = envs::FM_GATEWAY_DATA_DIR_ENV)]
    data_dir: PathBuf,

    /// Gateway webserver listen address
    #[arg(long = "listen", env = envs::FM_GATEWAY_LISTEN_ADDR_ENV)]
    listen: SocketAddr,

    /// Public URL from which the webserver API is reachable
    #[arg(long = "api-addr", env = envs::FM_GATEWAY_API_ADDR_ENV)]
    api_addr: SafeUrl,

    /// Gateway webserver authentication password
    #[arg(long = "password", env = envs::FM_GATEWAY_PASSWORD_ENV)]
    password: Option<String>,

    /// Bitcoin network this gateway will be running on
    #[arg(long = "network", env = envs::FM_GATEWAY_NETWORK_ENV)]
    network: Option<Network>,

    /// Configured gateway routing fees
    /// Format: <base_msat>,<proportional_millionths>
    #[arg(long = "fees", env = envs::FM_GATEWAY_FEES_ENV)]
    fees: Option<GatewayFee>,

    /// Number of route hints to return in invoices
    #[arg(
        long = "num-route-hints",
        env = envs::FM_NUMBER_OF_ROUTE_HINTS_ENV,
        default_value_t = DEFAULT_NUM_ROUTE_HINTS
    )]
    num_route_hints: u32,
}

impl GatewayOpts {
    /// Converts the command line parameters into a helper struct the Gateway
    /// uses to store runtime parameters.
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
    /// The gateway's federation manager.
    federation_manager: Arc<RwLock<FederationManager>>,

    /// Builder struct that allows the gateway to build a `ILnRpcClient`, which
    /// represents a connection to a lightning node.
    lightning_builder: Arc<dyn LightningBuilder + Send + Sync>,

    /// The gateway's current configuration
    gateway_config: Arc<RwLock<Option<GatewayConfiguration>>>,

    /// The current state of the Gateway.
    state: Arc<RwLock<GatewayState>>,

    /// Builder struct that allows the gateway to build a Fedimint client, which
    /// handles the communication with a federation.
    client_builder: GatewayClientBuilder,

    /// Database for Gateway metadata.
    gateway_db: Database,

    /// Joining or leaving Federation is protected by this lock to prevent
    /// trying to use same database at the same time from multiple threads.
    /// Could be more granular (per id), but shouldn't matter in practice.
    client_joining_lock: Arc<tokio::sync::Mutex<ClientsJoinLock>>,

    /// A public key representing the identity of the gateway. Private key is
    /// not used.
    gateway_id: PublicKey,

    /// The Gateway's API URL.
    versioned_api: SafeUrl,

    /// The socket the gateway listens on.
    listen: SocketAddr,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("federation_manager", &self.federation_manager)
            .field("gateway_config", &self.gateway_config)
            .field("state", &self.state)
            .field("client_builder", &self.client_builder)
            .field("gateway_db", &self.gateway_db)
            .field("gateway_id", &self.gateway_id)
            .finish_non_exhaustive()
    }
}

impl Gateway {
    /// Creates a new gateway but with a custom module registry provided inside
    /// `client_builder`. Currently only used for testing.
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
        gateway_state: GatewayState,
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
            gateway_state,
        )
        .await
    }

    /// Default function for creating a gateway with the `Mint`, `Wallet`, and
    /// `Gateway` modules.
    pub async fn new_with_default_modules() -> anyhow::Result<Gateway> {
        let opts = GatewayOpts::parse();

        // Gateway module will be attached when the federation clients are created
        // because the LN RPC will be injected with `GatewayClientGen`.
        let mut registry = ClientModuleInitRegistry::new();
        registry.attach(MintClientInit);
        registry.attach(WalletClientInit::default());

        let decoders = registry.available_decoders(DEFAULT_MODULE_KINDS.iter().copied())?;

        let gateway_db = Database::new(
            fedimint_rocksdb::RocksDb::open(opts.data_dir.join(DB_FILE))?,
            decoders,
        );

        let client_builder = GatewayClientBuilder::new(
            opts.data_dir.clone(),
            registry,
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
        );

        info!(
            "Starting gatewayd (version: {})",
            fedimint_build_code_version_env!()
        );

        let gateway_parameters = opts.to_gateway_parameters()?;

        Gateway::new(
            Arc::new(GatewayLightningBuilder {
                lightning_mode: opts.mode,
                gateway_db: gateway_db.clone(),
            }),
            gateway_parameters,
            gateway_db,
            client_builder,
            GatewayState::Initializing,
        )
        .await
    }

    /// Helper function for creating a gateway from either
    /// `new_with_default_modules` or `new_with_custom_registry`.
    async fn new(
        lightning_builder: Arc<dyn LightningBuilder + Send + Sync>,
        gateway_parameters: GatewayParameters,
        gateway_db: Database,
        client_builder: GatewayClientBuilder,
        gateway_state: GatewayState,
    ) -> anyhow::Result<Gateway> {
        // Apply database migrations before using the database to ensure old database
        // structures are readable.
        apply_migrations_server(
            &gateway_db,
            "gatewayd".to_string(),
            GATEWAYD_DATABASE_VERSION,
            get_gatewayd_database_migrations(),
        )
        .await?;

        // Reads the `GatewayConfig` from the database if it exists or is provided from
        // the command line.
        let gateway_config =
            Self::get_gateway_configuration(gateway_db.clone(), &gateway_parameters).await;

        Ok(Self {
            federation_manager: Arc::new(RwLock::new(FederationManager::new())),
            lightning_builder,
            gateway_config: Arc::new(RwLock::new(gateway_config)),
            state: Arc::new(RwLock::new(gateway_state)),
            client_builder,
            gateway_id: Self::load_gateway_id(&gateway_db).await,
            gateway_db,
            client_joining_lock: Arc::new(Mutex::new(ClientsJoinLock)),
            versioned_api: gateway_parameters.versioned_api,
            listen: gateway_parameters.listen,
        })
    }

    /// Returns a `PublicKey` that uniquely identifies the Gateway.
    async fn load_gateway_id(gateway_db: &Database) -> PublicKey {
        let mut dbtx = gateway_db.begin_transaction().await;
        if let Some(key_pair) = dbtx.get_value(&GatewayPublicKey {}).await {
            key_pair.public_key()
        } else {
            let context = Secp256k1::new();
            let (secret, public) = context.generate_keypair(&mut OsRng);
            let key_pair = KeyPair::from_secret_key(&context, &secret);
            dbtx.insert_new_entry(&GatewayPublicKey, &key_pair).await;
            dbtx.commit_tx().await;
            public
        }
    }

    pub fn gateway_id(&self) -> PublicKey {
        self.gateway_id
    }

    pub fn versioned_api(&self) -> &SafeUrl {
        &self.versioned_api
    }

    pub async fn clone_gateway_config(&self) -> Option<GatewayConfiguration> {
        self.gateway_config.read().await.clone()
    }

    pub async fn get_state(&self) -> GatewayState {
        self.state.read().await.clone()
    }

    /// Reads and serializes structures from the Gateway's database for the
    /// purpose for serializing to JSON for inspection.
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

    /// Main entrypoint into the gateway that starts the client registration
    /// timer, loads the federation clients from the persisted config,
    /// begins listening for intercepted HTLCs, and starts the webserver to
    /// service requests.
    pub async fn run(self, tg: &TaskGroup) -> anyhow::Result<TaskShutdownToken> {
        self.register_clients_timer(tg);
        Box::pin(self.load_clients()).await;
        self.start_gateway(tg);
        // start webserver last to avoid handling requests before fully initialized
        run_webserver(Arc::new(self), tg).await?;
        let handle = tg.make_handle();
        let shutdown_receiver = handle.make_shutdown_rx();
        Ok(shutdown_receiver)
    }

    /// Begins the task for listening for intercepted HTLCs from the Lightning
    /// node.
    fn start_gateway(&self, task_group: &TaskGroup) {
        let self_copy = self.clone();
        let tg = task_group.clone();
        task_group.spawn("Subscribe to intercepted HTLCs in stream", |handle| async move {
            loop {
                if handle.is_shutting_down() {
                    info!("Gateway HTLC handler loop is shutting down");
                    break;
                }

                let htlc_task_group = tg.make_subgroup();
                let lnrpc_route = self_copy.lightning_builder.build().await;

                debug!("Will try to intercept HTLC stream...");
                // Re-create the HTLC stream if the connection breaks
                match lnrpc_route
                    .route_htlcs(&htlc_task_group)
                    .await
                {
                    Ok((stream, ln_client)) => {
                        // Successful calls to route_htlcs establish a connection
                        self_copy.set_gateway_state(GatewayState::Connected).await;
                        info!("Established HTLC stream");

                        match ln_client.parsed_node_info().await {
                            Ok((lightning_public_key, lightning_alias, lightning_network, _block_height, _synced_to_chain)) => {
                                let gateway_config = self_copy.clone_gateway_config().await;
                                let gateway_config = if let Some(config) = gateway_config {
                                    config
                                } else {
                                    self_copy.set_gateway_state(GatewayState::Configuring).await;
                                    info!("Waiting for gateway to be configured...");
                                    self_copy.gateway_db
                                        .wait_key_exists(&GatewayConfigurationKey)
                                        .await
                                };

                                if gateway_config.network != lightning_network {
                                    warn!("Lightning node does not match previously configured gateway network : ({:?})", gateway_config.network);
                                    info!("Changing gateway network to match lightning node network : ({:?})", lightning_network);
                                    self_copy.handle_disconnect(htlc_task_group).await;
                                    self_copy.handle_set_configuration_msg(SetConfigurationPayload {
                                        password: None,
                                        network: Some(lightning_network),
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
                                if handle.cancel_on_shutdown(self_copy.handle_htlc_stream(stream, handle.clone())).await.is_ok() {
                                    warn!("HTLC Stream Lightning connection broken. Gateway is disconnected");
                                } else {
                                    info!("Received shutdown signal");
                                    self_copy.handle_disconnect(htlc_task_group).await;
                                    break;
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
    }

    /// Utility function for waiting for the task that is listening for
    /// intercepted HTLCs to shutdown.
    async fn handle_disconnect(&self, htlc_task_group: TaskGroup) {
        self.set_gateway_state(GatewayState::Disconnected).await;
        if let Err(e) = htlc_task_group.shutdown_join_all(None).await {
            error!("HTLC task group shutdown errors: {}", e);
        }
    }

    /// Blocks waiting for intercepted HTLCs to be sent over the `stream`.
    /// Spawns a state machine to either forward, cancel, or complete the
    /// HTLC depending on if the gateway is able to acquire the preimage from
    /// the federation.
    pub async fn handle_htlc_stream(&self, mut stream: RouteHtlcStream<'_>, handle: TaskHandle) {
        let GatewayState::Running { lightning_context } = self.get_state().await else {
            panic!("Gateway isn't in a running state")
        };

        loop {
            let htlc_request = match stream.next().await {
                Some(Ok(htlc_request)) => htlc_request,
                other => {
                    warn!(
                        ?other,
                        "Unexpected response from HTLC stream, exiting from loop..."
                    );
                    break;
                }
            };

            info!(
                "Intercepting HTLC {}",
                PrettyInterceptHtlcRequest(&htlc_request)
            );
            if handle.is_shutting_down() {
                break;
            }

            let payment_hash = bitcoin_hashes::sha256::Hash::from_slice(&htlc_request.payment_hash)
                .expect("32 bytes");

            // If `payment_hash` has been registered as a LNv2 payment, we try to complete
            // the payment by getting the preimage from the federation
            // using the LNv2 protocol. If the `payment_hash` is not registered,
            // this HTLC is either a legacy Lightning payment or the end destination is not
            // a Fedimint.
            if let Ok((contract, client)) = self
                .get_registered_incoming_contract_and_client_v2(
                    payment_hash.to_byte_array(),
                    htlc_request.incoming_amount_msat,
                )
                .await
            {
                if let Err(error) = client
                    .get_first_module::<GatewayClientModuleV2>()
                    .relay_incoming_htlc(
                        payment_hash,
                        htlc_request.incoming_chan_id,
                        htlc_request.htlc_id,
                        contract,
                    )
                    .await
                {
                    error!("Error relaying incoming HTLC: {error:?}");

                    let outcome = InterceptHtlcResponse {
                        action: Some(Action::Cancel(Cancel {
                            reason: "Insufficient Liquidity".to_string(),
                        })),
                        payment_hash: htlc_request.payment_hash,
                        incoming_chan_id: htlc_request.incoming_chan_id,
                        htlc_id: htlc_request.htlc_id,
                    };

                    if let Err(error) = lightning_context.lnrpc.complete_htlc(outcome).await {
                        error!("Error sending HTLC response to lightning node: {error:?}");
                    }
                }

                continue;
            }

            // Check if the HTLC corresponds to a federation supporting legacy Lightning.
            if let Some(short_channel_id) = htlc_request.short_channel_id {
                // Just forward the HTLC if we do not have a federation that
                // corresponds to the short channel id
                if let Some(client) = self
                    .federation_manager
                    .read()
                    .await
                    .get_client_for_scid(short_channel_id)
                {
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
                                    Ok(_) => return Some(ControlFlow::<(), ()>::Continue(())),
                                    Err(e) => {
                                        error!("Got error intercepting HTLC: {e:?}, will retry...");
                                    }
                                }
                            } else {
                                error!("Got no HTLC result");
                            }
                            None
                        })
                        .await;
                    if let Some(ControlFlow::Continue(())) = cf {
                        continue;
                    }
                }
            }

            let outcome = InterceptHtlcResponse {
                action: Some(Action::Forward(Forward {})),
                payment_hash: htlc_request.payment_hash,
                incoming_chan_id: htlc_request.incoming_chan_id,
                htlc_id: htlc_request.htlc_id,
            };

            if let Err(error) = lightning_context.lnrpc.complete_htlc(outcome).await {
                error!("Error sending HTLC response to lightning node: {error:?}");
            }
        }
    }

    /// Helper function for atomically changing the Gateway's internal state.
    async fn set_gateway_state(&self, state: GatewayState) {
        let mut lock = self.state.write().await;
        *lock = state;
    }

    /// Returns information about the Gateway back to the client when requested
    /// via the webserver.
    pub async fn handle_get_info(&self) -> Result<GatewayInfo> {
        let GatewayState::Running { lightning_context } = self.get_state().await else {
            return Ok(GatewayInfo {
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
                block_height: None,
                synced_to_chain: false,
            });
        };

        // `GatewayConfiguration` should always exist in the database when we are in the
        // `Running` state.
        let gateway_config = self
            .clone_gateway_config()
            .await
            .expect("Gateway configuration should be set");

        // Minimize the time we hold a lock on the federation manager.
        // TODO(tvolk131): See if we can make this block into a method on
        // `FederationManager`.
        let (federations, channels) = {
            let federation_manager = self.federation_manager.read().await;

            let dbtx = self.gateway_db.begin_transaction_nc().await;
            let federations = federation_manager
                .federation_info_all_federations(dbtx)
                .await;

            (federations, federation_manager.clone_scid_map())
        };

        let route_hints = lightning_context
            .lnrpc
            .parsed_route_hints(gateway_config.num_route_hints)
            .await;
        let node_info = lightning_context.lnrpc.parsed_node_info().await?;

        Ok(GatewayInfo {
            federations,
            channels: Some(channels),
            version_hash: fedimint_build_code_version_env!().to_string(),
            lightning_pub_key: Some(lightning_context.lightning_public_key.to_string()),
            lightning_alias: Some(lightning_context.lightning_alias.clone()),
            fees: Some(gateway_config.routing_fees),
            route_hints,
            gateway_id: self.gateway_id,
            gateway_state: self.state.read().await.to_string(),
            network: Some(gateway_config.network),
            block_height: Some(node_info.3),
            synced_to_chain: node_info.4,
        })
    }

    /// If the Gateway is connected to the Lightning node, returns the
    /// `ClientConfig` for each federation that the Gateway is connected to.
    pub async fn handle_get_federation_config(
        &self,
        federation_id_or: Option<FederationId>,
    ) -> Result<GatewayFedConfig> {
        if !matches!(self.get_state().await, GatewayState::Running { .. }) {
            return Ok(GatewayFedConfig {
                federations: BTreeMap::new(),
            });
        }

        let federations = if let Some(federation_id) = federation_id_or {
            let mut federations = BTreeMap::new();
            federations.insert(
                federation_id,
                self.federation_manager
                    .read()
                    .await
                    .get_federation_config(federation_id)
                    .await?,
            );
            federations
        } else {
            self.federation_manager
                .read()
                .await
                .get_all_federation_configs()
                .await
        };

        Ok(GatewayFedConfig { federations })
    }

    /// Returns the balance of the requested federation that the Gateway is
    /// connected to.
    pub async fn handle_balance_msg(&self, payload: BalancePayload) -> Result<Amount> {
        // no need for instrument, it is done on api layer
        Ok(self
            .select_client(payload.federation_id)
            .await?
            .value()
            .get_balance()
            .await)
    }

    /// Returns a Bitcoin deposit on-chain address for pegging in Bitcoin for a
    /// specific connected federation.
    pub async fn handle_address_msg(&self, payload: DepositAddressPayload) -> Result<Address> {
        let (_, address, _) = self
            .select_client(payload.federation_id)
            .await?
            .value()
            .get_first_module::<WalletClientModule>()
            .allocate_deposit_address_expert_only()
            .await?;
        Ok(address)
    }

    /// Returns a Bitcoin TXID from a peg-out transaction for a specific
    /// connected federation.
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
                    info!(
                        "Sent {amount} funds to address {}",
                        address.assume_checked()
                    );
                    return Ok(txid);
                }
                WithdrawState::Failed(e) => {
                    return Err(GatewayError::UnexpectedState(e));
                }
                WithdrawState::Created => {}
            }
        }

        Err(GatewayError::UnexpectedState(
            "Ran out of state updates while withdrawing".to_string(),
        ))
    }

    /// Requests the gateway to pay an outgoing LN invoice on behalf of a
    /// Fedimint client. Returns the payment hash's preimage on success.
    async fn handle_pay_invoice_msg(&self, payload: PayInvoicePayload) -> Result<Preimage> {
        if let GatewayState::Running { .. } = self.get_state().await {
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

    /// Handles a connection request to join a new federation. The gateway will
    /// download the federation's client configuration, construct a new
    /// client, registers, the gateway with the federation, and persists the
    /// necessary config to reconstruct the client when restarting the gateway.
    pub async fn handle_connect_federation(
        &self,
        payload: ConnectFedPayload,
    ) -> Result<FederationInfo> {
        let GatewayState::Running { lightning_context } = self.get_state().await else {
            return Err(GatewayError::Disconnected);
        };

        let invite_code = InviteCode::from_str(&payload.invite_code).map_err(|e| {
            GatewayError::InvalidMetadata(format!("Invalid federation member string {e:?}"))
        })?;
        let federation_id = invite_code.federation_id();

        let _join_federation = self.client_joining_lock.lock().await;

        // Check if this federation has already been registered
        if self
            .federation_manager
            .read()
            .await
            .has_federation(federation_id)
        {
            return Err(GatewayError::FederationAlreadyConnected);
        }

        // `GatewayConfiguration` should always exist in the database when we are in the
        // `Running` state.
        let gateway_config = self
            .clone_gateway_config()
            .await
            .expect("Gateway configuration should be set");

        // The gateway deterministically assigns a channel id (u64) to each federation
        // connected.
        let mint_channel_id = self.federation_manager.read().await.pop_next_scid()?;

        let gw_client_cfg = FederationConfig {
            invite_code,
            mint_channel_id,
            timelock_delta: 10,
            fees: gateway_config.routing_fees,
        };

        let client = self
            .client_builder
            .build(gw_client_cfg.clone(), Arc::new(self.clone()))
            .await?;

        // Instead of using `FederationManager::federation_info`, we manually create
        // federation info here because short channel id is not yet persisted.
        let federation_info = FederationInfo {
            federation_id,
            balance_msat: client.get_balance().await,
            config: client.config().await,
            channel_id: Some(mint_channel_id),
            routing_fees: Some(gateway_config.routing_fees.into()),
        };

        Self::check_federation_network(&federation_info, gateway_config.network)?;

        client
            .get_first_module::<GatewayClientModule>()
            .register_with_federation(
                // Route hints will be updated in the background
                Vec::new(),
                GW_ANNOUNCEMENT_TTL,
                gw_client_cfg.fees,
                lightning_context,
            )
            .await?;

        // no need to enter span earlier, because connect-fed has a span
        self.federation_manager.write().await.add_client(
            mint_channel_id,
            Spanned::new(
                info_span!("client", federation_id=%federation_id.clone()),
                async { client },
            )
            .await,
        );

        self.gateway_db
            .save_federation_config(gw_client_cfg)
            .await?;
        debug!("Federation with ID: {federation_id} connected and assigned channel id: {mint_channel_id}");

        Ok(federation_info)
    }

    /// Handle a request to have the Gateway leave a federation. The Gateway
    /// will request the federation to remove the registration record and
    /// the gateway will remove the configuration needed to construct the
    /// federation client.
    pub async fn handle_leave_federation(
        &self,
        payload: LeaveFedPayload,
    ) -> Result<FederationInfo> {
        let _client_joining_lock = self.client_joining_lock.lock().await;
        let mut dbtx = self.gateway_db.begin_transaction().await;

        let federation_info = self
            .federation_manager
            .write()
            .await
            .leave_federation(payload.federation_id, &mut dbtx.to_ref_nc())
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

    /// Handles a request for the gateway to backup a connected federation's
    /// ecash. Not currently supported.
    pub fn handle_backup_msg(
        &self,
        BackupPayload { federation_id: _ }: BackupPayload,
    ) -> Result<()> {
        unimplemented!("Backup is not currently supported");
    }

    /// Handles a request for the gateway to restore a connected federation's
    /// ecash. Not currently supported.
    pub fn handle_restore_msg(
        &self,
        RestorePayload { federation_id: _ }: RestorePayload,
    ) -> Result<()> {
        unimplemented!("Restore is not currently supported");
    }

    /// Handle a request to change a connected federation's configuration or
    /// gateway metadata. If `num_route_hints` is changed, the Gateway
    /// will re-register with all connected federations. If
    /// `per_federation_routing_fees` is changed, the Gateway will only
    /// re-register with the specified federation.
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
        let gw_state = self.get_state().await;
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

        let prev_gateway_config = self.clone_gateway_config().await;
        let new_gateway_config = if let Some(mut prev_config) = prev_gateway_config {
            if let Some(password) = password.as_ref() {
                let hashed_password = hash_password(password, prev_config.password_salt);
                prev_config.hashed_password = hashed_password;
            }

            if let Some(network) = network {
                if !self.federation_manager.read().await.is_empty() {
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
            if let Some(fees) = routing_fees {
                let routing_fees = GatewayFee(fees.into()).0;
                prev_config.routing_fees = routing_fees;
            }

            prev_config
        } else {
            let password = password.ok_or(GatewayError::GatewayConfigurationError(
                "The password field is required when initially configuring the gateway".to_string(),
            ))?;
            let password_salt: [u8; 16] = rand::thread_rng().gen();
            let hashed_password = hash_password(&password, password_salt);

            GatewayConfiguration {
                hashed_password,
                network: lightning_network,
                num_route_hints: DEFAULT_NUM_ROUTE_HINTS,
                routing_fees: DEFAULT_FEES,
                password_salt,
            }
        };
        dbtx.insert_entry(&GatewayConfigurationKey, &new_gateway_config)
            .await;

        let mut register_federations: Vec<(FederationId, FederationConfig)> = Vec::new();
        if let Some(per_federation_routing_fees) = per_federation_routing_fees {
            for (federation_id, routing_fees) in &per_federation_routing_fees {
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

    pub async fn handle_get_funding_address_msg(&self) -> Result<Address> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.get_funding_address().await?;
        Address::from_str(&response.address)
            .map(Address::assume_checked)
            .map_err(|e| GatewayError::LightningResponseParseError(e.into()))
    }

    /// Instructs the Gateway's Lightning node to open a channel to a peer
    /// specified by `pubkey`.
    pub async fn handle_open_channel_msg(
        &self,
        OpenChannelPayload {
            pubkey,
            host,
            channel_size_sats,
            push_amount_sats,
        }: OpenChannelPayload,
    ) -> Result<()> {
        let context = self.get_lightning_context().await?;
        context
            .lnrpc
            .open_channel(pubkey, host, channel_size_sats, push_amount_sats)
            .await?;
        Ok(())
    }

    /// Instructs the Gateway's Lightning node to close all channels with a peer
    /// specified by `pubkey`.
    pub async fn handle_close_channels_with_peer_msg(
        &self,
        CloseChannelsWithPeerPayload { pubkey }: CloseChannelsWithPeerPayload,
    ) -> Result<CloseChannelsWithPeerResponse> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.close_channels_with_peer(pubkey).await?;
        Ok(response)
    }

    /// Returns a list of Lightning network channels from the Gateway's
    /// Lightning node.
    pub async fn handle_list_active_channels_msg(&self) -> Result<Vec<lightning::ChannelInfo>> {
        let context = self.get_lightning_context().await?;
        let channels = context.lnrpc.list_active_channels().await?;
        Ok(channels)
    }

    /// Registers the gateway with each specified federation.
    async fn register_federations(
        &self,
        gateway_config: &GatewayConfiguration,
        federations: &[(FederationId, FederationConfig)],
    ) -> Result<()> {
        if let Ok(lightning_context) = self.get_lightning_context().await {
            let route_hints = lightning_context
                .lnrpc
                .parsed_route_hints(gateway_config.num_route_hints)
                .await;
            if route_hints.is_empty() {
                warn!("Gateway did not retrieve any route hints, may reduce receive success rate.");
            }

            for (federation_id, federation_config) in federations {
                if let Some(client) = self.federation_manager.read().await.client(federation_id) {
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
                            REGISTER_GATEWAY_ENDPOINT,
                            serde_json::Value::Null,
                            anyhow::anyhow!("Error registering federation {federation_id}: {e:?}"),
                        )))?;
                    }
                }
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
        let mut dbtx = gateway_db.begin_transaction_nc().await;

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
        let hashed_password = hash_password(password, password_salt);
        let gateway_config = GatewayConfiguration {
            hashed_password,
            network,
            num_route_hints,
            routing_fees: routing_fees.0,
            password_salt,
        };

        Some(gateway_config)
    }

    /// Retrieves a `ClientHandleArc` from the Gateway's in memory structures
    /// that keep track of available clients, given a `federation_id`.
    pub async fn select_client(
        &self,
        federation_id: FederationId,
    ) -> Result<Spanned<fedimint_client::ClientHandleArc>> {
        self.federation_manager
            .read()
            .await
            .client(&federation_id)
            .cloned()
            .ok_or(GatewayError::InvalidMetadata(format!(
                "No federation with id {federation_id}"
            )))
    }

    /// Reads the connected federation client configs from the Gateway's
    /// database and reconstructs the clients necessary for interacting with
    /// connection federations.
    async fn load_clients(&self) {
        let configs = self.gateway_db.load_federation_configs().await;

        let _join_federation = self.client_joining_lock.lock().await;

        for (_, config) in configs.clone() {
            let federation_id = config.invite_code.federation_id();
            let scid = config.mint_channel_id;

            if let Ok(client) = Box::pin(Spanned::try_new(
                info_span!("client", federation_id  = %federation_id.clone()),
                self.client_builder.build(config, Arc::new(self.clone())),
            ))
            .await
            {
                self.federation_manager
                    .write()
                    .await
                    .add_client(scid, client);
            } else {
                warn!("Failed to load client for federation: {federation_id}");
            }
        }

        if let Some(max_mint_channel_id) = configs.iter().map(|(_, cfg)| cfg.mint_channel_id).max()
        {
            self.federation_manager
                .read()
                .await
                .set_next_scid(max_mint_channel_id + 1);
        }
    }

    /// Legacy mechanism for registering the Gateway with connected federations.
    /// This will spawn a task that will re-register the Gateway with
    /// connected federations every 8.5 mins. Only registers the Gateway if it
    /// has successfully connected to the Lightning node, so that it can
    /// include route hints in the registration.
    fn register_clients_timer(&self, task_group: &TaskGroup) {
        let gateway = self.clone();
        task_group.spawn_cancellable("register clients", async move {
            loop {
                let mut registration_result: Option<Result<()>> = None;
                let gateway_config = gateway.clone_gateway_config().await;
                if let Some(gateway_config) = gateway_config {
                    let gateway_state = gateway.get_state().await;
                    if let GatewayState::Running { .. } = &gateway_state {
                        let all_federations_configs =  gateway.gateway_db.load_federation_configs().await;
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

    /// Verifies that the supplied `network` matches the Bitcoin network in the
    /// connected client's configuration.
    fn check_federation_network(info: &FederationInfo, network: Network) -> Result<()> {
        let cfg = info
            .config
            .modules
            .values()
            .find(|m| LightningCommonInit::KIND == m.kind)
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
        match self.get_state().await {
            GatewayState::Running { lightning_context } => Ok(lightning_context),
            _ => Err(LightningRpcError::FailedToConnect),
        }
    }

    /// Iterates through all of the federations the gateway is registered with
    /// and requests to remove the registration record.
    pub async fn unannounce_from_all_federations(&self) {
        let gateway_keypair = self.gateway_db.get_gateway_keypair().await;

        self.federation_manager
            .read()
            .await
            .unannounce_from_all_federations(gateway_keypair)
            .await;
    }
}

// LNv2 Gateway implementation
impl Gateway {
    /// Retrieves the `PublicKey` of the Gateway module for a given federation
    /// for LNv2. This is NOT the same as the `gateway_id`, it is different
    /// per-connected federation.
    async fn public_key_v2(&self, federation_id: &FederationId) -> Option<PublicKey> {
        self.federation_manager
            .read()
            .await
            .client(federation_id)
            .map(|client| {
                client
                    .value()
                    .get_first_module::<GatewayClientModuleV2>()
                    .keypair
                    .public_key()
            })
    }

    /// Returns payment information that LNv2 clients can use to instruct this
    /// Gateway to pay an invoice or receive a payment.
    pub async fn routing_info_v2(&self, federation_id: &FederationId) -> Option<RoutingInfo> {
        Some(RoutingInfo {
            public_key: self.public_key_v2(federation_id).await?,
            send_fee_default: PaymentFee::one_percent(),
            send_fee_minimum: PaymentFee::half_of_one_percent(),
            receive_fee: PaymentFee::half_of_one_percent(),
            expiration_delta_default: 500,
            expiration_delta_minimum: EXPIRATION_DELTA_MINIMUM_V2,
        })
    }

    pub async fn select_client_v2(
        &self,
        federation_id: FederationId,
    ) -> anyhow::Result<ClientHandleArc> {
        self.federation_manager
            .read()
            .await
            .client(&federation_id)
            .map(|entry| entry.value().clone())
            .ok_or(anyhow!("Federation client not available"))
    }

    /// Instructs this gateway to pay a Lightning network invoice via the LNv2
    /// protocol.
    async fn send_payment_v2(
        &self,
        payload: SendPaymentPayload,
    ) -> anyhow::Result<std::result::Result<[u8; 32], Signature>> {
        self.select_client_v2(payload.federation_id)
            .await?
            .get_first_module::<GatewayClientModuleV2>()
            .send_payment(payload)
            .await
    }

    /// For the LNv2 protocol, this will create an invoice by fetching it from
    /// the connected Lightning node, then save the payment hash so that
    /// incoming HTLCs can be matched as a receive attempt to a specific
    /// federation.
    async fn create_bolt11_invoice_v2(
        &self,
        payload: CreateBolt11InvoicePayload,
    ) -> anyhow::Result<Bolt11Invoice> {
        if !payload.contract.verify() {
            bail!("The contract is invalid")
        }

        let payment_info = self
            .routing_info_v2(&payload.federation_id)
            .await
            .ok_or(anyhow!("Payment Info not available"))?;

        if payload.contract.commitment.refund_pk != payment_info.public_key {
            bail!("The outgoing contract keyed to another gateway");
        }

        if payload.contract.commitment.amount == Amount::ZERO {
            bail!("Zero amount incoming contracts are not supported");
        }

        let contract_amount = payment_info
            .receive_fee
            .subtract_fee(payload.invoice_amount.msats);

        if contract_amount != payload.contract.commitment.amount {
            bail!("The contract amount does not pay the correct amount of fees");
        }

        if payload.contract.commitment.expiration <= duration_since_epoch().as_secs() {
            bail!("The contract has already expired");
        }

        let invoice = self
            .create_invoice_via_lnrpc_v2(
                payload.contract.commitment.payment_hash,
                payload.invoice_amount,
                payload.description.clone(),
                payload.expiry_time,
            )
            .await
            .map_err(|e| anyhow!(e))?;

        self.gateway_db.save_lnv2_incoming_contract(payload).await?;

        Ok(invoice)
    }

    /// Retrieves a BOLT11 invoice from the connected Lightning node with a
    /// specific `payment_hash`.
    pub async fn create_invoice_via_lnrpc_v2(
        &self,
        payment_hash: sha256::Hash,
        amount: Amount,
        description: Bolt11InvoiceDescription,
        expiry_time: u32,
    ) -> std::result::Result<Bolt11Invoice, String> {
        let lnrpc = self
            .get_lightning_context()
            .await
            .map_err(|e| e.to_string())?
            .lnrpc;

        let response = match description {
            Bolt11InvoiceDescription::Direct(description) => lnrpc
                .create_invoice(CreateInvoiceRequest {
                    payment_hash: payment_hash.to_byte_array().to_vec(),
                    amount_msat: amount.msats,
                    expiry_secs: expiry_time,
                    description: Some(Description::Direct(description)),
                })
                .await
                .map_err(|e| e.to_string())?,
            Bolt11InvoiceDescription::Hash(hash) => lnrpc
                .create_invoice(CreateInvoiceRequest {
                    payment_hash: payment_hash.to_byte_array().to_vec(),
                    amount_msat: amount.msats,
                    expiry_secs: expiry_time,
                    description: Some(Description::Hash(hash.to_byte_array().to_vec())),
                })
                .await
                .map_err(|e| e.to_string())?,
        };

        Bolt11Invoice::from_str(&response.invoice).map_err(|e| e.to_string())
    }

    /// Retrieves the persisted `CreateInvoicePayload` from the database
    /// specified by the `payment_hash` and the `ClientHandleArc` specified
    /// by the payload's `federation_id`.
    pub async fn get_registered_incoming_contract_and_client_v2(
        &self,
        payment_hash: [u8; 32],
        amount_msats: u64,
    ) -> anyhow::Result<(IncomingContract, ClientHandleArc)> {
        let registered_incoming_contract = self
            .gateway_db
            .load_lnv2_incoming_contract(payment_hash)
            .await?;

        if registered_incoming_contract.incoming_amount != amount_msats {
            bail!("The available decryption contract's amount is not equal the requested amount")
        }

        let client = self
            .select_client_v2(registered_incoming_contract.federation_id)
            .await?;

        Ok((registered_incoming_contract.contract, client))
    }
}

/// Errors that can occur while processing incoming HTLC's, making outgoing
/// payments, registering with connected federations, or responding to webserver
/// requests.
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Federation error: {}", OptStacktrace(.0))]
    FederationError(#[from] FederationError),
    #[error("Other: {}", OptStacktrace(.0))]
    ClientStateMachineError(#[from] anyhow::Error),
    #[error("Failed to open the database: {}", OptStacktrace(.0))]
    DatabaseError(anyhow::Error),
    #[error("Lightning rpc error: {}", .0)]
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
    #[error("Error parsing response: {}", OptStacktrace(.0))]
    LightningResponseParseError(anyhow::Error),
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

/// Utility struct for formatting an intercepted HTLC. Useful for debugging.
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
