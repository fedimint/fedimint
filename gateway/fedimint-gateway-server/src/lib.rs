#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::large_futures)]
#![allow(clippy::struct_field_names)]

pub mod client;
pub mod config;
pub mod envs;
mod error;
mod events;
mod federation_manager;
mod iroh_server;
pub mod rpc_server;
mod types;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Display;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, anyhow, ensure};
use async_trait::async_trait;
use bitcoin::hashes::sha256;
use bitcoin::{Address, Network, Txid, secp256k1};
use clap::Parser;
use client::GatewayClientBuilder;
pub use config::GatewayParameters;
use config::{DatabaseBackend, GatewayOpts};
use envs::FM_GATEWAY_SKIP_WAIT_FOR_SYNC_ENV;
use error::FederationNotConnected;
use events::ALL_GATEWAY_EVENTS;
use federation_manager::FederationManager;
use fedimint_bip39::{Bip39RootSecretStrategy, Language, Mnemonic};
use fedimint_bitcoind::bitcoincore::BitcoindClient;
use fedimint_bitcoind::{EsploraClient, IBitcoindRpc};
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client::secret::RootSecretStrategy;
use fedimint_client::{Client, ClientHandleArc};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::{Committable, Database, DatabaseTransaction, apply_migrations};
use fedimint_core::envs::is_env_var_set;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::CommonModuleInit;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::rustls::install_crypto_provider;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::task::{TaskGroup, TaskHandle, TaskShutdownToken, sleep};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::backoff_util::fibonacci_max_one_hour;
use fedimint_core::util::{FmtCompact, FmtCompactAnyhow, SafeUrl, Spanned, retry};
use fedimint_core::{
    Amount, BitcoinAmountOrAll, crit, fedimint_build_code_version_env, get_network_for_address,
};
use fedimint_eventlog::{DBTransactionEventLogExt, EventLogId, StructuredPaymentEvents};
use fedimint_gateway_common::{
    BackupPayload, ChainSource, CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse,
    ConnectFedPayload, ConnectorType, CreateInvoiceForOperatorPayload, CreateOfferPayload,
    CreateOfferResponse, DepositAddressPayload, DepositAddressRecheckPayload,
    FederationBalanceInfo, FederationConfig, FederationInfo, GatewayBalances, GatewayFedConfig,
    GatewayInfo, GetInvoiceRequest, GetInvoiceResponse, LeaveFedPayload, LightningInfo,
    LightningMode, ListTransactionsPayload, ListTransactionsResponse, MnemonicResponse,
    OpenChannelRequest, PayInvoiceForOperatorPayload, PayOfferPayload, PayOfferResponse,
    PaymentLogPayload, PaymentLogResponse, PaymentStats, PaymentSummaryPayload,
    PaymentSummaryResponse, ReceiveEcashPayload, ReceiveEcashResponse, RegisteredProtocol,
    SendOnchainRequest, SetFeesPayload, SetMnemonicPayload, SpendEcashPayload, SpendEcashResponse,
    V1_API_ENDPOINT, WithdrawPayload, WithdrawPreviewPayload, WithdrawPreviewResponse,
    WithdrawResponse,
};
use fedimint_gateway_server_db::{GatewayDbtxNcExt as _, get_gatewayd_database_migrations};
pub use fedimint_gateway_ui::IAdminGateway;
use fedimint_gw_client::events::compute_lnv1_stats;
use fedimint_gw_client::pay::{OutgoingPaymentError, OutgoingPaymentErrorType};
use fedimint_gw_client::{
    GatewayClientModule, GatewayExtPayStates, GatewayExtReceiveStates, IGatewayClientV1,
    SwapParameters,
};
use fedimint_gwv2_client::events::compute_lnv2_stats;
use fedimint_gwv2_client::{
    EXPIRATION_DELTA_MINIMUM_V2, FinalReceiveState, GatewayClientModuleV2, IGatewayClientV2,
};
use fedimint_lightning::lnd::GatewayLndClient;
use fedimint_lightning::{
    CreateInvoiceRequest, ILnRpcClient, InterceptPaymentRequest, InterceptPaymentResponse,
    InvoiceDescription, LightningContext, LightningRpcError, PayInvoiceResponse, PaymentAction,
    RouteHtlcStream, ldk,
};
use fedimint_ln_client::pay::PaymentData;
use fedimint_ln_common::LightningCommonInit;
use fedimint_ln_common::config::LightningClientConfig;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{IdentifiableContract, Preimage};
use fedimint_lnv2_common::Bolt11InvoiceDescription;
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::{
    CreateBolt11InvoicePayload, PaymentFee, RoutingInfo, SendPaymentPayload,
};
use fedimint_lnv2_common::lnurl::VerifyResponse;
use fedimint_logging::LOG_GATEWAY;
use fedimint_mint_client::{
    MintClientInit, MintClientModule, SelectNotesWithAtleastAmount, SelectNotesWithExactAmount,
};
use fedimint_wallet_client::{PegOutFees, WalletClientInit, WalletClientModule, WithdrawState};
use futures::stream::StreamExt;
use lightning_invoice::{Bolt11Invoice, RoutingFees};
use rand::rngs::OsRng;
use tokio::sync::RwLock;
use tracing::{debug, info, info_span, warn};

use crate::envs::FM_GATEWAY_MNEMONIC_ENV;
use crate::error::{AdminGatewayError, LNv1Error, LNv2Error, PublicGatewayError};
use crate::events::get_events_for_duration;
use crate::rpc_server::run_webserver;
use crate::types::PrettyInterceptPaymentRequest;

/// How long a gateway announcement stays valid
const GW_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(600);

/// The default number of route hints that the legacy gateway provides for
/// invoice creation.
const DEFAULT_NUM_ROUTE_HINTS: u32 = 1;

/// Default Bitcoin network for testing purposes.
pub const DEFAULT_NETWORK: Network = Network::Regtest;

pub type Result<T> = std::result::Result<T, PublicGatewayError>;
pub type AdminResult<T> = std::result::Result<T, AdminGatewayError>;

/// Name of the gateway's database that is used for metadata and configuration
/// storage.
const DB_FILE: &str = "gatewayd.db";

/// Name of the folder that the gateway uses to store its node database when
/// running in LDK mode.
const LDK_NODE_DB_FOLDER: &str = "ldk_node";

#[cfg_attr(doc, aquamarine::aquamarine)]
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    NotConfigured -- create or recover wallet --> Disconnected
///    Disconnected -- establish lightning connection --> Connected
///    Connected -- load federation clients --> Running
///    Connected -- not synced to chain --> Syncing
///    Syncing -- load federation clients --> Running
///    Running -- disconnected from lightning node --> Disconnected
///    Running -- shutdown initiated --> ShuttingDown
/// ```
#[derive(Clone, Debug)]
pub enum GatewayState {
    NotConfigured {
        // Broadcast channel to alert gateway background threads that the mnemonic has been
        // created/set.
        mnemonic_sender: tokio::sync::broadcast::Sender<()>,
    },
    Disconnected,
    Syncing,
    Connected,
    Running {
        lightning_context: LightningContext,
    },
    ShuttingDown {
        lightning_context: LightningContext,
    },
}

impl Display for GatewayState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GatewayState::NotConfigured { .. } => write!(f, "NotConfigured"),
            GatewayState::Disconnected => write!(f, "Disconnected"),
            GatewayState::Syncing => write!(f, "Syncing"),
            GatewayState::Connected => write!(f, "Connected"),
            GatewayState::Running { .. } => write!(f, "Running"),
            GatewayState::ShuttingDown { .. } => write!(f, "ShuttingDown"),
        }
    }
}

/// Helper struct for storing the registration parameters for LNv1 for each
/// network protocol.
#[derive(Debug, Clone)]
struct Registration {
    /// The url to advertise in the registration that clients can use to connect
    endpoint_url: SafeUrl,

    /// Keypair that was used to register the gateway registration
    keypair: secp256k1::Keypair,
}

impl Registration {
    pub async fn new(db: &Database, endpoint_url: SafeUrl, protocol: RegisteredProtocol) -> Self {
        let keypair = Gateway::load_or_create_gateway_keypair(db, protocol).await;
        Self {
            endpoint_url,
            keypair,
        }
    }
}

/// The action to take after handling a payment stream.
enum ReceivePaymentStreamAction {
    RetryAfterDelay,
    NoRetry,
}

#[derive(Clone)]
pub struct Gateway {
    /// The gateway's federation manager.
    federation_manager: Arc<RwLock<FederationManager>>,

    /// The mode that specifies the lightning connection parameters
    lightning_mode: LightningMode,

    /// The current state of the Gateway.
    state: Arc<RwLock<GatewayState>>,

    /// Builder struct that allows the gateway to build a Fedimint client, which
    /// handles the communication with a federation.
    client_builder: GatewayClientBuilder,

    /// Database for Gateway metadata.
    gateway_db: Database,

    /// The socket the gateway listens on.
    listen: SocketAddr,

    /// The socket the gateway's metrics server listens on.
    metrics_listen: SocketAddr,

    /// The task group for all tasks related to the gateway.
    task_group: TaskGroup,

    /// The bcrypt password hash used to authenticate the gateway.
    /// This is an `Arc` because `bcrypt::HashParts` does not implement `Clone`.
    bcrypt_password_hash: Arc<bcrypt::HashParts>,

    /// The number of route hints to include in LNv1 invoices.
    num_route_hints: u32,

    /// The Bitcoin network that the Lightning network is configured to.
    network: Network,

    /// The source of the Bitcoin blockchain data
    chain_source: ChainSource,

    /// The default routing fees for new federations
    default_routing_fees: PaymentFee,

    /// The default transaction fees for new federations
    default_transaction_fees: PaymentFee,

    /// The secret key for the Iroh `Endpoint`
    iroh_sk: iroh::SecretKey,

    /// The socket that the gateway listens on for the Iroh `Endpoint`
    iroh_listen: Option<SocketAddr>,

    /// Optional DNS server used for discovery of the Iroh `Endpoint`
    iroh_dns: Option<SafeUrl>,

    /// List of additional relays that can be used to establish a connection to
    /// the Iroh `Endpoint`
    iroh_relays: Vec<SafeUrl>,

    /// A map of the network protocols the gateway supports to the data needed
    /// for registering with a federation.
    registrations: BTreeMap<RegisteredProtocol, Registration>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("federation_manager", &self.federation_manager)
            .field("state", &self.state)
            .field("client_builder", &self.client_builder)
            .field("gateway_db", &self.gateway_db)
            .field("listen", &self.listen)
            .field("registrations", &self.registrations)
            .finish_non_exhaustive()
    }
}

/// Internal helper for on-chain withdrawal calculations
struct WithdrawDetails {
    amount: Amount,
    mint_fees: Option<Amount>,
    peg_out_fees: PegOutFees,
}

/// Calculates an estimated max withdrawable amount on-chain
async fn calculate_max_withdrawable(
    client: &ClientHandleArc,
    address: &Address,
) -> AdminResult<WithdrawDetails> {
    let wallet_module = client
        .get_first_module::<WalletClientModule>()
        .map_err(|_| AdminGatewayError::WithdrawError {
            failure_reason: "Withdrawal not yet supported with walletv2 module".to_string(),
        })?;

    let balance = client.get_balance_for_btc().await.map_err(|err| {
        AdminGatewayError::Unexpected(anyhow!(
            "Balance not available: {}",
            err.fmt_compact_anyhow()
        ))
    })?;

    let peg_out_fees = wallet_module
        .get_withdraw_fees(
            address,
            bitcoin::Amount::from_sat(balance.sats_round_down()),
        )
        .await?;

    let max_withdrawable_before_mint_fees = balance
        .checked_sub(peg_out_fees.amount().into())
        .ok_or_else(|| AdminGatewayError::WithdrawError {
            failure_reason: "Insufficient balance to cover peg-out fees".to_string(),
        })?;

    let mint_module = client.get_first_module::<MintClientModule>()?;
    let mint_fees = mint_module.estimate_spend_all_fees().await;

    let max_withdrawable = max_withdrawable_before_mint_fees.saturating_sub(mint_fees);

    Ok(WithdrawDetails {
        amount: max_withdrawable,
        mint_fees: Some(mint_fees),
        peg_out_fees,
    })
}

impl Gateway {
    /// Creates a new gateway but with a custom module registry provided inside
    /// `client_builder`. Currently only used for testing.
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_custom_registry(
        lightning_mode: LightningMode,
        client_builder: GatewayClientBuilder,
        listen: SocketAddr,
        api_addr: SafeUrl,
        bcrypt_password_hash: bcrypt::HashParts,
        network: Network,
        num_route_hints: u32,
        gateway_db: Database,
        gateway_state: GatewayState,
        chain_source: ChainSource,
        iroh_listen: Option<SocketAddr>,
    ) -> anyhow::Result<Gateway> {
        let versioned_api = api_addr
            .join(V1_API_ENDPOINT)
            .expect("Failed to version gateway API address");
        // Default metrics listen to localhost on UI port + 1
        let metrics_listen = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            listen.port() + 1,
        );
        Gateway::new(
            lightning_mode,
            GatewayParameters {
                listen,
                versioned_api: Some(versioned_api),
                bcrypt_password_hash,
                network,
                num_route_hints,
                default_routing_fees: PaymentFee::TRANSACTION_FEE_DEFAULT,
                default_transaction_fees: PaymentFee::TRANSACTION_FEE_DEFAULT,
                iroh_listen,
                iroh_dns: None,
                iroh_relays: vec![],
                skip_setup: true,
                metrics_listen,
            },
            gateway_db,
            client_builder,
            gateway_state,
            chain_source,
        )
        .await
    }

    /// Returns a bitcoind client using the credentials that were passed in from
    /// the environment variables.
    fn get_bitcoind_client(
        opts: &GatewayOpts,
        network: bitcoin::Network,
        gateway_id: &PublicKey,
    ) -> anyhow::Result<(BitcoindClient, ChainSource)> {
        let bitcoind_username = opts
            .bitcoind_username
            .clone()
            .expect("FM_BITCOIND_URL is set but FM_BITCOIND_USERNAME is not");
        let url = opts.bitcoind_url.clone().expect("No bitcoind url set");
        let password = opts
            .bitcoind_password
            .clone()
            .expect("FM_BITCOIND_URL is set but FM_BITCOIND_PASSWORD is not");

        let chain_source = ChainSource::Bitcoind {
            username: bitcoind_username.clone(),
            password: password.clone(),
            server_url: url.clone(),
        };
        let wallet_name = format!("gatewayd-{gateway_id}");
        let client = BitcoindClient::new(&url, bitcoind_username, password, &wallet_name, network)?;
        Ok((client, chain_source))
    }

    /// Default function for creating a gateway with the `Mint`, `Wallet`, and
    /// `Gateway` modules.
    pub async fn new_with_default_modules(
        mnemonic_sender: tokio::sync::broadcast::Sender<()>,
    ) -> anyhow::Result<Gateway> {
        let opts = GatewayOpts::parse();
        let gateway_parameters = opts.to_gateway_parameters()?;
        let decoders = ModuleDecoderRegistry::default();

        let db_path = opts.data_dir.join(DB_FILE);
        let gateway_db = match opts.db_backend {
            DatabaseBackend::RocksDb => {
                debug!(target: LOG_GATEWAY, "Using RocksDB database backend");
                Database::new(
                    fedimint_rocksdb::RocksDb::build(db_path).open().await?,
                    decoders,
                )
            }
            DatabaseBackend::CursedRedb => {
                debug!(target: LOG_GATEWAY, "Using CursedRedb database backend");
                Database::new(
                    fedimint_cursed_redb::MemAndRedb::new(db_path).await?,
                    decoders,
                )
            }
        };

        // Apply database migrations before using the database to ensure old database
        // structures are readable.
        apply_migrations(
            &gateway_db,
            (),
            "gatewayd".to_string(),
            get_gatewayd_database_migrations(),
            None,
            None,
        )
        .await?;

        // For legacy reasons, we use the http id for the unique identifier of the
        // bitcoind watch-only wallet
        let http_id = Self::load_or_create_gateway_keypair(&gateway_db, RegisteredProtocol::Http)
            .await
            .public_key();
        let (dyn_bitcoin_rpc, chain_source) =
            match (opts.bitcoind_url.as_ref(), opts.esplora_url.as_ref()) {
                (Some(_), None) => {
                    let (client, chain_source) =
                        Self::get_bitcoind_client(&opts, gateway_parameters.network, &http_id)?;
                    (client.into_dyn(), chain_source)
                }
                (None, Some(url)) => {
                    let client = EsploraClient::new(url)
                        .expect("Could not create EsploraClient")
                        .into_dyn();
                    let chain_source = ChainSource::Esplora {
                        server_url: url.clone(),
                    };
                    (client, chain_source)
                }
                (Some(_), Some(_)) => {
                    // Use bitcoind by default if both are set
                    let (client, chain_source) =
                        Self::get_bitcoind_client(&opts, gateway_parameters.network, &http_id)?;
                    (client.into_dyn(), chain_source)
                }
                _ => unreachable!("ArgGroup already enforced XOR relation"),
            };

        // Gateway module will be attached when the federation clients are created
        // because the LN RPC will be injected with `GatewayClientGen`.
        let mut registry = ClientModuleInitRegistry::new();
        registry.attach(MintClientInit);
        registry.attach(WalletClientInit::new(dyn_bitcoin_rpc));
        registry.attach(fedimint_walletv2_client::WalletClientInit);

        let client_builder =
            GatewayClientBuilder::new(opts.data_dir.clone(), registry, opts.db_backend).await?;

        let gateway_state = if Self::load_mnemonic(&gateway_db).await.is_some() {
            GatewayState::Disconnected
        } else {
            // Generate a mnemonic or use one from an environment variable if `skip_setup`
            // is true
            if gateway_parameters.skip_setup {
                let mnemonic = if let Ok(words) = std::env::var(FM_GATEWAY_MNEMONIC_ENV) {
                    info!(target: LOG_GATEWAY, "Using provided mnemonic from environment variable");
                    Mnemonic::parse_in_normalized(Language::English, words.as_str()).map_err(
                        |e| {
                            AdminGatewayError::MnemonicError(anyhow!(format!(
                                "Seed phrase provided in environment was invalid {e:?}"
                            )))
                        },
                    )?
                } else {
                    debug!(target: LOG_GATEWAY, "Generating mnemonic and writing entropy to client storage");
                    Bip39RootSecretStrategy::<12>::random(&mut OsRng)
                };

                Client::store_encodable_client_secret(&gateway_db, mnemonic.to_entropy())
                    .await
                    .map_err(AdminGatewayError::MnemonicError)?;
                GatewayState::Disconnected
            } else {
                GatewayState::NotConfigured { mnemonic_sender }
            }
        };

        info!(
            target: LOG_GATEWAY,
            version = %fedimint_build_code_version_env!(),
            "Starting gatewayd",
        );

        Gateway::new(
            opts.mode,
            gateway_parameters,
            gateway_db,
            client_builder,
            gateway_state,
            chain_source,
        )
        .await
    }

    /// Helper function for creating a gateway from either
    /// `new_with_default_modules` or `new_with_custom_registry`.
    async fn new(
        lightning_mode: LightningMode,
        gateway_parameters: GatewayParameters,
        gateway_db: Database,
        client_builder: GatewayClientBuilder,
        gateway_state: GatewayState,
        chain_source: ChainSource,
    ) -> anyhow::Result<Gateway> {
        let num_route_hints = gateway_parameters.num_route_hints;
        let network = gateway_parameters.network;

        let task_group = TaskGroup::new();
        task_group.install_kill_handler();

        let mut registrations = BTreeMap::new();
        if let Some(http_url) = gateway_parameters.versioned_api {
            registrations.insert(
                RegisteredProtocol::Http,
                Registration::new(&gateway_db, http_url, RegisteredProtocol::Http).await,
            );
        }

        let iroh_sk = Self::load_or_create_iroh_key(&gateway_db).await;
        if gateway_parameters.iroh_listen.is_some() {
            let endpoint_url = SafeUrl::parse(&format!("iroh://{}", iroh_sk.public()))?;
            registrations.insert(
                RegisteredProtocol::Iroh,
                Registration::new(&gateway_db, endpoint_url, RegisteredProtocol::Iroh).await,
            );
        }

        Ok(Self {
            federation_manager: Arc::new(RwLock::new(FederationManager::new())),
            lightning_mode,
            state: Arc::new(RwLock::new(gateway_state)),
            client_builder,
            gateway_db: gateway_db.clone(),
            listen: gateway_parameters.listen,
            metrics_listen: gateway_parameters.metrics_listen,
            task_group,
            bcrypt_password_hash: Arc::new(gateway_parameters.bcrypt_password_hash),
            num_route_hints,
            network,
            chain_source,
            default_routing_fees: gateway_parameters.default_routing_fees,
            default_transaction_fees: gateway_parameters.default_transaction_fees,
            iroh_sk,
            iroh_dns: gateway_parameters.iroh_dns,
            iroh_relays: gateway_parameters.iroh_relays,
            iroh_listen: gateway_parameters.iroh_listen,
            registrations,
        })
    }

    async fn load_or_create_gateway_keypair(
        gateway_db: &Database,
        protocol: RegisteredProtocol,
    ) -> secp256k1::Keypair {
        let mut dbtx = gateway_db.begin_transaction().await;
        let keypair = dbtx.load_or_create_gateway_keypair(protocol).await;
        dbtx.commit_tx().await;
        keypair
    }

    /// Returns `iroh::SecretKey` and saves it to the database if it does not
    /// exist
    async fn load_or_create_iroh_key(gateway_db: &Database) -> iroh::SecretKey {
        let mut dbtx = gateway_db.begin_transaction().await;
        let iroh_sk = dbtx.load_or_create_iroh_key().await;
        dbtx.commit_tx().await;
        iroh_sk
    }

    pub async fn http_gateway_id(&self) -> PublicKey {
        Self::load_or_create_gateway_keypair(&self.gateway_db, RegisteredProtocol::Http)
            .await
            .public_key()
    }

    async fn get_state(&self) -> GatewayState {
        self.state.read().await.clone()
    }

    /// Reads and serializes structures from the Gateway's database for the
    /// purpose for serializing to JSON for inspection.
    pub async fn dump_database(
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> {
        dbtx.dump_database(prefix_names).await
    }

    /// Main entrypoint into the gateway that starts the client registration
    /// timer, loads the federation clients from the persisted config,
    /// begins listening for intercepted payments, and starts the webserver
    /// to service requests.
    pub async fn run(
        self,
        runtime: Arc<tokio::runtime::Runtime>,
        mnemonic_receiver: tokio::sync::broadcast::Receiver<()>,
    ) -> anyhow::Result<TaskShutdownToken> {
        install_crypto_provider().await;
        self.register_clients_timer();
        self.load_clients().await?;
        self.start_gateway(runtime, mnemonic_receiver.resubscribe());
        self.spawn_backup_task();
        // start metrics server
        fedimint_metrics::spawn_api_server(self.metrics_listen, self.task_group.clone()).await?;
        // start webserver last to avoid handling requests before fully initialized
        let handle = self.task_group.make_handle();
        run_webserver(Arc::new(self), mnemonic_receiver.resubscribe()).await?;
        let shutdown_receiver = handle.make_shutdown_rx();
        Ok(shutdown_receiver)
    }

    /// Spawns a background task that checks every `BACKUP_UPDATE_INTERVAL` to
    /// see if any federations need to be backed up.
    fn spawn_backup_task(&self) {
        let self_copy = self.clone();
        self.task_group
            .spawn_cancellable_silent("backup ecash", async move {
                const BACKUP_UPDATE_INTERVAL: Duration = Duration::from_secs(60 * 60);
                let mut interval = tokio::time::interval(BACKUP_UPDATE_INTERVAL);
                interval.tick().await;
                loop {
                    {
                        let mut dbtx = self_copy.gateway_db.begin_transaction().await;
                        self_copy.backup_all_federations(&mut dbtx).await;
                        dbtx.commit_tx().await;
                        interval.tick().await;
                    }
                }
            });
    }

    /// Loops through all federations and checks their last save backup time. If
    /// the last saved backup time is past the threshold time, backup the
    /// federation.
    pub async fn backup_all_federations(&self, dbtx: &mut DatabaseTransaction<'_, Committable>) {
        /// How long the federation manager should wait to backup the ecash for
        /// each federation
        const BACKUP_THRESHOLD_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

        let now = fedimint_core::time::now();
        let threshold = now
            .checked_sub(BACKUP_THRESHOLD_DURATION)
            .expect("Cannot be negative");
        for (id, last_backup) in dbtx.load_backup_records().await {
            match last_backup {
                Some(backup_time) if backup_time < threshold => {
                    let fed_manager = self.federation_manager.read().await;
                    fed_manager.backup_federation(&id, dbtx, now).await;
                }
                None => {
                    let fed_manager = self.federation_manager.read().await;
                    fed_manager.backup_federation(&id, dbtx, now).await;
                }
                _ => {}
            }
        }
    }

    /// Begins the task for listening for intercepted payments from the
    /// lightning node.
    fn start_gateway(
        &self,
        runtime: Arc<tokio::runtime::Runtime>,
        mut mnemonic_receiver: tokio::sync::broadcast::Receiver<()>,
    ) {
        const PAYMENT_STREAM_RETRY_SECONDS: u64 = 60;

        let self_copy = self.clone();
        let tg = self.task_group.clone();
        self.task_group.spawn(
            "Subscribe to intercepted lightning payments in stream",
            |handle| async move {
                // Repeatedly attempt to establish a connection to the lightning node and create a payment stream, re-trying if the connection is broken.
                loop {
                    if handle.is_shutting_down() {
                        info!(target: LOG_GATEWAY, "Gateway lightning payment stream handler loop is shutting down");
                        break;
                    }

                    if let GatewayState::NotConfigured{ .. } = self_copy.get_state().await {
                        info!(target: LOG_GATEWAY, "Waiting for the mnemonic to be set before starting lightning receive loop.");
                        let _ = mnemonic_receiver.recv().await;
                    }

                    let payment_stream_task_group = tg.make_subgroup();
                    let lnrpc_route = self_copy.create_lightning_client(runtime.clone()).await;

                    debug!(target: LOG_GATEWAY, "Establishing lightning payment stream...");
                    let (stream, ln_client) = match lnrpc_route.route_htlcs(&payment_stream_task_group).await
                    {
                        Ok((stream, ln_client)) => (stream, ln_client),
                        Err(err) => {
                            warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Failed to open lightning payment stream");
                            sleep(Duration::from_secs(PAYMENT_STREAM_RETRY_SECONDS)).await;
                            continue
                        }
                    };

                    // Successful calls to `route_htlcs` establish a connection
                    self_copy.set_gateway_state(GatewayState::Connected).await;
                    info!(target: LOG_GATEWAY, "Established lightning payment stream");

                    let route_payments_response =
                        self_copy.route_lightning_payments(&handle, stream, ln_client).await;

                    self_copy.set_gateway_state(GatewayState::Disconnected).await;
                    if let Err(err) = payment_stream_task_group.shutdown_join_all(None).await {
                        crit!(target: LOG_GATEWAY, err = %err.fmt_compact_anyhow(), "Lightning payment stream task group shutdown");
                    }

                    self_copy.unannounce_from_all_federations().await;

                    match route_payments_response {
                        ReceivePaymentStreamAction::RetryAfterDelay => {
                            warn!(target: LOG_GATEWAY, retry_interval = %PAYMENT_STREAM_RETRY_SECONDS, "Disconnected from lightning node");
                            sleep(Duration::from_secs(PAYMENT_STREAM_RETRY_SECONDS)).await;
                        }
                        ReceivePaymentStreamAction::NoRetry => break,
                    }
                }
            },
        );
    }

    /// Handles a stream of incoming payments from the lightning node after
    /// ensuring the gateway is properly configured. Awaits until the stream
    /// is closed, then returns with the appropriate action to take.
    async fn route_lightning_payments<'a>(
        &'a self,
        handle: &TaskHandle,
        mut stream: RouteHtlcStream<'a>,
        ln_client: Arc<dyn ILnRpcClient>,
    ) -> ReceivePaymentStreamAction {
        let LightningInfo::Connected {
            public_key: lightning_public_key,
            alias: lightning_alias,
            network: lightning_network,
            block_height: _,
            synced_to_chain,
        } = ln_client.parsed_node_info().await
        else {
            warn!(target: LOG_GATEWAY, "Failed to retrieve Lightning info");
            return ReceivePaymentStreamAction::RetryAfterDelay;
        };

        assert!(
            self.network == lightning_network,
            "Lightning node network does not match Gateway's network. LN: {lightning_network} Gateway: {}",
            self.network
        );

        if synced_to_chain || is_env_var_set(FM_GATEWAY_SKIP_WAIT_FOR_SYNC_ENV) {
            info!(target: LOG_GATEWAY, "Gateway is already synced to chain");
        } else {
            self.set_gateway_state(GatewayState::Syncing).await;
            info!(target: LOG_GATEWAY, "Waiting for chain sync");
            if let Err(err) = ln_client.wait_for_chain_sync().await {
                warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Failed to wait for chain sync");
                return ReceivePaymentStreamAction::RetryAfterDelay;
            }
        }

        let lightning_context = LightningContext {
            lnrpc: ln_client,
            lightning_public_key,
            lightning_alias,
            lightning_network,
        };
        self.set_gateway_state(GatewayState::Running { lightning_context })
            .await;
        info!(target: LOG_GATEWAY, "Gateway is running");

        if matches!(self.lightning_mode, LightningMode::Lnd { .. }) {
            // Re-register the gateway with all federations after connecting to the
            // lightning node
            let mut dbtx = self.gateway_db.begin_transaction_nc().await;
            let all_federations_configs =
                dbtx.load_federation_configs().await.into_iter().collect();
            self.register_federations(&all_federations_configs, &self.task_group)
                .await;
        }

        // Runs until the connection to the lightning node breaks or we receive the
        // shutdown signal.
        if handle
            .cancel_on_shutdown(async move {
                loop {
                    let payment_request_or = tokio::select! {
                        payment_request_or = stream.next() => {
                            payment_request_or
                        }
                        () = self.is_shutting_down_safely() => {
                            break;
                        }
                    };

                    let Some(payment_request) = payment_request_or else {
                        warn!(
                            target: LOG_GATEWAY,
                            "Unexpected response from incoming lightning payment stream. Shutting down payment processor"
                        );
                        break;
                    };

                    let state_guard = self.state.read().await;
                    if let GatewayState::Running { ref lightning_context } = *state_guard {
                        self.handle_lightning_payment(payment_request, lightning_context).await;
                    } else {
                        warn!(
                            target: LOG_GATEWAY,
                            state = %state_guard,
                            "Gateway isn't in a running state, cannot handle incoming payments."
                        );
                        break;
                    }
                }
            })
            .await
            .is_ok()
        {
            warn!(target: LOG_GATEWAY, "Lightning payment stream connection broken. Gateway is disconnected");
            ReceivePaymentStreamAction::RetryAfterDelay
        } else {
            info!(target: LOG_GATEWAY, "Received shutdown signal");
            ReceivePaymentStreamAction::NoRetry
        }
    }

    /// Polls the Gateway's state waiting for it to shutdown so the thread
    /// processing payment requests can exit.
    async fn is_shutting_down_safely(&self) {
        loop {
            if let GatewayState::ShuttingDown { .. } = self.get_state().await {
                return;
            }

            fedimint_core::task::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Handles an intercepted lightning payment. If the payment is part of an
    /// incoming payment to a federation, spawns a state machine and hands the
    /// payment off to it. Otherwise, forwards the payment to the next hop like
    /// a normal lightning node.
    async fn handle_lightning_payment(
        &self,
        payment_request: InterceptPaymentRequest,
        lightning_context: &LightningContext,
    ) {
        info!(
            target: LOG_GATEWAY,
            lightning_payment = %PrettyInterceptPaymentRequest(&payment_request),
            "Intercepting lightning payment",
        );

        if self
            .try_handle_lightning_payment_lnv2(&payment_request, lightning_context)
            .await
            .is_ok()
        {
            return;
        }

        if self
            .try_handle_lightning_payment_ln_legacy(&payment_request)
            .await
            .is_ok()
        {
            return;
        }

        Self::forward_lightning_payment(payment_request, lightning_context).await;
    }

    /// Tries to handle a lightning payment using the LNv2 protocol.
    /// Returns `Ok` if the payment was handled, `Err` otherwise.
    async fn try_handle_lightning_payment_lnv2(
        &self,
        htlc_request: &InterceptPaymentRequest,
        lightning_context: &LightningContext,
    ) -> Result<()> {
        // If `payment_hash` has been registered as a LNv2 payment, we try to complete
        // the payment by getting the preimage from the federation
        // using the LNv2 protocol. If the `payment_hash` is not registered,
        // this payment is either a legacy Lightning payment or the end destination is
        // not a Fedimint.
        let (contract, client) = self
            .get_registered_incoming_contract_and_client_v2(
                PaymentImage::Hash(htlc_request.payment_hash),
                htlc_request.amount_msat,
            )
            .await?;

        if let Err(err) = client
            .get_first_module::<GatewayClientModuleV2>()
            .expect("Must have client module")
            .relay_incoming_htlc(
                htlc_request.payment_hash,
                htlc_request.incoming_chan_id,
                htlc_request.htlc_id,
                contract,
                htlc_request.amount_msat,
            )
            .await
        {
            warn!(target: LOG_GATEWAY, err = %err.fmt_compact_anyhow(), "Error relaying incoming lightning payment");

            let outcome = InterceptPaymentResponse {
                action: PaymentAction::Cancel,
                payment_hash: htlc_request.payment_hash,
                incoming_chan_id: htlc_request.incoming_chan_id,
                htlc_id: htlc_request.htlc_id,
            };

            if let Err(err) = lightning_context.lnrpc.complete_htlc(outcome).await {
                warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Error sending HTLC response to lightning node");
            }
        }

        Ok(())
    }

    /// Tries to handle a lightning payment using the legacy lightning protocol.
    /// Returns `Ok` if the payment was handled, `Err` otherwise.
    async fn try_handle_lightning_payment_ln_legacy(
        &self,
        htlc_request: &InterceptPaymentRequest,
    ) -> Result<()> {
        // Check if the payment corresponds to a federation supporting legacy Lightning.
        let Some(federation_index) = htlc_request.short_channel_id else {
            return Err(PublicGatewayError::LNv1(LNv1Error::IncomingPayment(
                "Incoming payment has not last hop short channel id".to_string(),
            )));
        };

        let Some(client) = self
            .federation_manager
            .read()
            .await
            .get_client_for_index(federation_index)
        else {
            return Err(PublicGatewayError::LNv1(LNv1Error::IncomingPayment("Incoming payment has a last hop short channel id that does not map to a known federation".to_string())));
        };

        client
            .borrow()
            .with(|client| async {
                let htlc = htlc_request.clone().try_into();
                match htlc {
                    Ok(htlc) => {
                        let lnv1 =
                            client
                                .get_first_module::<GatewayClientModule>()
                                .map_err(|_| {
                                    PublicGatewayError::LNv1(LNv1Error::IncomingPayment(
                                        "Federation does not have LNv1 module".to_string(),
                                    ))
                                })?;
                        match lnv1.gateway_handle_intercepted_htlc(htlc).await {
                            Ok(_) => Ok(()),
                            Err(e) => Err(PublicGatewayError::LNv1(LNv1Error::IncomingPayment(
                                format!("Error intercepting lightning payment {e:?}"),
                            ))),
                        }
                    }
                    _ => Err(PublicGatewayError::LNv1(LNv1Error::IncomingPayment(
                        "Could not convert InterceptHtlcResult into an HTLC".to_string(),
                    ))),
                }
            })
            .await
    }

    /// Forwards a lightning payment to the next hop like a normal lightning
    /// node. Only necessary for LNv1, since LNv2 uses hold invoices instead
    /// of HTLC interception for routing incoming payments.
    async fn forward_lightning_payment(
        htlc_request: InterceptPaymentRequest,
        lightning_context: &LightningContext,
    ) {
        let outcome = InterceptPaymentResponse {
            action: PaymentAction::Forward,
            payment_hash: htlc_request.payment_hash,
            incoming_chan_id: htlc_request.incoming_chan_id,
            htlc_id: htlc_request.htlc_id,
        };

        if let Err(err) = lightning_context.lnrpc.complete_htlc(outcome).await {
            warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Error sending lightning payment response to lightning node");
        }
    }

    /// Helper function for atomically changing the Gateway's internal state.
    async fn set_gateway_state(&self, state: GatewayState) {
        let mut lock = self.state.write().await;
        *lock = state;
    }

    /// If the Gateway is connected to the Lightning node, returns the
    /// `ClientConfig` for each federation that the Gateway is connected to.
    pub async fn handle_get_federation_config(
        &self,
        federation_id_or: Option<FederationId>,
    ) -> AdminResult<GatewayFedConfig> {
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

    /// Returns a Bitcoin deposit on-chain address for pegging in Bitcoin for a
    /// specific connected federation.
    pub async fn handle_address_msg(&self, payload: DepositAddressPayload) -> AdminResult<Address> {
        let client = self.select_client(payload.federation_id).await?;

        if let Ok(wallet_module) = client.value().get_first_module::<WalletClientModule>() {
            let (_, address, _) = wallet_module
                .allocate_deposit_address_expert_only(())
                .await?;
            return Ok(address);
        }

        if let Ok(wallet_module) = client
            .value()
            .get_first_module::<fedimint_walletv2_client::WalletClientModule>()
        {
            return Ok(wallet_module.receive().await);
        }

        Err(AdminGatewayError::Unexpected(anyhow!(
            "No wallet module found"
        )))
    }

    /// Requests the gateway to pay an outgoing LN invoice on behalf of a
    /// Fedimint client. Returns the payment hash's preimage on success.
    async fn handle_pay_invoice_msg(
        &self,
        payload: fedimint_ln_client::pay::PayInvoicePayload,
    ) -> Result<Preimage> {
        let GatewayState::Running { .. } = self.get_state().await else {
            return Err(PublicGatewayError::Lightning(
                LightningRpcError::FailedToConnect,
            ));
        };

        debug!(target: LOG_GATEWAY, "Handling pay invoice message");
        let client = self.select_client(payload.federation_id).await?;
        let contract_id = payload.contract_id;
        let gateway_module = &client
            .value()
            .get_first_module::<GatewayClientModule>()
            .map_err(LNv1Error::OutgoingPayment)
            .map_err(PublicGatewayError::LNv1)?;
        let operation_id = gateway_module
            .gateway_pay_bolt11_invoice(payload)
            .await
            .map_err(LNv1Error::OutgoingPayment)
            .map_err(PublicGatewayError::LNv1)?;
        let mut updates = gateway_module
            .gateway_subscribe_ln_pay(operation_id)
            .await
            .map_err(LNv1Error::OutgoingPayment)
            .map_err(PublicGatewayError::LNv1)?
            .into_stream();
        while let Some(update) = updates.next().await {
            match update {
                GatewayExtPayStates::Success { preimage, .. } => {
                    debug!(target: LOG_GATEWAY, contract_id = %contract_id, "Successfully paid invoice");
                    return Ok(preimage);
                }
                GatewayExtPayStates::Fail {
                    error,
                    error_message,
                } => {
                    return Err(PublicGatewayError::LNv1(LNv1Error::OutgoingContract {
                        error: Box::new(error),
                        message: format!(
                            "{error_message} while paying invoice with contract id {contract_id}"
                        ),
                    }));
                }
                GatewayExtPayStates::Canceled { error } => {
                    return Err(PublicGatewayError::LNv1(LNv1Error::OutgoingContract {
                        error: Box::new(error.clone()),
                        message: format!(
                            "Cancelled with {error} while paying invoice with contract id {contract_id}"
                        ),
                    }));
                }
                GatewayExtPayStates::Created => {
                    debug!(target: LOG_GATEWAY, contract_id = %contract_id, "Start pay invoice state machine");
                }
                other => {
                    debug!(target: LOG_GATEWAY, state = ?other, contract_id = %contract_id, "Got state while paying invoice");
                }
            }
        }

        Err(PublicGatewayError::LNv1(LNv1Error::OutgoingPayment(
            anyhow!("Ran out of state updates while paying invoice"),
        )))
    }

    /// Handles a request for the gateway to backup a connected federation's
    /// ecash.
    pub async fn handle_backup_msg(
        &self,
        BackupPayload { federation_id }: BackupPayload,
    ) -> AdminResult<()> {
        let federation_manager = self.federation_manager.read().await;
        let client = federation_manager
            .client(&federation_id)
            .ok_or(AdminGatewayError::ClientCreationError(anyhow::anyhow!(
                format!("Gateway has not connected to {federation_id}")
            )))?
            .value();
        let metadata: BTreeMap<String, String> = BTreeMap::new();
        client
            .backup_to_federation(fedimint_client::backup::Metadata::from_json_serialized(
                metadata,
            ))
            .await?;
        Ok(())
    }

    /// Trigger rechecking for deposits on an address
    pub async fn handle_recheck_address_msg(
        &self,
        payload: DepositAddressRecheckPayload,
    ) -> AdminResult<()> {
        let client = self.select_client(payload.federation_id).await?;

        if let Ok(wallet_module) = client.value().get_first_module::<WalletClientModule>() {
            wallet_module
                .recheck_pegin_address_by_address(payload.address)
                .await?;
            return Ok(());
        }

        // Walletv2 auto-claims deposits, so this is a no-op
        if client
            .value()
            .get_first_module::<fedimint_walletv2_client::WalletClientModule>()
            .is_ok()
        {
            return Ok(());
        }

        Err(AdminGatewayError::Unexpected(anyhow!(
            "No wallet module found"
        )))
    }

    /// Handles a request to receive ecash into the gateway.
    pub async fn handle_receive_ecash_msg(
        &self,
        payload: ReceiveEcashPayload,
    ) -> Result<ReceiveEcashResponse> {
        let amount = payload.notes.total_amount();
        let client = self
            .federation_manager
            .read()
            .await
            .get_client_for_federation_id_prefix(payload.notes.federation_id_prefix())
            .ok_or(FederationNotConnected {
                federation_id_prefix: payload.notes.federation_id_prefix(),
            })?;
        let mint = client
            .value()
            .get_first_module::<MintClientModule>()
            .map_err(|e| PublicGatewayError::ReceiveEcashError {
                failure_reason: format!("Mint module does not exist: {e:?}"),
            })?;

        let operation_id = mint
            .reissue_external_notes(payload.notes, ())
            .await
            .map_err(|e| PublicGatewayError::ReceiveEcashError {
                failure_reason: e.to_string(),
            })?;
        if payload.wait {
            let mut updates = mint
                .subscribe_reissue_external_notes(operation_id)
                .await
                .unwrap()
                .into_stream();

            while let Some(update) = updates.next().await {
                if let fedimint_mint_client::ReissueExternalNotesState::Failed(e) = update {
                    return Err(PublicGatewayError::ReceiveEcashError {
                        failure_reason: e.to_string(),
                    });
                }
            }
        }

        Ok(ReceiveEcashResponse { amount })
    }

    /// Retrieves an invoice by the payment hash if it exists, otherwise returns
    /// `None`.
    pub async fn handle_get_invoice_msg(
        &self,
        payload: GetInvoiceRequest,
    ) -> AdminResult<Option<GetInvoiceResponse>> {
        let lightning_context = self.get_lightning_context().await?;
        let invoice = lightning_context.lnrpc.get_invoice(payload).await?;
        Ok(invoice)
    }

    /// Creates a BOLT12 offer using the gateway's lightning node
    pub async fn handle_create_offer_for_operator_msg(
        &self,
        payload: CreateOfferPayload,
    ) -> AdminResult<CreateOfferResponse> {
        let lightning_context = self.get_lightning_context().await?;
        let offer = lightning_context.lnrpc.create_offer(
            payload.amount,
            payload.description,
            payload.expiry_secs,
            payload.quantity,
        )?;
        Ok(CreateOfferResponse { offer })
    }

    /// Pays a BOLT12 offer using the gateway's lightning node
    pub async fn handle_pay_offer_for_operator_msg(
        &self,
        payload: PayOfferPayload,
    ) -> AdminResult<PayOfferResponse> {
        let lightning_context = self.get_lightning_context().await?;
        let preimage = lightning_context
            .lnrpc
            .pay_offer(
                payload.offer,
                payload.quantity,
                payload.amount,
                payload.payer_note,
            )
            .await?;
        Ok(PayOfferResponse {
            preimage: preimage.to_string(),
        })
    }

    /// Registers the gateway with each specified federation.
    async fn register_federations(
        &self,
        federations: &BTreeMap<FederationId, FederationConfig>,
        register_task_group: &TaskGroup,
    ) {
        if let Ok(lightning_context) = self.get_lightning_context().await {
            let route_hints = lightning_context
                .lnrpc
                .parsed_route_hints(self.num_route_hints)
                .await;
            if route_hints.is_empty() {
                warn!(target: LOG_GATEWAY, "Gateway did not retrieve any route hints, may reduce receive success rate.");
            }

            for (federation_id, federation_config) in federations {
                let fed_manager = self.federation_manager.read().await;
                if let Some(client) = fed_manager.client(federation_id) {
                    let client_arc = client.clone().into_value();
                    let route_hints = route_hints.clone();
                    let lightning_context = lightning_context.clone();
                    let federation_config = federation_config.clone();
                    let registrations =
                        self.registrations.clone().into_values().collect::<Vec<_>>();

                    register_task_group.spawn_cancellable_silent(
                        "register federation",
                        async move {
                            let Ok(gateway_client) =
                                client_arc.get_first_module::<GatewayClientModule>()
                            else {
                                return;
                            };

                            for registration in registrations {
                                gateway_client
                                    .try_register_with_federation(
                                        route_hints.clone(),
                                        GW_ANNOUNCEMENT_TTL,
                                        federation_config.lightning_fee.into(),
                                        lightning_context.clone(),
                                        registration.endpoint_url,
                                        registration.keypair.public_key(),
                                    )
                                    .await;
                            }
                        },
                    );
                }
            }
        }
    }

    /// Retrieves a `ClientHandleArc` from the Gateway's in memory structures
    /// that keep track of available clients, given a `federation_id`.
    pub async fn select_client(
        &self,
        federation_id: FederationId,
    ) -> std::result::Result<Spanned<fedimint_client::ClientHandleArc>, FederationNotConnected>
    {
        self.federation_manager
            .read()
            .await
            .client(&federation_id)
            .cloned()
            .ok_or(FederationNotConnected {
                federation_id_prefix: federation_id.to_prefix(),
            })
    }

    async fn load_mnemonic(gateway_db: &Database) -> Option<Mnemonic> {
        let secret = Client::load_decodable_client_secret::<Vec<u8>>(gateway_db)
            .await
            .ok()?;
        Mnemonic::from_entropy(&secret).ok()
    }

    /// Reads the connected federation client configs from the Gateway's
    /// database and reconstructs the clients necessary for interacting with
    /// connection federations.
    async fn load_clients(&self) -> AdminResult<()> {
        if let GatewayState::NotConfigured { .. } = self.get_state().await {
            return Ok(());
        }

        let mut federation_manager = self.federation_manager.write().await;

        let configs = {
            let mut dbtx = self.gateway_db.begin_transaction_nc().await;
            dbtx.load_federation_configs().await
        };

        if let Some(max_federation_index) = configs.values().map(|cfg| cfg.federation_index).max() {
            federation_manager.set_next_index(max_federation_index + 1);
        }

        let mnemonic = Self::load_mnemonic(&self.gateway_db)
            .await
            .expect("mnemonic should be set");

        for (federation_id, config) in configs {
            let federation_index = config.federation_index;
            match Box::pin(Spanned::try_new(
                info_span!(target: LOG_GATEWAY, "client", federation_id  = %federation_id.clone()),
                self.client_builder
                    .build(config, Arc::new(self.clone()), &mnemonic),
            ))
            .await
            {
                Ok(client) => {
                    federation_manager.add_client(federation_index, client);
                }
                _ => {
                    warn!(target: LOG_GATEWAY, federation_id = %federation_id, "Failed to load client");
                }
            }
        }

        Ok(())
    }

    /// Legacy mechanism for registering the Gateway with connected federations.
    /// This will spawn a task that will re-register the Gateway with
    /// connected federations every 8.5 mins. Only registers the Gateway if it
    /// has successfully connected to the Lightning node, so that it can
    /// include route hints in the registration.
    fn register_clients_timer(&self) {
        // Only spawn background registration thread if gateway is LND
        if matches!(self.lightning_mode, LightningMode::Lnd { .. }) {
            info!(target: LOG_GATEWAY, "Spawning register task...");
            let gateway = self.clone();
            let register_task_group = self.task_group.make_subgroup();
            self.task_group.spawn_cancellable("register clients", async move {
                loop {
                    let gateway_state = gateway.get_state().await;
                    if let GatewayState::Running { .. } = &gateway_state {
                        let mut dbtx = gateway.gateway_db.begin_transaction_nc().await;
                        let all_federations_configs = dbtx.load_federation_configs().await.into_iter().collect();
                        gateway.register_federations(&all_federations_configs, &register_task_group).await;
                    } else {
                        // We need to retry more often if the gateway is not in the Running state
                        const NOT_RUNNING_RETRY: Duration = Duration::from_secs(10);
                        warn!(target: LOG_GATEWAY, gateway_state = %gateway_state, retry_interval = ?NOT_RUNNING_RETRY, "Will not register federation yet because gateway still not in Running state");
                        sleep(NOT_RUNNING_RETRY).await;
                        continue;
                    }

                    // Allow a 15% buffer of the TTL before the re-registering gateway
                    // with the federations.
                    sleep(GW_ANNOUNCEMENT_TTL.mul_f32(0.85)).await;
                }
            });
        }
    }

    /// Verifies that the federation has at least one lightning module (LNv1 or
    /// LNv2) and that the network matches the gateway's network.
    async fn check_federation_network(
        client: &ClientHandleArc,
        network: Network,
    ) -> AdminResult<()> {
        let federation_id = client.federation_id();
        let config = client.config().await;

        let lnv1_cfg = config
            .modules
            .values()
            .find(|m| LightningCommonInit::KIND == m.kind);

        let lnv2_cfg = config
            .modules
            .values()
            .find(|m| fedimint_lnv2_common::LightningCommonInit::KIND == m.kind);

        // Ensure the federation has at least one lightning module
        if lnv1_cfg.is_none() && lnv2_cfg.is_none() {
            return Err(AdminGatewayError::ClientCreationError(anyhow!(
                "Federation {federation_id} does not have any lightning module (LNv1 or LNv2)"
            )));
        }

        // Verify the LNv1 network if present
        if let Some(cfg) = lnv1_cfg {
            let ln_cfg: &LightningClientConfig = cfg.cast()?;

            if ln_cfg.network.0 != network {
                crit!(
                    target: LOG_GATEWAY,
                    federation_id = %federation_id,
                    network = %network,
                    "Incorrect LNv1 network for federation",
                );
                return Err(AdminGatewayError::ClientCreationError(anyhow!(format!(
                    "Unsupported LNv1 network {}",
                    ln_cfg.network
                ))));
            }
        }

        // Verify the LNv2 network if present
        if let Some(cfg) = lnv2_cfg {
            let ln_cfg: &fedimint_lnv2_common::config::LightningClientConfig = cfg.cast()?;

            if ln_cfg.network != network {
                crit!(
                    target: LOG_GATEWAY,
                    federation_id = %federation_id,
                    network = %network,
                    "Incorrect LNv2 network for federation",
                );
                return Err(AdminGatewayError::ClientCreationError(anyhow!(format!(
                    "Unsupported LNv2 network {}",
                    ln_cfg.network
                ))));
            }
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
            GatewayState::Running { lightning_context }
            | GatewayState::ShuttingDown { lightning_context } => Ok(lightning_context),
            _ => Err(LightningRpcError::FailedToConnect),
        }
    }

    /// Iterates through all of the federations the gateway is registered with
    /// and requests to remove the registration record.
    pub async fn unannounce_from_all_federations(&self) {
        if matches!(self.lightning_mode, LightningMode::Lnd { .. }) {
            for registration in self.registrations.values() {
                self.federation_manager
                    .read()
                    .await
                    .unannounce_from_all_federations(registration.keypair)
                    .await;
            }
        }
    }

    async fn create_lightning_client(
        &self,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> Box<dyn ILnRpcClient> {
        match self.lightning_mode.clone() {
            LightningMode::Lnd {
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
            } => Box::new(GatewayLndClient::new(
                lnd_rpc_addr,
                lnd_tls_cert,
                lnd_macaroon,
                None,
            )),
            LightningMode::Ldk {
                lightning_port,
                alias,
            } => {
                let mnemonic = Self::load_mnemonic(&self.gateway_db)
                    .await
                    .expect("mnemonic should be set");
                // Retrieving the fees inside of LDK can sometimes fail/time out. To prevent
                // crashing the gateway, we wait a bit and just try
                // to re-create the client. The gateway cannot proceed until this succeeds.
                retry("create LDK Node", fibonacci_max_one_hour(), || async {
                    ldk::GatewayLdkClient::new(
                        &self.client_builder.data_dir().join(LDK_NODE_DB_FOLDER),
                        self.chain_source.clone(),
                        self.network,
                        lightning_port,
                        alias.clone(),
                        mnemonic.clone(),
                        runtime.clone(),
                    )
                    .map(Box::new)
                })
                .await
                .expect("Could not create LDK Node")
            }
        }
    }
}

#[async_trait]
impl IAdminGateway for Gateway {
    type Error = AdminGatewayError;

    /// Returns information about the Gateway back to the client when requested
    /// via the webserver.
    async fn handle_get_info(&self) -> AdminResult<GatewayInfo> {
        let GatewayState::Running { lightning_context } = self.get_state().await else {
            return Ok(GatewayInfo {
                federations: vec![],
                federation_fake_scids: None,
                version_hash: fedimint_build_code_version_env!().to_string(),
                gateway_state: self.state.read().await.to_string(),
                lightning_info: LightningInfo::NotConnected,
                lightning_mode: self.lightning_mode.clone(),
                registrations: self
                    .registrations
                    .iter()
                    .map(|(k, v)| (k.clone(), (v.endpoint_url.clone(), v.keypair.public_key())))
                    .collect(),
            });
        };

        let dbtx = self.gateway_db.begin_transaction_nc().await;
        let federations = self
            .federation_manager
            .read()
            .await
            .federation_info_all_federations(dbtx)
            .await;

        let channels: BTreeMap<u64, FederationId> = federations
            .iter()
            .map(|federation_info| {
                (
                    federation_info.config.federation_index,
                    federation_info.federation_id,
                )
            })
            .collect();

        let lightning_info = lightning_context.lnrpc.parsed_node_info().await;

        Ok(GatewayInfo {
            federations,
            federation_fake_scids: Some(channels),
            version_hash: fedimint_build_code_version_env!().to_string(),
            gateway_state: self.state.read().await.to_string(),
            lightning_info,
            lightning_mode: self.lightning_mode.clone(),
            registrations: self
                .registrations
                .iter()
                .map(|(k, v)| (k.clone(), (v.endpoint_url.clone(), v.keypair.public_key())))
                .collect(),
        })
    }

    /// Returns a list of Lightning network channels from the Gateway's
    /// Lightning node.
    async fn handle_list_channels_msg(
        &self,
    ) -> AdminResult<Vec<fedimint_gateway_common::ChannelInfo>> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.list_channels().await?;
        Ok(response.channels)
    }

    /// Computes the 24 hour payment summary statistics for this gateway.
    /// Combines the LNv1 and LNv2 stats together.
    async fn handle_payment_summary_msg(
        &self,
        PaymentSummaryPayload {
            start_millis,
            end_millis,
        }: PaymentSummaryPayload,
    ) -> AdminResult<PaymentSummaryResponse> {
        let federation_manager = self.federation_manager.read().await;
        let fed_configs = federation_manager.get_all_federation_configs().await;
        let federation_ids = fed_configs.keys().collect::<Vec<_>>();
        let start = UNIX_EPOCH + Duration::from_millis(start_millis);
        let end = UNIX_EPOCH + Duration::from_millis(end_millis);

        if start > end {
            return Err(AdminGatewayError::Unexpected(anyhow!("Invalid time range")));
        }

        let mut outgoing = StructuredPaymentEvents::default();
        let mut incoming = StructuredPaymentEvents::default();
        for fed_id in federation_ids {
            let client = federation_manager
                .client(fed_id)
                .expect("No client available")
                .value();
            let all_events = &get_events_for_duration(client, start, end).await;

            let (mut lnv1_outgoing, mut lnv1_incoming) = compute_lnv1_stats(all_events);
            let (mut lnv2_outgoing, mut lnv2_incoming) = compute_lnv2_stats(all_events);
            outgoing.combine(&mut lnv1_outgoing);
            incoming.combine(&mut lnv1_incoming);
            outgoing.combine(&mut lnv2_outgoing);
            incoming.combine(&mut lnv2_incoming);
        }

        Ok(PaymentSummaryResponse {
            outgoing: PaymentStats::compute(&outgoing),
            incoming: PaymentStats::compute(&incoming),
        })
    }

    /// Handle a request to have the Gateway leave a federation. The Gateway
    /// will request the federation to remove the registration record and
    /// the gateway will remove the configuration needed to construct the
    /// federation client.
    async fn handle_leave_federation(
        &self,
        payload: LeaveFedPayload,
    ) -> AdminResult<FederationInfo> {
        // Lock the federation manager before starting the db transaction to reduce the
        // chance of db write conflicts.
        let mut federation_manager = self.federation_manager.write().await;
        let mut dbtx = self.gateway_db.begin_transaction().await;

        let federation_info = federation_manager
            .leave_federation(
                payload.federation_id,
                &mut dbtx.to_ref_nc(),
                self.registrations.values().collect(),
            )
            .await?;

        dbtx.remove_federation_config(payload.federation_id).await;
        dbtx.commit_tx().await;
        Ok(federation_info)
    }

    /// Handles a connection request to join a new federation. The gateway will
    /// download the federation's client configuration, construct a new
    /// client, registers, the gateway with the federation, and persists the
    /// necessary config to reconstruct the client when restarting the gateway.
    async fn handle_connect_federation(
        &self,
        payload: ConnectFedPayload,
    ) -> AdminResult<FederationInfo> {
        let GatewayState::Running { lightning_context } = self.get_state().await else {
            return Err(AdminGatewayError::Lightning(
                LightningRpcError::FailedToConnect,
            ));
        };

        let invite_code = InviteCode::from_str(&payload.invite_code).map_err(|e| {
            AdminGatewayError::ClientCreationError(anyhow!(format!(
                "Invalid federation member string {e:?}"
            )))
        })?;

        let federation_id = invite_code.federation_id();

        let mut federation_manager = self.federation_manager.write().await;

        // Check if this federation has already been registered
        if federation_manager.has_federation(federation_id) {
            return Err(AdminGatewayError::ClientCreationError(anyhow!(
                "Federation has already been registered"
            )));
        }

        // The gateway deterministically assigns a unique identifier (u64) to each
        // federation connected.
        let federation_index = federation_manager.pop_next_index()?;

        let federation_config = FederationConfig {
            invite_code,
            federation_index,
            lightning_fee: self.default_routing_fees,
            transaction_fee: self.default_transaction_fees,
            // Note: deprecated, unused
            _connector: ConnectorType::Tcp,
        };

        let mnemonic = Self::load_mnemonic(&self.gateway_db)
            .await
            .expect("mnemonic should be set");
        let recover = payload.recover.unwrap_or(false);
        if recover {
            self.client_builder
                .recover(federation_config.clone(), Arc::new(self.clone()), &mnemonic)
                .await?;
        }

        let client = self
            .client_builder
            .build(federation_config.clone(), Arc::new(self.clone()), &mnemonic)
            .await?;

        if recover {
            client.wait_for_all_active_state_machines().await?;
        }

        // Instead of using `FederationManager::federation_info`, we manually create
        // federation info here because short channel id is not yet persisted.
        let federation_info = FederationInfo {
            federation_id,
            federation_name: federation_manager.federation_name(&client).await,
            balance_msat: client.get_balance_for_btc().await.unwrap_or_else(|err| {
                warn!(
                    target: LOG_GATEWAY,
                    err = %err.fmt_compact_anyhow(),
                    %federation_id,
                    "Balance not immediately available after joining/recovering."
                );
                Amount::default()
            }),
            config: federation_config.clone(),
            last_backup_time: None,
        };

        Self::check_federation_network(&client, self.network).await?;
        if matches!(self.lightning_mode, LightningMode::Lnd { .. })
            && let Ok(lnv1) = client.get_first_module::<GatewayClientModule>()
        {
            for registration in self.registrations.values() {
                lnv1.try_register_with_federation(
                    // Route hints will be updated in the background
                    Vec::new(),
                    GW_ANNOUNCEMENT_TTL,
                    federation_config.lightning_fee.into(),
                    lightning_context.clone(),
                    registration.endpoint_url.clone(),
                    registration.keypair.public_key(),
                )
                .await;
            }
        }

        // no need to enter span earlier, because connect-fed has a span
        federation_manager.add_client(
            federation_index,
            Spanned::new(
                info_span!(target: LOG_GATEWAY, "client", federation_id=%federation_id.clone()),
                async { client },
            )
            .await,
        );

        let mut dbtx = self.gateway_db.begin_transaction().await;
        dbtx.save_federation_config(&federation_config).await;
        dbtx.save_federation_backup_record(federation_id, None)
            .await;
        dbtx.commit_tx().await;
        debug!(
            target: LOG_GATEWAY,
            federation_id = %federation_id,
            federation_index = %federation_index,
            "Federation connected"
        );

        Ok(federation_info)
    }

    /// Handles a request to change the lightning or transaction fees for all
    /// federations or a federation specified by the `FederationId`.
    async fn handle_set_fees_msg(
        &self,
        SetFeesPayload {
            federation_id,
            lightning_base,
            lightning_parts_per_million,
            transaction_base,
            transaction_parts_per_million,
        }: SetFeesPayload,
    ) -> AdminResult<()> {
        let mut dbtx = self.gateway_db.begin_transaction().await;
        let mut fed_configs = if let Some(fed_id) = federation_id {
            dbtx.load_federation_configs()
                .await
                .into_iter()
                .filter(|(id, _)| *id == fed_id)
                .collect::<BTreeMap<_, _>>()
        } else {
            dbtx.load_federation_configs().await
        };

        let federation_manager = self.federation_manager.read().await;

        for (federation_id, config) in &mut fed_configs {
            let mut lightning_fee = config.lightning_fee;
            if let Some(lightning_base) = lightning_base {
                lightning_fee.base = lightning_base;
            }

            if let Some(lightning_ppm) = lightning_parts_per_million {
                lightning_fee.parts_per_million = lightning_ppm;
            }

            let mut transaction_fee = config.transaction_fee;
            if let Some(transaction_base) = transaction_base {
                transaction_fee.base = transaction_base;
            }

            if let Some(transaction_ppm) = transaction_parts_per_million {
                transaction_fee.parts_per_million = transaction_ppm;
            }

            let client =
                federation_manager
                    .client(federation_id)
                    .ok_or(FederationNotConnected {
                        federation_id_prefix: federation_id.to_prefix(),
                    })?;
            let client_config = client.value().config().await;
            let contains_lnv2 = client_config
                .modules
                .values()
                .any(|m| fedimint_lnv2_common::LightningCommonInit::KIND == m.kind);

            // Check if the lightning fee + transaction fee is higher than the send limit
            let send_fees = lightning_fee + transaction_fee;
            if contains_lnv2 && send_fees.gt(&PaymentFee::SEND_FEE_LIMIT) {
                return Err(AdminGatewayError::GatewayConfigurationError(format!(
                    "Total Send fees exceeded {}",
                    PaymentFee::SEND_FEE_LIMIT
                )));
            }

            // Check if the transaction fee is higher than the receive limit
            if contains_lnv2 && transaction_fee.gt(&PaymentFee::RECEIVE_FEE_LIMIT) {
                return Err(AdminGatewayError::GatewayConfigurationError(format!(
                    "Transaction fees exceeded RECEIVE LIMIT {}",
                    PaymentFee::RECEIVE_FEE_LIMIT
                )));
            }

            config.lightning_fee = lightning_fee;
            config.transaction_fee = transaction_fee;
            dbtx.save_federation_config(config).await;
        }

        dbtx.commit_tx().await;

        if matches!(self.lightning_mode, LightningMode::Lnd { .. }) {
            let register_task_group = TaskGroup::new();

            self.register_federations(&fed_configs, &register_task_group)
                .await;
        }

        Ok(())
    }

    /// Handles an authenticated request for the gateway's mnemonic. This also
    /// returns a vector of federations that are not using the mnemonic
    /// backup strategy.
    async fn handle_mnemonic_msg(&self) -> AdminResult<MnemonicResponse> {
        let mnemonic = Self::load_mnemonic(&self.gateway_db)
            .await
            .expect("mnemonic should be set");
        let words = mnemonic
            .words()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        let all_federations = self
            .federation_manager
            .read()
            .await
            .get_all_federation_configs()
            .await
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let legacy_federations = self.client_builder.legacy_federations(all_federations);
        let mnemonic_response = MnemonicResponse {
            mnemonic: words,
            legacy_federations,
        };
        Ok(mnemonic_response)
    }

    /// Instructs the Gateway's Lightning node to open a channel to a peer
    /// specified by `pubkey`.
    async fn handle_open_channel_msg(&self, payload: OpenChannelRequest) -> AdminResult<Txid> {
        info!(target: LOG_GATEWAY, pubkey = %payload.pubkey, host = %payload.host, amount = %payload.channel_size_sats, "Opening Lightning channel...");
        let context = self.get_lightning_context().await?;
        let res = context.lnrpc.open_channel(payload).await?;
        info!(target: LOG_GATEWAY, txid = %res.funding_txid, "Initiated channel open");
        Txid::from_str(&res.funding_txid).map_err(|e| {
            AdminGatewayError::Lightning(LightningRpcError::InvalidMetadata {
                failure_reason: format!("Received invalid channel funding txid string {e}"),
            })
        })
    }

    /// Instructs the Gateway's Lightning node to close all channels with a peer
    /// specified by `pubkey`.
    async fn handle_close_channels_with_peer_msg(
        &self,
        payload: CloseChannelsWithPeerRequest,
    ) -> AdminResult<CloseChannelsWithPeerResponse> {
        info!(target: LOG_GATEWAY, close_channel_request = %payload, "Closing lightning channel...");
        let context = self.get_lightning_context().await?;
        let response = context
            .lnrpc
            .close_channels_with_peer(payload.clone())
            .await?;
        info!(target: LOG_GATEWAY, close_channel_request = %payload, "Initiated channel closure");
        Ok(response)
    }

    /// Returns the ecash, lightning, and onchain balances for the gateway and
    /// the gateway's lightning node.
    async fn handle_get_balances_msg(&self) -> AdminResult<GatewayBalances> {
        let dbtx = self.gateway_db.begin_transaction_nc().await;
        let federation_infos = self
            .federation_manager
            .read()
            .await
            .federation_info_all_federations(dbtx)
            .await;

        let ecash_balances: Vec<FederationBalanceInfo> = federation_infos
            .iter()
            .map(|federation_info| FederationBalanceInfo {
                federation_id: federation_info.federation_id,
                ecash_balance_msats: Amount {
                    msats: federation_info.balance_msat.msats,
                },
            })
            .collect();

        let context = self.get_lightning_context().await?;
        let lightning_node_balances = context.lnrpc.get_balances().await?;

        Ok(GatewayBalances {
            onchain_balance_sats: lightning_node_balances.onchain_balance_sats,
            lightning_balance_msats: lightning_node_balances.lightning_balance_msats,
            ecash_balances,
            inbound_lightning_liquidity_msats: lightning_node_balances
                .inbound_lightning_liquidity_msats,
        })
    }

    /// Send funds from the gateway's lightning node on-chain wallet.
    async fn handle_send_onchain_msg(&self, payload: SendOnchainRequest) -> AdminResult<Txid> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.send_onchain(payload.clone()).await?;
        let txid =
            Txid::from_str(&response.txid).map_err(|e| AdminGatewayError::WithdrawError {
                failure_reason: format!("Failed to parse withdrawal TXID: {e}"),
            })?;
        info!(onchain_request = %payload, txid = %txid, "Sent onchain transaction");
        Ok(txid)
    }

    /// Generates an onchain address to fund the gateway's lightning node.
    async fn handle_get_ln_onchain_address_msg(&self) -> AdminResult<Address> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.get_ln_onchain_address().await?;

        let address = Address::from_str(&response.address).map_err(|e| {
            AdminGatewayError::Lightning(LightningRpcError::InvalidMetadata {
                failure_reason: e.to_string(),
            })
        })?;

        address.require_network(self.network).map_err(|e| {
            AdminGatewayError::Lightning(LightningRpcError::InvalidMetadata {
                failure_reason: e.to_string(),
            })
        })
    }

    async fn handle_deposit_address_msg(
        &self,
        payload: DepositAddressPayload,
    ) -> AdminResult<Address> {
        self.handle_address_msg(payload).await
    }

    async fn handle_receive_ecash_msg(
        &self,
        payload: ReceiveEcashPayload,
    ) -> AdminResult<ReceiveEcashResponse> {
        Self::handle_receive_ecash_msg(self, payload)
            .await
            .map_err(|e| AdminGatewayError::Unexpected(anyhow::anyhow!("{}", e)))
    }

    /// Creates an invoice that is directly payable to the gateway's lightning
    /// node.
    async fn handle_create_invoice_for_operator_msg(
        &self,
        payload: CreateInvoiceForOperatorPayload,
    ) -> AdminResult<Bolt11Invoice> {
        let GatewayState::Running { lightning_context } = self.get_state().await else {
            return Err(AdminGatewayError::Lightning(
                LightningRpcError::FailedToConnect,
            ));
        };

        Bolt11Invoice::from_str(
            &lightning_context
                .lnrpc
                .create_invoice(CreateInvoiceRequest {
                    payment_hash: None, /* Empty payment hash indicates an invoice payable
                                         * directly to the gateway. */
                    amount_msat: payload.amount_msats,
                    expiry_secs: payload.expiry_secs.unwrap_or(3600),
                    description: payload.description.map(InvoiceDescription::Direct),
                })
                .await?
                .invoice,
        )
        .map_err(|e| {
            AdminGatewayError::Lightning(LightningRpcError::InvalidMetadata {
                failure_reason: e.to_string(),
            })
        })
    }

    /// Requests the gateway to pay an outgoing LN invoice using its own funds.
    /// Returns the payment hash's preimage on success.
    async fn handle_pay_invoice_for_operator_msg(
        &self,
        payload: PayInvoiceForOperatorPayload,
    ) -> AdminResult<Preimage> {
        // Those are the ldk defaults
        const BASE_FEE: u64 = 50;
        const FEE_DENOMINATOR: u64 = 100;
        const MAX_DELAY: u64 = 1008;

        let GatewayState::Running { lightning_context } = self.get_state().await else {
            return Err(AdminGatewayError::Lightning(
                LightningRpcError::FailedToConnect,
            ));
        };

        let max_fee = BASE_FEE
            + payload
                .invoice
                .amount_milli_satoshis()
                .context("Invoice is missing amount")?
                .saturating_div(FEE_DENOMINATOR);

        let res = lightning_context
            .lnrpc
            .pay(payload.invoice, MAX_DELAY, Amount::from_msats(max_fee))
            .await?;
        Ok(res.preimage)
    }

    /// Lists the transactions that the lightning node has made.
    async fn handle_list_transactions_msg(
        &self,
        payload: ListTransactionsPayload,
    ) -> AdminResult<ListTransactionsResponse> {
        let lightning_context = self.get_lightning_context().await?;
        let response = lightning_context
            .lnrpc
            .list_transactions(payload.start_secs, payload.end_secs)
            .await?;
        Ok(response)
    }

    // Handles a request the spend the gateway's ecash for a given federation.
    async fn handle_spend_ecash_msg(
        &self,
        payload: SpendEcashPayload,
    ) -> AdminResult<SpendEcashResponse> {
        let client = self
            .select_client(payload.federation_id)
            .await?
            .into_value();
        let mint_module = client.get_first_module::<MintClientModule>()?;
        let timeout = Duration::from_secs(payload.timeout);
        let (operation_id, notes) = if payload.allow_overpay {
            let (operation_id, notes) = mint_module
                .spend_notes_with_selector(
                    &SelectNotesWithAtleastAmount,
                    payload.amount,
                    timeout,
                    payload.include_invite,
                    (),
                )
                .await?;

            let overspend_amount = notes.total_amount().saturating_sub(payload.amount);
            if overspend_amount != Amount::ZERO {
                warn!(
                    target: LOG_GATEWAY,
                    overspend_amount = %overspend_amount,
                    "Selected notes worth more than requested",
                );
            }

            (operation_id, notes)
        } else {
            mint_module
                .spend_notes_with_selector(
                    &SelectNotesWithExactAmount,
                    payload.amount,
                    timeout,
                    payload.include_invite,
                    (),
                )
                .await?
        };

        debug!(target: LOG_GATEWAY, ?operation_id, ?notes, "Spend ecash notes");

        Ok(SpendEcashResponse {
            operation_id,
            notes,
        })
    }

    /// Instructs the gateway to shutdown, but only after all incoming payments
    /// have been handled.
    async fn handle_shutdown_msg(&self, task_group: TaskGroup) -> AdminResult<()> {
        // Take the write lock on the state so that no additional payments are processed
        let mut state_guard = self.state.write().await;
        if let GatewayState::Running { lightning_context } = state_guard.clone() {
            *state_guard = GatewayState::ShuttingDown { lightning_context };

            self.federation_manager
                .read()
                .await
                .wait_for_incoming_payments()
                .await?;
        }

        let tg = task_group.clone();
        tg.spawn("Kill Gateway", |_task_handle| async {
            if let Err(err) = task_group.shutdown_join_all(Duration::from_secs(180)).await {
                warn!(target: LOG_GATEWAY, err = %err.fmt_compact_anyhow(), "Error shutting down gateway");
            }
        });
        Ok(())
    }

    fn get_task_group(&self) -> TaskGroup {
        self.task_group.clone()
    }

    /// Returns a Bitcoin TXID from a peg-out transaction for a specific
    /// connected federation.
    async fn handle_withdraw_msg(&self, payload: WithdrawPayload) -> AdminResult<WithdrawResponse> {
        let WithdrawPayload {
            amount,
            address,
            federation_id,
            quoted_fees,
        } = payload;

        let address_network = get_network_for_address(&address);
        let gateway_network = self.network;
        let Ok(address) = address.require_network(gateway_network) else {
            return Err(AdminGatewayError::WithdrawError {
                failure_reason: format!(
                    "Gateway is running on network {gateway_network}, but provided withdraw address is for network {address_network}"
                ),
            });
        };

        let client = self.select_client(federation_id).await?;
        let wallet_module = client.value().get_first_module::<WalletClientModule>()?;

        // If fees are provided (from UI preview flow), use them directly
        // Otherwise fetch fees (CLI backwards compatibility)
        let (withdraw_amount, fees) = match quoted_fees {
            // UI flow: user confirmed these exact values, just use them
            Some(fees) => {
                let amt = match amount {
                    BitcoinAmountOrAll::Amount(a) => a,
                    BitcoinAmountOrAll::All => {
                        // UI always resolves "all" to specific amount in preview - reject if not
                        return Err(AdminGatewayError::WithdrawError {
                            failure_reason:
                                "Cannot use 'all' with quoted fees - amount must be resolved first"
                                    .to_string(),
                        });
                    }
                };
                (amt, fees)
            }
            // CLI flow: fetch fees (existing behavior for backwards compatibility)
            None => match amount {
                // If the amount is "all", then we need to subtract the fees from
                // the amount we are withdrawing
                BitcoinAmountOrAll::All => {
                    let balance = bitcoin::Amount::from_sat(
                        client
                            .value()
                            .get_balance_for_btc()
                            .await
                            .map_err(|err| {
                                AdminGatewayError::Unexpected(anyhow!(
                                    "Balance not available: {}",
                                    err.fmt_compact_anyhow()
                                ))
                            })?
                            .msats
                            / 1000,
                    );
                    let fees = wallet_module.get_withdraw_fees(&address, balance).await?;
                    let withdraw_amount = balance.checked_sub(fees.amount());
                    if withdraw_amount.is_none() {
                        return Err(AdminGatewayError::WithdrawError {
                            failure_reason: format!(
                                "Insufficient funds. Balance: {balance} Fees: {fees:?}"
                            ),
                        });
                    }
                    (withdraw_amount.expect("checked above"), fees)
                }
                BitcoinAmountOrAll::Amount(amount) => (
                    amount,
                    wallet_module.get_withdraw_fees(&address, amount).await?,
                ),
            },
        };

        let operation_id = wallet_module
            .withdraw(&address, withdraw_amount, fees, ())
            .await?;
        let mut updates = wallet_module
            .subscribe_withdraw_updates(operation_id)
            .await?
            .into_stream();

        while let Some(update) = updates.next().await {
            match update {
                WithdrawState::Succeeded(txid) => {
                    info!(target: LOG_GATEWAY, amount = %withdraw_amount, address = %address, "Sent funds");
                    return Ok(WithdrawResponse { txid, fees });
                }
                WithdrawState::Failed(e) => {
                    return Err(AdminGatewayError::WithdrawError { failure_reason: e });
                }
                WithdrawState::Created => {}
            }
        }

        Err(AdminGatewayError::WithdrawError {
            failure_reason: "Ran out of state updates while withdrawing".to_string(),
        })
    }

    /// Returns a preview of the withdrawal fees without executing the
    /// withdrawal. Used by the UI for two-step withdrawal confirmation.
    async fn handle_withdraw_preview_msg(
        &self,
        payload: WithdrawPreviewPayload,
    ) -> AdminResult<WithdrawPreviewResponse> {
        let gateway_network = self.network;
        let address_checked = payload
            .address
            .clone()
            .require_network(gateway_network)
            .map_err(|_| AdminGatewayError::WithdrawError {
                failure_reason: "Address network mismatch".to_string(),
            })?;

        let client = self.select_client(payload.federation_id).await?;
        let wallet_module = client.value().get_first_module::<WalletClientModule>()?;

        let WithdrawDetails {
            amount,
            mint_fees,
            peg_out_fees,
        } = match payload.amount {
            BitcoinAmountOrAll::All => {
                calculate_max_withdrawable(client.value(), &address_checked).await?
            }
            BitcoinAmountOrAll::Amount(btc_amount) => WithdrawDetails {
                amount: btc_amount.into(),
                mint_fees: None,
                peg_out_fees: wallet_module
                    .get_withdraw_fees(&address_checked, btc_amount)
                    .await?,
            },
        };

        let total_cost = amount
            .checked_add(peg_out_fees.amount().into())
            .and_then(|a| a.checked_add(mint_fees.unwrap_or(Amount::ZERO)))
            .ok_or_else(|| AdminGatewayError::Unexpected(anyhow!("Total cost overflow")))?;

        Ok(WithdrawPreviewResponse {
            withdraw_amount: amount,
            address: payload.address.assume_checked().to_string(),
            peg_out_fees,
            total_cost,
            mint_fees,
        })
    }

    /// Queries the client log for payment events and returns to the user.
    async fn handle_payment_log_msg(
        &self,
        PaymentLogPayload {
            end_position,
            pagination_size,
            federation_id,
            event_kinds,
        }: PaymentLogPayload,
    ) -> AdminResult<PaymentLogResponse> {
        const BATCH_SIZE: u64 = 10_000;
        let federation_manager = self.federation_manager.read().await;
        let client = federation_manager
            .client(&federation_id)
            .ok_or(FederationNotConnected {
                federation_id_prefix: federation_id.to_prefix(),
            })?
            .value();

        let event_kinds = if event_kinds.is_empty() {
            ALL_GATEWAY_EVENTS.to_vec()
        } else {
            event_kinds
        };

        let end_position = if let Some(position) = end_position {
            position
        } else {
            let mut dbtx = client.db().begin_transaction_nc().await;
            dbtx.get_next_event_log_id().await
        };

        let mut start_position = end_position.saturating_sub(BATCH_SIZE);

        let mut payment_log = Vec::new();

        while payment_log.len() < pagination_size {
            let batch = client.get_event_log(Some(start_position), BATCH_SIZE).await;
            let mut filtered_batch = batch
                .into_iter()
                .filter(|e| e.id() <= end_position && event_kinds.contains(&e.as_raw().kind))
                .collect::<Vec<_>>();
            filtered_batch.reverse();
            payment_log.extend(filtered_batch);

            // Compute the start position for the next batch query
            start_position = start_position.saturating_sub(BATCH_SIZE);

            if start_position == EventLogId::LOG_START {
                break;
            }
        }

        // Truncate the payment log to the expected pagination size
        payment_log.truncate(pagination_size);

        Ok(PaymentLogResponse(payment_log))
    }

    /// Set the gateway's root mnemonic by generating a new one or using the
    /// words provided in `SetMnemonicPayload`.
    async fn handle_set_mnemonic_msg(&self, payload: SetMnemonicPayload) -> AdminResult<()> {
        // Verify the state is NotConfigured
        let GatewayState::NotConfigured { mnemonic_sender } = self.get_state().await else {
            return Err(AdminGatewayError::MnemonicError(anyhow!(
                "Gateway is not is NotConfigured state"
            )));
        };

        let mnemonic = if let Some(words) = payload.words {
            info!(target: LOG_GATEWAY, "Using user provided mnemonic");
            Mnemonic::parse_in_normalized(Language::English, words.as_str()).map_err(|e| {
                AdminGatewayError::MnemonicError(anyhow!(format!(
                    "Seed phrase provided in environment was invalid {e:?}"
                )))
            })?
        } else {
            debug!(target: LOG_GATEWAY, "Generating mnemonic and writing entropy to client storage");
            Bip39RootSecretStrategy::<12>::random(&mut OsRng)
        };

        Client::store_encodable_client_secret(&self.gateway_db, mnemonic.to_entropy())
            .await
            .map_err(AdminGatewayError::MnemonicError)?;

        self.set_gateway_state(GatewayState::Disconnected).await;

        // Alert the gateway background threads that the mnemonic has been set
        let _ = mnemonic_sender.send(());

        Ok(())
    }

    fn get_password_hash(&self) -> String {
        self.bcrypt_password_hash.to_string()
    }

    fn gatewayd_version(&self) -> String {
        let gatewayd_version = env!("CARGO_PKG_VERSION");
        gatewayd_version.to_string()
    }

    async fn get_chain_source(&self) -> (ChainSource, Network) {
        (self.chain_source.clone(), self.network)
    }

    fn lightning_mode(&self) -> LightningMode {
        self.lightning_mode.clone()
    }

    async fn is_configured(&self) -> bool {
        !matches!(self.get_state().await, GatewayState::NotConfigured { .. })
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
                    .expect("Must have client module")
                    .keypair
                    .public_key()
            })
    }

    /// Returns payment information that LNv2 clients can use to instruct this
    /// Gateway to pay an invoice or receive a payment.
    pub async fn routing_info_v2(
        &self,
        federation_id: &FederationId,
    ) -> Result<Option<RoutingInfo>> {
        let context = self.get_lightning_context().await?;

        let mut dbtx = self.gateway_db.begin_transaction_nc().await;
        let fed_config = dbtx.load_federation_config(*federation_id).await.ok_or(
            PublicGatewayError::FederationNotConnected(FederationNotConnected {
                federation_id_prefix: federation_id.to_prefix(),
            }),
        )?;

        let lightning_fee = fed_config.lightning_fee;
        let transaction_fee = fed_config.transaction_fee;

        Ok(self
            .public_key_v2(federation_id)
            .await
            .map(|module_public_key| RoutingInfo {
                lightning_public_key: context.lightning_public_key,
                module_public_key,
                send_fee_default: lightning_fee + transaction_fee,
                // The base fee ensures that the gateway does not loose sats sending the payment due
                // to fees paid on the transaction claiming the outgoing contract or
                // subsequent transactions spending the newly issued ecash
                send_fee_minimum: transaction_fee,
                expiration_delta_default: 1440,
                expiration_delta_minimum: EXPIRATION_DELTA_MINIMUM_V2,
                // The base fee ensures that the gateway does not loose sats receiving the payment
                // due to fees paid on the transaction funding the incoming contract
                receive_fee: transaction_fee,
            }))
    }

    /// Instructs this gateway to pay a Lightning network invoice via the LNv2
    /// protocol.
    async fn send_payment_v2(
        &self,
        payload: SendPaymentPayload,
    ) -> Result<std::result::Result<[u8; 32], Signature>> {
        self.select_client(payload.federation_id)
            .await?
            .value()
            .get_first_module::<GatewayClientModuleV2>()
            .expect("Must have client module")
            .send_payment(payload)
            .await
            .map_err(LNv2Error::OutgoingPayment)
            .map_err(PublicGatewayError::LNv2)
    }

    /// For the LNv2 protocol, this will create an invoice by fetching it from
    /// the connected Lightning node, then save the payment hash so that
    /// incoming lightning payments can be matched as a receive attempt to a
    /// specific federation.
    async fn create_bolt11_invoice_v2(
        &self,
        payload: CreateBolt11InvoicePayload,
    ) -> Result<Bolt11Invoice> {
        if !payload.contract.verify() {
            return Err(PublicGatewayError::LNv2(LNv2Error::IncomingPayment(
                "The contract is invalid".to_string(),
            )));
        }

        let payment_info = self.routing_info_v2(&payload.federation_id).await?.ok_or(
            LNv2Error::IncomingPayment(format!(
                "Federation {} does not exist",
                payload.federation_id
            )),
        )?;

        if payload.contract.commitment.refund_pk != payment_info.module_public_key {
            return Err(PublicGatewayError::LNv2(LNv2Error::IncomingPayment(
                "The incoming contract is keyed to another gateway".to_string(),
            )));
        }

        let contract_amount = payment_info.receive_fee.subtract_from(payload.amount.msats);

        if contract_amount == Amount::ZERO {
            return Err(PublicGatewayError::LNv2(LNv2Error::IncomingPayment(
                "Zero amount incoming contracts are not supported".to_string(),
            )));
        }

        if contract_amount != payload.contract.commitment.amount {
            return Err(PublicGatewayError::LNv2(LNv2Error::IncomingPayment(
                "The contract amount does not pay the correct amount of fees".to_string(),
            )));
        }

        if payload.contract.commitment.expiration <= duration_since_epoch().as_secs() {
            return Err(PublicGatewayError::LNv2(LNv2Error::IncomingPayment(
                "The contract has already expired".to_string(),
            )));
        }

        let payment_hash = match payload.contract.commitment.payment_image {
            PaymentImage::Hash(payment_hash) => payment_hash,
            PaymentImage::Point(..) => {
                return Err(PublicGatewayError::LNv2(LNv2Error::IncomingPayment(
                    "PaymentImage is not a payment hash".to_string(),
                )));
            }
        };

        let invoice = self
            .create_invoice_via_lnrpc_v2(
                payment_hash,
                payload.amount,
                payload.description.clone(),
                payload.expiry_secs,
            )
            .await?;

        let mut dbtx = self.gateway_db.begin_transaction().await;

        if dbtx
            .save_registered_incoming_contract(
                payload.federation_id,
                payload.amount,
                payload.contract,
            )
            .await
            .is_some()
        {
            return Err(PublicGatewayError::LNv2(LNv2Error::IncomingPayment(
                "PaymentHash is already registered".to_string(),
            )));
        }

        dbtx.commit_tx_result().await.map_err(|_| {
            PublicGatewayError::LNv2(LNv2Error::IncomingPayment(
                "Payment hash is already registered".to_string(),
            ))
        })?;

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
    ) -> std::result::Result<Bolt11Invoice, LightningRpcError> {
        let lnrpc = self.get_lightning_context().await?.lnrpc;

        let response = match description {
            Bolt11InvoiceDescription::Direct(description) => {
                lnrpc
                    .create_invoice(CreateInvoiceRequest {
                        payment_hash: Some(payment_hash),
                        amount_msat: amount.msats,
                        expiry_secs: expiry_time,
                        description: Some(InvoiceDescription::Direct(description)),
                    })
                    .await?
            }
            Bolt11InvoiceDescription::Hash(hash) => {
                lnrpc
                    .create_invoice(CreateInvoiceRequest {
                        payment_hash: Some(payment_hash),
                        amount_msat: amount.msats,
                        expiry_secs: expiry_time,
                        description: Some(InvoiceDescription::Hash(hash)),
                    })
                    .await?
            }
        };

        Bolt11Invoice::from_str(&response.invoice).map_err(|e| {
            LightningRpcError::FailedToGetInvoice {
                failure_reason: e.to_string(),
            }
        })
    }

    pub async fn verify_bolt11_preimage_v2(
        &self,
        payment_hash: sha256::Hash,
        wait: bool,
    ) -> std::result::Result<VerifyResponse, String> {
        let registered_contract = self
            .gateway_db
            .begin_transaction_nc()
            .await
            .load_registered_incoming_contract(PaymentImage::Hash(payment_hash))
            .await
            .ok_or("Unknown payment hash".to_string())?;

        let client = self
            .select_client(registered_contract.federation_id)
            .await
            .map_err(|_| "Not connected to federation".to_string())?
            .into_value();

        let operation_id = OperationId::from_encodable(&registered_contract.contract);

        if !(wait || client.operation_exists(operation_id).await) {
            return Ok(VerifyResponse {
                status: "OK".to_string(),
                settled: false,
                preimage: None,
            });
        }

        let state = client
            .get_first_module::<GatewayClientModuleV2>()
            .expect("Must have client module")
            .await_receive(operation_id)
            .await;

        let preimage = match state {
            FinalReceiveState::Success(preimage) => Ok(preimage),
            FinalReceiveState::Failure => Err("Payment has failed".to_string()),
            FinalReceiveState::Refunded => Err("Payment has been refunded".to_string()),
            FinalReceiveState::Rejected => Err("Payment has been rejected".to_string()),
        }?;

        Ok(VerifyResponse {
            status: "OK".to_string(),
            settled: true,
            preimage: Some(preimage),
        })
    }

    /// Retrieves the persisted `CreateInvoicePayload` from the database
    /// specified by the `payment_hash` and the `ClientHandleArc` specified
    /// by the payload's `federation_id`.
    pub async fn get_registered_incoming_contract_and_client_v2(
        &self,
        payment_image: PaymentImage,
        amount_msats: u64,
    ) -> Result<(IncomingContract, ClientHandleArc)> {
        let registered_incoming_contract = self
            .gateway_db
            .begin_transaction_nc()
            .await
            .load_registered_incoming_contract(payment_image)
            .await
            .ok_or(PublicGatewayError::LNv2(LNv2Error::IncomingPayment(
                "No corresponding decryption contract available".to_string(),
            )))?;

        if registered_incoming_contract.incoming_amount_msats != amount_msats {
            return Err(PublicGatewayError::LNv2(LNv2Error::IncomingPayment(
                "The available decryption contract's amount is not equal to the requested amount"
                    .to_string(),
            )));
        }

        let client = self
            .select_client(registered_incoming_contract.federation_id)
            .await?
            .into_value();

        Ok((registered_incoming_contract.contract, client))
    }
}

#[async_trait]
impl IGatewayClientV2 for Gateway {
    async fn complete_htlc(&self, htlc_response: InterceptPaymentResponse) {
        loop {
            match self.get_lightning_context().await {
                Ok(lightning_context) => {
                    match lightning_context
                        .lnrpc
                        .complete_htlc(htlc_response.clone())
                        .await
                    {
                        Ok(..) => return,
                        Err(err) => {
                            warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Failure trying to complete payment");
                        }
                    }
                }
                Err(err) => {
                    warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Failure trying to complete payment");
                }
            }

            sleep(Duration::from_secs(5)).await;
        }
    }

    async fn is_direct_swap(
        &self,
        invoice: &Bolt11Invoice,
    ) -> anyhow::Result<Option<(IncomingContract, ClientHandleArc)>> {
        let lightning_context = self.get_lightning_context().await?;
        if lightning_context.lightning_public_key == invoice.get_payee_pub_key() {
            let (contract, client) = self
                .get_registered_incoming_contract_and_client_v2(
                    PaymentImage::Hash(*invoice.payment_hash()),
                    invoice
                        .amount_milli_satoshis()
                        .expect("The amount invoice has been previously checked"),
                )
                .await?;
            Ok(Some((contract, client)))
        } else {
            Ok(None)
        }
    }

    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> std::result::Result<[u8; 32], LightningRpcError> {
        let lightning_context = self.get_lightning_context().await?;
        lightning_context
            .lnrpc
            .pay(invoice, max_delay, max_fee)
            .await
            .map(|response| response.preimage.0)
    }

    async fn min_contract_amount(
        &self,
        federation_id: &FederationId,
        amount: u64,
    ) -> anyhow::Result<Amount> {
        Ok(self
            .routing_info_v2(federation_id)
            .await?
            .ok_or(anyhow!("Routing Info not available"))?
            .send_fee_minimum
            .add_to(amount))
    }

    async fn is_lnv1_invoice(&self, invoice: &Bolt11Invoice) -> Option<Spanned<ClientHandleArc>> {
        let rhints = invoice.route_hints();
        match rhints.first().and_then(|rh| rh.0.last()) {
            None => None,
            Some(hop) => match self.get_lightning_context().await {
                Ok(lightning_context) => {
                    if hop.src_node_id != lightning_context.lightning_public_key {
                        return None;
                    }

                    self.federation_manager
                        .read()
                        .await
                        .get_client_for_index(hop.short_channel_id)
                }
                Err(_) => None,
            },
        }
    }

    async fn relay_lnv1_swap(
        &self,
        client: &ClientHandleArc,
        invoice: &Bolt11Invoice,
    ) -> anyhow::Result<FinalReceiveState> {
        let swap_params = SwapParameters {
            payment_hash: *invoice.payment_hash(),
            amount_msat: Amount::from_msats(
                invoice
                    .amount_milli_satoshis()
                    .ok_or(anyhow!("Amountless invoice not supported"))?,
            ),
        };
        let lnv1 = client
            .get_first_module::<GatewayClientModule>()
            .expect("No LNv1 module");
        let operation_id = lnv1.gateway_handle_direct_swap(swap_params).await?;
        let mut stream = lnv1
            .gateway_subscribe_ln_receive(operation_id)
            .await?
            .into_stream();
        let mut final_state = FinalReceiveState::Failure;
        while let Some(update) = stream.next().await {
            match update {
                GatewayExtReceiveStates::Funding => {}
                GatewayExtReceiveStates::FundingFailed { error: _ } => {
                    final_state = FinalReceiveState::Rejected;
                }
                GatewayExtReceiveStates::Preimage(preimage) => {
                    final_state = FinalReceiveState::Success(preimage.0);
                }
                GatewayExtReceiveStates::RefundError {
                    error_message: _,
                    error: _,
                } => {
                    final_state = FinalReceiveState::Failure;
                }
                GatewayExtReceiveStates::RefundSuccess {
                    out_points: _,
                    error: _,
                } => {
                    final_state = FinalReceiveState::Refunded;
                }
            }
        }

        Ok(final_state)
    }
}

#[async_trait]
impl IGatewayClientV1 for Gateway {
    async fn verify_preimage_authentication(
        &self,
        payment_hash: sha256::Hash,
        preimage_auth: sha256::Hash,
        contract: OutgoingContractAccount,
    ) -> std::result::Result<(), OutgoingPaymentError> {
        let mut dbtx = self.gateway_db.begin_transaction().await;
        if let Some(secret_hash) = dbtx.load_preimage_authentication(payment_hash).await {
            if secret_hash != preimage_auth {
                return Err(OutgoingPaymentError {
                    error_type: OutgoingPaymentErrorType::InvalidInvoicePreimage,
                    contract_id: contract.contract.contract_id(),
                    contract: Some(contract),
                });
            }
        } else {
            // Committing the `preimage_auth` to the database can fail if two users try to
            // pay the same invoice at the same time.
            dbtx.save_new_preimage_authentication(payment_hash, preimage_auth)
                .await;
            return dbtx
                .commit_tx_result()
                .await
                .map_err(|_| OutgoingPaymentError {
                    error_type: OutgoingPaymentErrorType::InvoiceAlreadyPaid,
                    contract_id: contract.contract.contract_id(),
                    contract: Some(contract),
                });
        }

        Ok(())
    }

    async fn verify_pruned_invoice(&self, payment_data: PaymentData) -> anyhow::Result<()> {
        let lightning_context = self.get_lightning_context().await?;

        if matches!(payment_data, PaymentData::PrunedInvoice { .. }) {
            ensure!(
                lightning_context.lnrpc.supports_private_payments(),
                "Private payments are not supported by the lightning node"
            );
        }

        Ok(())
    }

    async fn get_routing_fees(&self, federation_id: FederationId) -> Option<RoutingFees> {
        let mut gateway_dbtx = self.gateway_db.begin_transaction_nc().await;
        gateway_dbtx
            .load_federation_config(federation_id)
            .await
            .map(|c| c.lightning_fee.into())
    }

    async fn get_client(&self, federation_id: &FederationId) -> Option<Spanned<ClientHandleArc>> {
        self.federation_manager
            .read()
            .await
            .client(federation_id)
            .cloned()
    }

    async fn get_client_for_invoice(
        &self,
        payment_data: PaymentData,
    ) -> Option<Spanned<ClientHandleArc>> {
        let rhints = payment_data.route_hints();
        match rhints.first().and_then(|rh| rh.0.last()) {
            None => None,
            Some(hop) => match self.get_lightning_context().await {
                Ok(lightning_context) => {
                    if hop.src_node_id != lightning_context.lightning_public_key {
                        return None;
                    }

                    self.federation_manager
                        .read()
                        .await
                        .get_client_for_index(hop.short_channel_id)
                }
                Err(_) => None,
            },
        }
    }

    async fn pay(
        &self,
        payment_data: PaymentData,
        max_delay: u64,
        max_fee: Amount,
    ) -> std::result::Result<PayInvoiceResponse, LightningRpcError> {
        let lightning_context = self.get_lightning_context().await?;

        match payment_data {
            PaymentData::Invoice(invoice) => {
                lightning_context
                    .lnrpc
                    .pay(invoice, max_delay, max_fee)
                    .await
            }
            PaymentData::PrunedInvoice(invoice) => {
                lightning_context
                    .lnrpc
                    .pay_private(invoice, max_delay, max_fee)
                    .await
            }
        }
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptPaymentResponse,
    ) -> std::result::Result<(), LightningRpcError> {
        // Wait until the lightning node is online to complete the HTLC.
        let lightning_context = loop {
            match self.get_lightning_context().await {
                Ok(lightning_context) => break lightning_context,
                Err(err) => {
                    warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Failure trying to complete payment");
                    sleep(Duration::from_secs(5)).await;
                }
            }
        };

        lightning_context.lnrpc.complete_htlc(htlc).await
    }

    async fn is_lnv2_direct_swap(
        &self,
        payment_hash: sha256::Hash,
        amount: Amount,
    ) -> anyhow::Result<
        Option<(
            fedimint_lnv2_common::contracts::IncomingContract,
            ClientHandleArc,
        )>,
    > {
        let (contract, client) = self
            .get_registered_incoming_contract_and_client_v2(
                PaymentImage::Hash(payment_hash),
                amount.msats,
            )
            .await?;
        Ok(Some((contract, client)))
    }
}
