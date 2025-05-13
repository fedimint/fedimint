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

pub mod client;
pub mod config;
pub mod envs;
mod error;
mod events;
mod federation_manager;
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
use bitcoin::{Address, Network, Txid};
use clap::Parser;
use client::GatewayClientBuilder;
use config::GatewayOpts;
pub use config::GatewayParameters;
use envs::{FM_GATEWAY_OVERRIDE_LN_MODULE_CHECK_ENV, FM_GATEWAY_SKIP_WAIT_FOR_SYNC_ENV};
use error::FederationNotConnected;
use events::ALL_GATEWAY_EVENTS;
use federation_manager::FederationManager;
use fedimint_api_client::api::net::Connector;
use fedimint_bip39::{Bip39RootSecretStrategy, Language, Mnemonic};
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client::secret::RootSecretStrategy;
use fedimint_client::{Client, ClientHandleArc};
use fedimint_core::config::FederationId;
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_MINT, LEGACY_HARDCODED_INSTANCE_ID_WALLET, ModuleInstanceId,
    ModuleKind,
};
use fedimint_core::db::{Database, DatabaseTransaction, apply_migrations};
use fedimint_core::envs::is_env_var_set;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::CommonModuleInit;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::task::{TaskGroup, TaskHandle, TaskShutdownToken, sleep};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::{FmtCompact, FmtCompactAnyhow, SafeUrl, Spanned};
use fedimint_core::{
    Amount, BitcoinAmountOrAll, crit, fedimint_build_code_version_env, get_network_for_address,
};
use fedimint_eventlog::{DBTransactionEventLogExt, EventLogId, StructuredPaymentEvents};
use fedimint_gateway_common::{
    BackupPayload, CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, ConnectFedPayload,
    CreateInvoiceForOperatorPayload, CreateOfferPayload, CreateOfferResponse,
    DepositAddressPayload, DepositAddressRecheckPayload, FederationBalanceInfo, FederationConfig,
    FederationInfo, GatewayBalances, GatewayFedConfig, GatewayInfo, GetInvoiceRequest,
    GetInvoiceResponse, LeaveFedPayload, LightningMode, ListTransactionsPayload,
    ListTransactionsResponse, MnemonicResponse, OpenChannelRequest, PayInvoiceForOperatorPayload,
    PayOfferPayload, PayOfferResponse, PaymentLogPayload, PaymentLogResponse, PaymentStats,
    PaymentSummaryPayload, PaymentSummaryResponse, ReceiveEcashPayload, ReceiveEcashResponse,
    SendOnchainRequest, SetFeesPayload, SpendEcashPayload, SpendEcashResponse, V1_API_ENDPOINT,
    WithdrawPayload, WithdrawResponse,
};
use fedimint_gateway_server_db::{GatewayDbtxNcExt as _, get_gatewayd_database_migrations};
use fedimint_gw_client::events::compute_lnv1_stats;
use fedimint_gw_client::pay::{OutgoingPaymentError, OutgoingPaymentErrorType};
use fedimint_gw_client::{GatewayClientModule, GatewayExtPayStates, IGatewayClientV1};
use fedimint_gwv2_client::events::compute_lnv2_stats;
use fedimint_gwv2_client::{EXPIRATION_DELTA_MINIMUM_V2, GatewayClientModuleV2, IGatewayClientV2};
use fedimint_lightning::ldk::{self, GatewayLdkChainSourceConfig};
use fedimint_lightning::lnd::GatewayLndClient;
use fedimint_lightning::{
    CreateInvoiceRequest, ILnRpcClient, InterceptPaymentRequest, InterceptPaymentResponse,
    InvoiceDescription, LightningContext, LightningRpcError, PayInvoiceResponse, PaymentAction,
    RouteHtlcStream,
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
use fedimint_logging::LOG_GATEWAY;
use fedimint_mint_client::{
    MintClientInit, MintClientModule, MintCommonInit, SelectNotesWithAtleastAmount,
    SelectNotesWithExactAmount,
};
use fedimint_wallet_client::{
    WalletClientInit, WalletClientModule, WalletCommonInit, WithdrawState,
};
use futures::stream::StreamExt;
use lightning_invoice::{Bolt11Invoice, RoutingFees};
use rand::thread_rng;
use tokio::sync::RwLock;
use tracing::{debug, info, info_span, warn};

use crate::config::LightningModuleMode;
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

/// The non-lightning default module types that the Gateway supports.
const DEFAULT_MODULE_KINDS: [(ModuleInstanceId, &ModuleKind); 2] = [
    (LEGACY_HARDCODED_INSTANCE_ID_MINT, &MintCommonInit::KIND),
    (LEGACY_HARDCODED_INSTANCE_ID_WALLET, &WalletCommonInit::KIND),
];

#[cfg_attr(doc, aquamarine::aquamarine)]
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    Disconnected -- establish lightning connection --> Connected
///    Connected -- load federation clients --> Running
///    Connected -- not synced to chain --> Syncing
///    Syncing -- load federation clients --> Running
///    Running -- disconnected from lightning node --> Disconnected
///    Running -- shutdown initiated --> ShuttingDown
/// ```
#[derive(Clone, Debug)]
pub enum GatewayState {
    Disconnected,
    Syncing,
    Connected,
    Running { lightning_context: LightningContext },
    ShuttingDown { lightning_context: LightningContext },
}

impl Display for GatewayState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GatewayState::Disconnected => write!(f, "Disconnected"),
            GatewayState::Syncing => write!(f, "Syncing"),
            GatewayState::Connected => write!(f, "Connected"),
            GatewayState::Running { .. } => write!(f, "Running"),
            GatewayState::ShuttingDown { .. } => write!(f, "ShuttingDown"),
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

    // The mnemonic for the gateway
    mnemonic: Mnemonic,

    /// The mode that specifies the lightning connection parameters
    lightning_mode: LightningMode,

    /// The current state of the Gateway.
    state: Arc<RwLock<GatewayState>>,

    /// Builder struct that allows the gateway to build a Fedimint client, which
    /// handles the communication with a federation.
    client_builder: GatewayClientBuilder,

    /// Database for Gateway metadata.
    gateway_db: Database,

    /// A public key representing the identity of the gateway. Private key is
    /// not used.
    gateway_id: PublicKey,

    /// The Gateway's API URL.
    versioned_api: SafeUrl,

    /// The socket the gateway listens on.
    listen: SocketAddr,

    /// The "module mode" of the gateway. Options are LNv1, LNv2, or All.
    lightning_module_mode: LightningModuleMode,

    /// The task group for all tasks related to the gateway.
    task_group: TaskGroup,

    /// The bcrypt password hash used to authenticate the gateway.
    /// This is an `Arc` because `bcrypt::HashParts` does not implement `Clone`.
    bcrypt_password_hash: Arc<bcrypt::HashParts>,

    /// The number of route hints to include in LNv1 invoices.
    num_route_hints: u32,

    /// The Bitcoin network that the Lightning network is configured to.
    network: Network,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("federation_manager", &self.federation_manager)
            .field("state", &self.state)
            .field("client_builder", &self.client_builder)
            .field("gateway_db", &self.gateway_db)
            .field("gateway_id", &self.gateway_id)
            .field("versioned_api", &self.versioned_api)
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
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
        lightning_module_mode: LightningModuleMode,
    ) -> anyhow::Result<Gateway> {
        let versioned_api = api_addr
            .join(V1_API_ENDPOINT)
            .expect("Failed to version gateway API address");
        Gateway::new(
            lightning_mode,
            GatewayParameters {
                listen,
                versioned_api,
                bcrypt_password_hash,
                network,
                num_route_hints,
                lightning_module_mode,
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
            fedimint_rocksdb::RocksDb::open(opts.data_dir.join(DB_FILE)).await?,
            decoders,
        );

        let client_builder =
            GatewayClientBuilder::new(opts.data_dir.clone(), registry, fedimint_mint_client::KIND);

        info!(
            target: LOG_GATEWAY,
            version = %fedimint_build_code_version_env!(),
            "Starting gatewayd",
        );

        let mut gateway_parameters = opts.to_gateway_parameters()?;

        if gateway_parameters.lightning_module_mode != LightningModuleMode::LNv2
            && matches!(opts.mode, LightningMode::Ldk { .. })
        {
            warn!(target: LOG_GATEWAY, "Overriding LDK Gateway to only run LNv2...");
            gateway_parameters.lightning_module_mode = LightningModuleMode::LNv2;
        }

        Gateway::new(
            opts.mode,
            gateway_parameters,
            gateway_db,
            client_builder,
            GatewayState::Disconnected,
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
    ) -> anyhow::Result<Gateway> {
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

        let num_route_hints = gateway_parameters.num_route_hints;
        let network = gateway_parameters.network;

        let task_group = TaskGroup::new();
        task_group.install_kill_handler();

        Ok(Self {
            federation_manager: Arc::new(RwLock::new(FederationManager::new())),
            mnemonic: Self::load_or_generate_mnemonic(&gateway_db).await?,
            lightning_mode,
            state: Arc::new(RwLock::new(gateway_state)),
            client_builder,
            gateway_id: Self::load_or_create_gateway_id(&gateway_db).await,
            gateway_db,
            versioned_api: gateway_parameters.versioned_api,
            listen: gateway_parameters.listen,
            lightning_module_mode: gateway_parameters.lightning_module_mode,
            task_group,
            bcrypt_password_hash: Arc::new(gateway_parameters.bcrypt_password_hash),
            num_route_hints,
            network,
        })
    }

    /// Returns a `PublicKey` that uniquely identifies the Gateway.
    async fn load_or_create_gateway_id(gateway_db: &Database) -> PublicKey {
        let mut dbtx = gateway_db.begin_transaction().await;
        let keypair = dbtx.load_or_create_gateway_keypair().await;
        dbtx.commit_tx().await;
        keypair.public_key()
    }

    pub fn gateway_id(&self) -> PublicKey {
        self.gateway_id
    }

    pub fn versioned_api(&self) -> &SafeUrl {
        &self.versioned_api
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
    ) -> anyhow::Result<TaskShutdownToken> {
        self.verify_lightning_module_mode()?;
        self.register_clients_timer();
        self.load_clients().await?;
        self.start_gateway(runtime);
        // start webserver last to avoid handling requests before fully initialized
        let handle = self.task_group.make_handle();
        run_webserver(Arc::new(self)).await?;
        let shutdown_receiver = handle.make_shutdown_rx();
        Ok(shutdown_receiver)
    }

    /// Verifies that the gateway is not running on mainnet with
    /// `LightningModuleMode::All`
    fn verify_lightning_module_mode(&self) -> anyhow::Result<()> {
        if !is_env_var_set(FM_GATEWAY_OVERRIDE_LN_MODULE_CHECK_ENV)
            && self.network == Network::Bitcoin
            && self.lightning_module_mode == LightningModuleMode::All
        {
            crit!(
                "It is not recommended to run the Gateway with `LightningModuleMode::All`, because LNv2 invoices cannot be paid with LNv1 clients. If you really know what you're doing and want to bypass this, please set FM_GATEWAY_OVERRIDE_LN_MODULE_CHECK"
            );
            return Err(anyhow!(
                "Cannot run gateway with LightningModuleMode::All on mainnet"
            ));
        }

        Ok(())
    }

    /// Begins the task for listening for intercepted payments from the
    /// lightning node.
    fn start_gateway(&self, runtime: Arc<tokio::runtime::Runtime>) {
        const PAYMENT_STREAM_RETRY_SECONDS: u64 = 5;

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

                    let payment_stream_task_group = tg.make_subgroup();
                    let lnrpc_route = self_copy.create_lightning_client(runtime.clone());

                    debug!(target: LOG_GATEWAY, "Establishing lightning payment stream...");
                    let (stream, ln_client) = match lnrpc_route.route_htlcs(&payment_stream_task_group).await
                    {
                        Ok((stream, ln_client)) => (stream, ln_client),
                        Err(err) => {
                            warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Failed to open lightning payment stream");
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
        let (lightning_public_key, lightning_alias, lightning_network, synced_to_chain) =
            match ln_client.parsed_node_info().await {
                Ok((
                    lightning_public_key,
                    lightning_alias,
                    lightning_network,
                    _block_height,
                    synced_to_chain,
                )) => (
                    lightning_public_key,
                    lightning_alias,
                    lightning_network,
                    synced_to_chain,
                ),
                Err(err) => {
                    warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Failed to retrieve Lightning info");
                    return ReceivePaymentStreamAction::RetryAfterDelay;
                }
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

        if self.is_running_lnv1() {
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
                        match client
                            .get_first_module::<GatewayClientModule>()
                            .expect("Must have client module")
                            .gateway_handle_intercepted_htlc(htlc)
                            .await
                        {
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

    /// Returns information about the Gateway back to the client when requested
    /// via the webserver.
    pub async fn handle_get_info(&self) -> AdminResult<GatewayInfo> {
        let GatewayState::Running { lightning_context } = self.get_state().await else {
            return Ok(GatewayInfo {
                federations: vec![],
                federation_fake_scids: None,
                version_hash: fedimint_build_code_version_env!().to_string(),
                lightning_pub_key: None,
                lightning_alias: None,
                gateway_id: self.gateway_id,
                gateway_state: self.state.read().await.to_string(),
                network: self.network,
                block_height: None,
                synced_to_chain: false,
                api: self.versioned_api.clone(),
                lightning_mode: self.lightning_mode.clone(),
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

        let node_info = lightning_context.lnrpc.parsed_node_info().await?;

        Ok(GatewayInfo {
            federations,
            federation_fake_scids: Some(channels),
            version_hash: fedimint_build_code_version_env!().to_string(),
            lightning_pub_key: Some(lightning_context.lightning_public_key.to_string()),
            lightning_alias: Some(lightning_context.lightning_alias.clone()),
            gateway_id: self.gateway_id,
            gateway_state: self.state.read().await.to_string(),
            network: self.network,
            block_height: Some(node_info.3),
            synced_to_chain: node_info.4,
            api: self.versioned_api.clone(),
            lightning_mode: self.lightning_mode.clone(),
        })
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
        let (_, address, _) = self
            .select_client(payload.federation_id)
            .await?
            .value()
            .get_first_module::<WalletClientModule>()
            .expect("Must have client module")
            .allocate_deposit_address_expert_only(())
            .await?;
        Ok(address)
    }

    /// Returns a Bitcoin TXID from a peg-out transaction for a specific
    /// connected federation.
    pub async fn handle_withdraw_msg(
        &self,
        payload: WithdrawPayload,
    ) -> AdminResult<WithdrawResponse> {
        let WithdrawPayload {
            amount,
            address,
            federation_id,
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

        // TODO: Fees should probably be passed in as a parameter
        let (amount, fees) = match amount {
            // If the amount is "all", then we need to subtract the fees from
            // the amount we are withdrawing
            BitcoinAmountOrAll::All => {
                let balance =
                    bitcoin::Amount::from_sat(client.value().get_balance().await.msats / 1000);
                let fees = wallet_module.get_withdraw_fees(&address, balance).await?;
                let withdraw_amount = balance.checked_sub(fees.amount());
                if withdraw_amount.is_none() {
                    return Err(AdminGatewayError::WithdrawError {
                        failure_reason: format!(
                            "Insufficient funds. Balance: {balance} Fees: {fees:?}"
                        ),
                    });
                }
                (withdraw_amount.unwrap(), fees)
            }
            BitcoinAmountOrAll::Amount(amount) => (
                amount,
                wallet_module.get_withdraw_fees(&address, amount).await?,
            ),
        };

        let operation_id = wallet_module.withdraw(&address, amount, fees, ()).await?;
        let mut updates = wallet_module
            .subscribe_withdraw_updates(operation_id)
            .await?
            .into_stream();

        while let Some(update) = updates.next().await {
            match update {
                WithdrawState::Succeeded(txid) => {
                    info!(target: LOG_GATEWAY, amount = %amount, address = %address, "Sent funds");
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

    /// Handles a connection request to join a new federation. The gateway will
    /// download the federation's client configuration, construct a new
    /// client, registers, the gateway with the federation, and persists the
    /// necessary config to reconstruct the client when restarting the gateway.
    pub async fn handle_connect_federation(
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

        #[cfg(feature = "tor")]
        let connector = match &payload.use_tor {
            Some(true) => Connector::tor(),
            Some(false) => Connector::default(),
            None => {
                debug!(target: LOG_GATEWAY, "Missing `use_tor` payload field, defaulting to `Connector::Tcp` variant!");
                Connector::default()
            }
        };

        #[cfg(not(feature = "tor"))]
        let connector = Connector::default();

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
            lightning_fee: PaymentFee::TRANSACTION_FEE_DEFAULT,
            transaction_fee: PaymentFee::TRANSACTION_FEE_DEFAULT,
            connector,
        };

        let recover = payload.recover.unwrap_or(false);
        if recover {
            self.client_builder
                .recover(
                    federation_config.clone(),
                    Arc::new(self.clone()),
                    &self.mnemonic,
                )
                .await?;
        }

        let client = self
            .client_builder
            .build(
                federation_config.clone(),
                Arc::new(self.clone()),
                &self.mnemonic,
            )
            .await?;

        if recover {
            client.wait_for_all_active_state_machines().await?;
        }

        // Instead of using `FederationManager::federation_info`, we manually create
        // federation info here because short channel id is not yet persisted.
        let federation_info = FederationInfo {
            federation_id,
            federation_name: federation_manager.federation_name(&client).await,
            balance_msat: client.get_balance().await,
            config: federation_config.clone(),
        };

        if self.is_running_lnv1() {
            Self::check_lnv1_federation_network(&client, self.network).await?;
            client
                .get_first_module::<GatewayClientModule>()?
                .try_register_with_federation(
                    // Route hints will be updated in the background
                    Vec::new(),
                    GW_ANNOUNCEMENT_TTL,
                    federation_config.lightning_fee.into(),
                    lightning_context,
                    self.versioned_api.clone(),
                    self.gateway_id,
                )
                .await;
        }

        if self.is_running_lnv2() {
            Self::check_lnv2_federation_network(&client, self.network).await?;
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
        dbtx.commit_tx().await;
        debug!(
            target: LOG_GATEWAY,
            federation_id = %federation_id,
            federation_index = %federation_index,
            "Federation connected"
        );

        Ok(federation_info)
    }

    /// Handle a request to have the Gateway leave a federation. The Gateway
    /// will request the federation to remove the registration record and
    /// the gateway will remove the configuration needed to construct the
    /// federation client.
    pub async fn handle_leave_federation(
        &self,
        payload: LeaveFedPayload,
    ) -> AdminResult<FederationInfo> {
        // Lock the federation manager before starting the db transaction to reduce the
        // chance of db write conflicts.
        let mut federation_manager = self.federation_manager.write().await;
        let mut dbtx = self.gateway_db.begin_transaction().await;

        let federation_info = federation_manager
            .leave_federation(payload.federation_id, &mut dbtx.to_ref_nc())
            .await?;

        dbtx.remove_federation_config(payload.federation_id).await;
        dbtx.commit_tx().await;
        Ok(federation_info)
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

    /// Handles an authenticated request for the gateway's mnemonic. This also
    /// returns a vector of federations that are not using the mnemonic
    /// backup strategy.
    pub async fn handle_mnemonic_msg(&self) -> AdminResult<MnemonicResponse> {
        let words = self
            .mnemonic
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

    /// Handles a request to change the lightning or transaction fees for all
    /// federations or a federation specified by the `FederationId`.
    pub async fn handle_set_fees_msg(
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

        for config in &mut fed_configs.values_mut() {
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

            // Check if the lightning fee + transaction fee is higher than the send limit
            let send_fees = lightning_fee + transaction_fee;
            if !self.is_running_lnv1() && send_fees.gt(&PaymentFee::SEND_FEE_LIMIT) {
                return Err(AdminGatewayError::GatewayConfigurationError(format!(
                    "Total Send fees exceeded {}",
                    PaymentFee::SEND_FEE_LIMIT
                )));
            }

            // Check if the transaction fee is higher than the receive limit
            if !self.is_running_lnv1() && transaction_fee.gt(&PaymentFee::RECEIVE_FEE_LIMIT) {
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

        if self.is_running_lnv1() {
            let register_task_group = TaskGroup::new();

            self.register_federations(&fed_configs, &register_task_group)
                .await;
        }

        Ok(())
    }

    /// Generates an onchain address to fund the gateway's lightning node.
    pub async fn handle_get_ln_onchain_address_msg(&self) -> AdminResult<Address> {
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

    /// Instructs the Gateway's Lightning node to open a channel to a peer
    /// specified by `pubkey`.
    pub async fn handle_open_channel_msg(&self, payload: OpenChannelRequest) -> AdminResult<Txid> {
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
    pub async fn handle_close_channels_with_peer_msg(
        &self,
        payload: CloseChannelsWithPeerRequest,
    ) -> AdminResult<CloseChannelsWithPeerResponse> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.close_channels_with_peer(payload).await?;
        Ok(response)
    }

    /// Returns a list of Lightning network channels from the Gateway's
    /// Lightning node.
    pub async fn handle_list_active_channels_msg(
        &self,
    ) -> AdminResult<Vec<fedimint_gateway_common::ChannelInfo>> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.list_active_channels().await?;
        Ok(response.channels)
    }

    /// Send funds from the gateway's lightning node on-chain wallet.
    pub async fn handle_send_onchain_msg(&self, payload: SendOnchainRequest) -> AdminResult<Txid> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.send_onchain(payload).await?;
        Txid::from_str(&response.txid).map_err(|e| AdminGatewayError::WithdrawError {
            failure_reason: format!("Failed to parse withdrawal TXID: {e}"),
        })
    }

    /// Trigger rechecking for deposits on an address
    pub async fn handle_recheck_address_msg(
        &self,
        payload: DepositAddressRecheckPayload,
    ) -> AdminResult<()> {
        self.select_client(payload.federation_id)
            .await?
            .value()
            .get_first_module::<WalletClientModule>()
            .expect("Must have client module")
            .recheck_pegin_address_by_address(payload.address)
            .await?;
        Ok(())
    }

    /// Returns the ecash, lightning, and onchain balances for the gateway and
    /// the gateway's lightning node.
    pub async fn handle_get_balances_msg(&self) -> AdminResult<GatewayBalances> {
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

    // Handles a request the spend the gateway's ecash for a given federation.
    pub async fn handle_spend_ecash_msg(
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

    /// Instructs the gateway to shutdown, but only after all incoming payments
    /// have been handlded.
    pub async fn handle_shutdown_msg(&self, task_group: TaskGroup) -> AdminResult<()> {
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

    /// Queries the client log for payment events and returns to the user.
    pub async fn handle_payment_log_msg(
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
                .filter(|e| e.event_id <= end_position && event_kinds.contains(&e.event_kind))
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

    /// Computes the 24 hour payment summary statistics for this gateway.
    /// Combines the LNv1 and LNv2 stats together.
    pub async fn handle_payment_summary_msg(
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

            if self.is_running_lnv1() && self.is_running_lnv2() {
                let (mut lnv1_outgoing, mut lnv1_incoming) = compute_lnv1_stats(all_events);
                let (mut lnv2_outgoing, mut lnv2_incoming) = compute_lnv2_stats(all_events);
                outgoing.combine(&mut lnv1_outgoing);
                incoming.combine(&mut lnv1_incoming);
                outgoing.combine(&mut lnv2_outgoing);
                incoming.combine(&mut lnv2_incoming);
            } else if self.is_running_lnv1() {
                let (mut lnv1_outgoing, mut lnv1_incoming) = compute_lnv1_stats(all_events);
                outgoing.combine(&mut lnv1_outgoing);
                incoming.combine(&mut lnv1_incoming);
            } else {
                let (mut lnv2_outgoing, mut lnv2_incoming) = compute_lnv2_stats(all_events);
                outgoing.combine(&mut lnv2_outgoing);
                incoming.combine(&mut lnv2_incoming);
            }
        }

        Ok(PaymentSummaryResponse {
            outgoing: PaymentStats::compute(&outgoing),
            incoming: PaymentStats::compute(&incoming),
        })
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

    pub async fn handle_list_transactions_msg(
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
                    let api = self.versioned_api.clone();
                    let gateway_id = self.gateway_id;

                    if let Err(err) = register_task_group
                        .spawn_cancellable("register_federation", async move {
                            let gateway_client = client_arc
                                .get_first_module::<GatewayClientModule>()
                                .expect("No GatewayClientModule exists");
                            gateway_client
                                .try_register_with_federation(
                                    route_hints,
                                    GW_ANNOUNCEMENT_TTL,
                                    federation_config.lightning_fee.into(),
                                    lightning_context,
                                    api,
                                    gateway_id,
                                )
                                .await;
                        })
                        .await
                    {
                        warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Failed to shutdown register federation task");
                    }
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

    /// Loads a mnemonic from the database or generates a new one if the
    /// mnemonic does not exist. Before generating a new mnemonic, this
    /// function will check if a mnemonic has been provided in the environment
    /// variable and use that if provided.
    async fn load_or_generate_mnemonic(gateway_db: &Database) -> AdminResult<Mnemonic> {
        Ok(
            if let Ok(entropy) = Client::load_decodable_client_secret::<Vec<u8>>(gateway_db).await {
                Mnemonic::from_entropy(&entropy)
                    .map_err(|e| AdminGatewayError::MnemonicError(anyhow!(e.to_string())))?
            } else {
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
                    Bip39RootSecretStrategy::<12>::random(&mut thread_rng())
                };

                Client::store_encodable_client_secret(gateway_db, mnemonic.to_entropy())
                    .await
                    .map_err(AdminGatewayError::MnemonicError)?;
                mnemonic
            },
        )
    }

    /// Reads the connected federation client configs from the Gateway's
    /// database and reconstructs the clients necessary for interacting with
    /// connection federations.
    async fn load_clients(&self) -> AdminResult<()> {
        let mut federation_manager = self.federation_manager.write().await;

        let configs = {
            let mut dbtx = self.gateway_db.begin_transaction_nc().await;
            dbtx.load_federation_configs().await
        };

        if let Some(max_federation_index) = configs.values().map(|cfg| cfg.federation_index).max() {
            federation_manager.set_next_index(max_federation_index + 1);
        }

        for (federation_id, config) in configs {
            let federation_index = config.federation_index;
            match Box::pin(Spanned::try_new(
                info_span!(target: LOG_GATEWAY, "client", federation_id  = %federation_id.clone()),
                self.client_builder
                    .build(config, Arc::new(self.clone()), &self.mnemonic),
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
        // Only spawn background registration thread if gateway is running LNv1
        if self.is_running_lnv1() {
            let lightning_module_mode = self.lightning_module_mode;
            info!(target: LOG_GATEWAY, lightning_module_mode = %lightning_module_mode, "Spawning register task...");
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

    /// Verifies that the supplied `network` matches the Bitcoin network in the
    /// connected client's LNv1 configuration.
    async fn check_lnv1_federation_network(
        client: &ClientHandleArc,
        network: Network,
    ) -> AdminResult<()> {
        let federation_id = client.federation_id();
        let config = client.config().await;
        let cfg = config
            .modules
            .values()
            .find(|m| LightningCommonInit::KIND == m.kind)
            .ok_or(AdminGatewayError::ClientCreationError(anyhow!(format!(
                "Federation {federation_id} does not have an LNv1 module"
            ))))?;
        let ln_cfg: &LightningClientConfig = cfg.cast()?;

        if ln_cfg.network.0 != network {
            crit!(
                target: LOG_GATEWAY,
                federation_id = %federation_id,
                network = %network,
                "Incorrect network for federation",
            );
            return Err(AdminGatewayError::ClientCreationError(anyhow!(format!(
                "Unsupported network {}",
                ln_cfg.network
            ))));
        }

        Ok(())
    }

    /// Verifies that the supplied `network` matches the Bitcoin network in the
    /// connected client's LNv2 configuration.
    async fn check_lnv2_federation_network(
        client: &ClientHandleArc,
        network: Network,
    ) -> AdminResult<()> {
        let federation_id = client.federation_id();
        let config = client.config().await;
        let cfg = config
            .modules
            .values()
            .find(|m| fedimint_lnv2_common::LightningCommonInit::KIND == m.kind)
            .ok_or(AdminGatewayError::ClientCreationError(anyhow!(format!(
                "Federation {federation_id} does not have an LNv2 module"
            ))))?;
        let ln_cfg: &fedimint_lnv2_common::config::LightningClientConfig = cfg.cast()?;

        if ln_cfg.network != network {
            crit!(
                target: LOG_GATEWAY,
                federation_id = %federation_id,
                network = %network,
                "Incorrect network for federation",
            );
            return Err(AdminGatewayError::ClientCreationError(anyhow!(format!(
                "Unsupported network {}",
                ln_cfg.network
            ))));
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
        if self.is_running_lnv1() {
            let mut dbtx = self.gateway_db.begin_transaction_nc().await;
            let gateway_keypair = dbtx.load_gateway_keypair_assert_exists().await;

            self.federation_manager
                .read()
                .await
                .unannounce_from_all_federations(gateway_keypair)
                .await;
        }
    }

    fn create_lightning_client(
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
                esplora_server_url,
                bitcoind_rpc_url,
                network,
                lightning_port,
                alias,
            } => {
                let chain_source_config = {
                    match (esplora_server_url, bitcoind_rpc_url) {
                        (Some(esplora_server_url), None) => GatewayLdkChainSourceConfig::Esplora {
                            server_url: SafeUrl::parse(&esplora_server_url.clone())
                                .expect("Could not parse esplora server url"),
                        },
                        (None, Some(bitcoind_rpc_url)) => GatewayLdkChainSourceConfig::Bitcoind {
                            server_url: SafeUrl::parse(&bitcoind_rpc_url.clone())
                                .expect("Could not parse bitcoind rpc url"),
                        },
                        (None, None) => {
                            panic!("Either esplora or bitcoind chain info source must be provided")
                        }
                        (Some(_), Some(bitcoind_rpc_url)) => {
                            warn!(
                                "Esplora and bitcoind connection parameters are both set, using bitcoind..."
                            );
                            GatewayLdkChainSourceConfig::Bitcoind {
                                server_url: SafeUrl::parse(&bitcoind_rpc_url.clone())
                                    .expect("Could not parse bitcoind rpc url"),
                            }
                        }
                    }
                };

                Box::new(
                    ldk::GatewayLdkClient::new(
                        &self.client_builder.data_dir().join(LDK_NODE_DB_FOLDER),
                        chain_source_config,
                        network,
                        lightning_port,
                        alias,
                        self.mnemonic.clone(),
                        runtime,
                    )
                    .expect("Failed to create LDK client"),
                )
            }
        }
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

    /// Helper function for determining if the gateway supports LNv2.
    fn is_running_lnv2(&self) -> bool {
        self.lightning_module_mode == LightningModuleMode::LNv2
            || self.lightning_module_mode == LightningModuleMode::All
    }

    /// Helper function for determining if the gateway supports LNv1.
    fn is_running_lnv1(&self) -> bool {
        self.lightning_module_mode == LightningModuleMode::LNv1
            || self.lightning_module_mode == LightningModuleMode::All
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
}
