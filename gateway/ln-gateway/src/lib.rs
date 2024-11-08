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

pub mod client;
pub mod config;
mod db;
pub mod envs;
mod error;
mod federation_manager;
pub mod gateway_module_v2;
pub mod lightning;
pub mod rpc;
pub mod state_machine;
mod types;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Display;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use bitcoin::hashes::sha256;
use bitcoin::{Address, Network, Txid};
use clap::Parser;
use client::GatewayClientBuilder;
use config::GatewayOpts;
pub use config::GatewayParameters;
use db::{GatewayConfiguration, GatewayConfigurationKey, GatewayDbtxNcExt};
use error::FederationNotConnected;
use federation_manager::FederationManager;
use fedimint_api_client::api::net::Connector;
use fedimint_bip39::{Bip39RootSecretStrategy, Language, Mnemonic};
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::RootSecretStrategy;
use fedimint_client::{Client, ClientHandleArc};
use fedimint_core::config::FederationId;
use fedimint_core::core::{
    ModuleInstanceId, ModuleKind, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::{apply_migrations_server, Database, DatabaseTransaction};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::CommonModuleInit;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::task::{sleep, TaskGroup, TaskHandle, TaskShutdownToken};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::{SafeUrl, Spanned};
use fedimint_core::{fedimint_build_code_version_env, Amount, BitcoinAmountOrAll};
use fedimint_ln_common::config::{GatewayFee, LightningClientConfig};
use fedimint_ln_common::contracts::Preimage;
use fedimint_ln_common::LightningCommonInit;
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::{
    CreateBolt11InvoicePayload, PaymentFee, RoutingInfo, SendPaymentPayload,
};
use fedimint_lnv2_common::Bolt11InvoiceDescription;
use fedimint_mint_client::{
    MintClientInit, MintClientModule, MintCommonInit, SelectNotesWithAtleastAmount,
    SelectNotesWithExactAmount,
};
use fedimint_wallet_client::{
    WalletClientInit, WalletClientModule, WalletCommonInit, WithdrawState,
};
use futures::stream::StreamExt;
use lightning::{
    CloseChannelsWithPeerResponse, CreateInvoiceRequest, ILnRpcClient, InterceptPaymentRequest,
    InterceptPaymentResponse, InvoiceDescription, LightningBuilder, LightningRpcError,
    PaymentAction,
};
use lightning_invoice::{Bolt11Invoice, RoutingFees};
use rand::{thread_rng, Rng};
use rpc::{
    CloseChannelsWithPeerPayload, CreateInvoiceForOperatorPayload, FederationInfo,
    GatewayFedConfig, GatewayInfo, LeaveFedPayload, MnemonicResponse, OpenChannelPayload,
    PayInvoiceForOperatorPayload, ReceiveEcashPayload, ReceiveEcashResponse, SendOnchainPayload,
    SetConfigurationPayload, SpendEcashPayload, SpendEcashResponse, WithdrawResponse,
    V1_API_ENDPOINT,
};
use state_machine::{GatewayClientModule, GatewayExtPayStates};
use tokio::sync::RwLock;
use tracing::{debug, error, info, info_span, warn};

use crate::config::LightningModuleMode;
use crate::db::{get_gatewayd_database_migrations, FederationConfig};
use crate::envs::FM_GATEWAY_MNEMONIC_ENV;
use crate::error::{AdminGatewayError, LNv1Error, LNv2Error, PublicGatewayError};
use crate::gateway_module_v2::GatewayClientModuleV2;
use crate::lightning::{GatewayLightningBuilder, LightningContext, LightningMode, RouteHtlcStream};
use crate::rpc::rpc_server::{hash_password, run_webserver};
use crate::rpc::{
    BackupPayload, ConnectFedPayload, DepositAddressPayload, FederationBalanceInfo,
    GatewayBalances, WithdrawPayload,
};
use crate::types::PrettyInterceptPaymentRequest;

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
///    Initializing -- begin intercepting lightning payments --> Connected
///    Initializing -- gateway needs config --> Configuring
///    Configuring -- configuration set --> Connected
///    Connected -- load federation clients --> Running
///    Connected -- not synced to chain --> Syncing
///    Syncing -- load federation clients --> Running
///    Running -- disconnected from lightning node --> Disconnected
///    Disconnected -- re-established lightning connection --> Connected
/// ```
#[derive(Clone, Debug)]
pub enum GatewayState {
    Initializing,
    Configuring,
    Syncing,
    Connected,
    Running { lightning_context: LightningContext },
    Disconnected,
    ShuttingDown { lightning_context: LightningContext },
}

impl Display for GatewayState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GatewayState::Initializing => write!(f, "Initializing"),
            GatewayState::Configuring => write!(f, "Configuring"),
            GatewayState::Syncing => write!(f, "Syncing"),
            GatewayState::Connected => write!(f, "Connected"),
            GatewayState::Running { .. } => write!(f, "Running"),
            GatewayState::Disconnected => write!(f, "Disconnected"),
            GatewayState::ShuttingDown { .. } => write!(f, "ShuttingDown"),
        }
    }
}

/// The action to take after handling a payment stream.
enum ReceivePaymentStreamAction {
    ImmediatelyRetry,
    RetryAfterDelay,
    NoRetry,
}

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

    /// A public key representing the identity of the gateway. Private key is
    /// not used.
    gateway_id: PublicKey,

    /// The Gateway's API URL.
    versioned_api: SafeUrl,

    /// The socket the gateway listens on.
    listen: SocketAddr,

    /// The "module mode" of the gateway. Options are LNv1, LNv2, or All.
    lightning_module_mode: LightningModuleMode,
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
        lightning_module_mode: LightningModuleMode,
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

        let mut gateway_parameters = opts.to_gateway_parameters()?;

        if gateway_parameters.lightning_module_mode != LightningModuleMode::LNv2
            && matches!(opts.mode, LightningMode::Ldk { .. })
        {
            warn!("Overriding LDK Gateway to only run LNv2...");
            gateway_parameters.lightning_module_mode = LightningModuleMode::LNv2;
        }

        let mnemonic = Self::load_or_generate_mnemonic(&gateway_db).await?;
        Gateway::new(
            Arc::new(GatewayLightningBuilder {
                lightning_mode: opts.mode,
                gateway_db: gateway_db.clone(),
                ldk_data_dir: opts.data_dir.join(LDK_NODE_DB_FOLDER),
                mnemonic,
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
            gateway_id: Self::load_or_create_gateway_id(&gateway_db).await,
            gateway_db,
            versioned_api: gateway_parameters.versioned_api,
            listen: gateway_parameters.listen,
            lightning_module_mode: gateway_parameters.lightning_module_mode,
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

    pub async fn clone_gateway_config(&self) -> Option<GatewayConfiguration> {
        self.gateway_config.read().await.clone()
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
    pub async fn run(self, tg: TaskGroup) -> anyhow::Result<TaskShutdownToken> {
        self.register_clients_timer(&tg);
        self.load_clients().await?;
        self.start_gateway(&tg);
        // start webserver last to avoid handling requests before fully initialized
        let handle = tg.make_handle();
        run_webserver(Arc::new(self), tg).await?;
        let shutdown_receiver = handle.make_shutdown_rx();
        Ok(shutdown_receiver)
    }

    /// Begins the task for listening for intercepted payments from the
    /// lightning node.
    fn start_gateway(&self, task_group: &TaskGroup) {
        const PAYMENT_STREAM_RETRY_SECONDS: u64 = 5;

        let self_copy = self.clone();
        let tg = task_group.clone();
        task_group.spawn(
            "Subscribe to intercepted lightning payments in stream",
            |handle| async move {
                // Repeatedly attempt to establish a connection to the lightning node and create a payment stream, re-trying if the connection is broken.
                loop {
                    if handle.is_shutting_down() {
                        info!("Gateway lightning payment stream handler loop is shutting down");
                        break;
                    }

                    let payment_stream_task_group = tg.make_subgroup();
                    let lnrpc_route = self_copy.lightning_builder.build().await;

                    debug!("Establishing lightning payment stream...");
                    let (stream, ln_client) = match lnrpc_route.route_htlcs(&payment_stream_task_group).await
                    {
                        Ok((stream, ln_client)) => (stream, ln_client),
                        Err(e) => {
                            warn!(?e, "Failed to open lightning payment stream");
                            continue
                        }
                    };

                    // Successful calls to `route_htlcs` establish a connection
                    self_copy.set_gateway_state(GatewayState::Connected).await;
                    info!("Established lightning payment stream");

                    let route_payments_response =
                        self_copy.route_lightning_payments(&handle, stream, ln_client).await;

                    self_copy.set_gateway_state(GatewayState::Disconnected).await;
                    if let Err(e) = payment_stream_task_group.shutdown_join_all(None).await {
                        error!("Lightning payment stream task group shutdown errors: {}", e);
                    }

                    match route_payments_response {
                        ReceivePaymentStreamAction::ImmediatelyRetry => {},
                        ReceivePaymentStreamAction::RetryAfterDelay => {
                            warn!("Disconnected from lightning node. Waiting {PAYMENT_STREAM_RETRY_SECONDS} seconds and trying again");
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
                Err(e) => {
                    warn!("Failed to retrieve Lightning info: {e:?}");
                    return ReceivePaymentStreamAction::RetryAfterDelay;
                }
            };

        let gateway_config = if let Some(config) = self.clone_gateway_config().await {
            config
        } else {
            self.set_gateway_state(GatewayState::Configuring).await;
            info!("Waiting for gateway to be configured...");
            self.gateway_db
                .wait_key_exists(&GatewayConfigurationKey)
                .await
        };

        if gateway_config.network != lightning_network {
            warn!(
                "Lightning node does not match previously configured gateway network : ({:?})",
                gateway_config.network
            );
            info!(
                "Changing gateway network to match lightning node network : ({:?})",
                lightning_network
            );
            self.handle_set_configuration_msg(SetConfigurationPayload {
                password: None,
                network: Some(lightning_network),
                num_route_hints: None,
                routing_fees: None,
                per_federation_routing_fees: None,
            })
            .await
            .expect("Failed to set gateway configuration");
            return ReceivePaymentStreamAction::ImmediatelyRetry;
        }

        if synced_to_chain {
            info!("Gateway is already synced to chain");
        } else {
            self.set_gateway_state(GatewayState::Syncing).await;
            if let Err(e) = ln_client.wait_for_chain_sync().await {
                error!(?e, "Failed to wait for chain sync");
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
        info!("Gateway is running");

        // Runs until the connection to the lightning node breaks or we receive the
        // shutdown signal.
        if handle
            .cancel_on_shutdown(async move {
                loop {
                    let payment_request = tokio::select! {
                        payment_request = stream.next() => {
                            payment_request
                        }
                        () = self.is_shutting_down_safely() => {
                            break;
                        }
                    };

                    // Hold the Gateway state's lock so that it doesn't change before `handle_lightning_payment`.
                    let state_guard = self.state.read().await;
                    let GatewayState::Running { ref lightning_context } = *state_guard else {
                        warn!(
                            ?state_guard,
                            "Gateway isn't in a running state, cannot handle incoming payments."
                        );
                        break;
                    };

                    let payment_request = match payment_request {
                        Some(payment_request) => payment_request,
                        other => {
                            warn!(
                                ?other,
                                "Unexpected response from incoming lightning payment stream. Exiting from loop..."
                            );
                            break;
                        }
                    };

                    self.handle_lightning_payment(payment_request, lightning_context).await;
                }
            })
            .await
            .is_ok()
        {
            warn!("Lightning payment stream connection broken. Gateway is disconnected");
            ReceivePaymentStreamAction::RetryAfterDelay
        } else {
            info!("Received shutdown signal");
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
            "Intercepting lightning payment {}",
            PrettyInterceptPaymentRequest(&payment_request)
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

        if let Err(error) = client
            .get_first_module::<GatewayClientModuleV2>()
            .expect("Must have client module")
            .relay_incoming_htlc(
                htlc_request.payment_hash,
                htlc_request.incoming_chan_id,
                htlc_request.htlc_id,
                contract,
            )
            .await
        {
            error!("Error relaying incoming lightning payment: {error:?}");

            let outcome = InterceptPaymentResponse {
                action: PaymentAction::Cancel,
                payment_hash: htlc_request.payment_hash,
                incoming_chan_id: htlc_request.incoming_chan_id,
                htlc_id: htlc_request.htlc_id,
            };

            if let Err(error) = lightning_context.lnrpc.complete_htlc(outcome).await {
                error!("Error sending HTLC response to lightning node: {error:?}");
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
                if let Ok(htlc) = htlc {
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
                } else {
                    Err(PublicGatewayError::LNv1(LNv1Error::IncomingPayment(
                        "Could not convert InterceptHtlcResult into an HTLC".to_string(),
                    )))
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

        if let Err(error) = lightning_context.lnrpc.complete_htlc(outcome).await {
            error!("Error sending lightning payment response to lightning node: {error:?}");
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
                network: None,
                block_height: None,
                synced_to_chain: false,
                api: self.versioned_api.clone(),
                lightning_mode: None,
            });
        };

        // `GatewayConfiguration` should always exist in the database when we are in the
        // `Running` state.
        let gateway_config = self
            .clone_gateway_config()
            .await
            .expect("Gateway configuration should be set");

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
                    federation_info.federation_index,
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
            network: Some(gateway_config.network),
            block_height: Some(node_info.3),
            synced_to_chain: node_info.4,
            api: self.versioned_api.clone(),
            lightning_mode: self.lightning_builder.lightning_mode(),
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
        let client = self.select_client(federation_id).await?;
        let wallet_module = client.value().get_first_module::<WalletClientModule>()?;

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

        debug!("Handling pay invoice message: {payload:?}");
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
                    debug!("Successfully paid invoice: {contract_id}");
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
                    return Err(PublicGatewayError::LNv1(LNv1Error::OutgoingContract { error: Box::new(error.clone()), message: format!("Cancelled with {error} while paying invoice with contract id {contract_id}") }));
                }
                GatewayExtPayStates::Created => {
                    debug!("Got initial state Created while paying invoice: {contract_id}");
                }
                other => {
                    info!("Got state {other:?} while paying invoice: {contract_id}");
                }
            };
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
                info!("Missing `use_tor` payload field, defaulting to `Connector::Tcp` variant!");
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

        // `GatewayConfiguration` should always exist in the database when we are in the
        // `Running` state.
        let gateway_config = self
            .clone_gateway_config()
            .await
            .expect("Gateway configuration should be set");

        // The gateway deterministically assigns a unique identifier (u64) to each
        // federation connected.
        let federation_index = federation_manager.pop_next_index()?;

        let federation_config = FederationConfig {
            invite_code,
            federation_index,
            timelock_delta: 10,
            fees: gateway_config.routing_fees,
            connector,
        };

        let mnemonic = Self::load_or_generate_mnemonic(&self.gateway_db).await?;
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
            balance_msat: client.get_balance().await,
            federation_index,
            routing_fees: Some(gateway_config.routing_fees.into()),
        };

        if self.is_running_lnv1() {
            Self::check_lnv1_federation_network(&client, gateway_config.network).await?;
            client
                .get_first_module::<GatewayClientModule>()?
                .try_register_with_federation(
                    // Route hints will be updated in the background
                    Vec::new(),
                    GW_ANNOUNCEMENT_TTL,
                    federation_config.fees,
                    lightning_context,
                )
                .await;
        }

        if self.is_running_lnv2() {
            Self::check_lnv2_federation_network(&client, gateway_config.network).await?;
        }

        // no need to enter span earlier, because connect-fed has a span
        federation_manager.add_client(
            federation_index,
            Spanned::new(
                info_span!("client", federation_id=%federation_id.clone()),
                async { client },
            )
            .await,
        );

        let mut dbtx = self.gateway_db.begin_transaction().await;
        dbtx.save_federation_config(&federation_config).await;
        dbtx.commit_tx().await;
        debug!("Federation with ID: {federation_id} connected and assigned federation index: {federation_index}");

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
        let mnemonic = Self::load_or_generate_mnemonic(&self.gateway_db).await?;
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
    ) -> AdminResult<()> {
        let gw_state = self.get_state().await;
        let lightning_network = match gw_state {
            GatewayState::Running { lightning_context } => {
                if network.is_some() && network != Some(lightning_context.lightning_network) {
                    return Err(AdminGatewayError::GatewayConfigurationError(
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
                    return Err(AdminGatewayError::GatewayConfigurationError(
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
            let password = password.ok_or(AdminGatewayError::GatewayConfigurationError(
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
        dbtx.set_gateway_config(&new_gateway_config).await;

        let mut register_federations: Vec<(FederationId, FederationConfig)> = Vec::new();
        if let Some(per_federation_routing_fees) = per_federation_routing_fees {
            for (federation_id, routing_fees) in &per_federation_routing_fees {
                if let Some(mut federation_config) =
                    dbtx.load_federation_config(*federation_id).await
                {
                    federation_config.fees = routing_fees.clone().into();
                    dbtx.save_federation_config(&federation_config).await;
                    register_federations.push((*federation_id, federation_config));
                } else {
                    warn!("Given federation {federation_id} not found for updating routing fees");
                }
            }
        }

        // If 'num_route_hints' is provided, all federations must be re-registered.
        // Otherwise, only those affected by the new fees need to be re-registered.
        let register_task_group = TaskGroup::new();
        if num_route_hints.is_some() {
            let all_federations_configs: Vec<_> =
                dbtx.load_federation_configs().await.into_iter().collect();
            self.register_federations(
                &new_gateway_config,
                &all_federations_configs,
                &register_task_group,
            )
            .await;
        } else {
            self.register_federations(
                &new_gateway_config,
                &register_federations,
                &register_task_group,
            )
            .await;
        }

        dbtx.commit_tx().await;

        let mut curr_gateway_config = self.gateway_config.write().await;
        *curr_gateway_config = Some(new_gateway_config.clone());

        info!("Set GatewayConfiguration successfully.");

        Ok(())
    }

    /// Generates an onchain address to fund the gateway's lightning node.
    pub async fn handle_get_ln_onchain_address_msg(&self) -> AdminResult<Address> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.get_ln_onchain_address().await?;
        Address::from_str(&response.address)
            .map(Address::assume_checked)
            .map_err(|e| {
                AdminGatewayError::Lightning(LightningRpcError::InvalidMetadata {
                    failure_reason: e.to_string(),
                })
            })
    }

    /// Instructs the Gateway's Lightning node to open a channel to a peer
    /// specified by `pubkey`.
    pub async fn handle_open_channel_msg(&self, payload: OpenChannelPayload) -> AdminResult<Txid> {
        let context = self.get_lightning_context().await?;
        let res = context.lnrpc.open_channel(payload).await?;
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
        payload: CloseChannelsWithPeerPayload,
    ) -> AdminResult<CloseChannelsWithPeerResponse> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.close_channels_with_peer(payload).await?;
        Ok(response)
    }

    /// Returns a list of Lightning network channels from the Gateway's
    /// Lightning node.
    pub async fn handle_list_active_channels_msg(
        &self,
    ) -> AdminResult<Vec<lightning::ChannelInfo>> {
        let context = self.get_lightning_context().await?;
        let channels = context.lnrpc.list_active_channels().await?;
        Ok(channels)
    }

    /// Send funds from the gateway's lightning node on-chain wallet.
    pub async fn handle_send_onchain_msg(&self, payload: SendOnchainPayload) -> AdminResult<Txid> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.send_onchain(payload).await?;
        Txid::from_str(&response.txid).map_err(|e| AdminGatewayError::WithdrawError {
            failure_reason: format!("Failed to parse withdrawal TXID: {e}"),
        })
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

            let overspend_amount = notes.total_amount() - payload.amount;
            if overspend_amount != Amount::ZERO {
                warn!(
                    "Selected notes {} worth more than requested",
                    overspend_amount
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

        info!("Spend ecash operation id: {:?}", operation_id);
        info!("Spend ecash notes: {:?}", notes);

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
            if let Err(e) = task_group.shutdown_join_all(Duration::from_secs(180)).await {
                error!(?e, "Error shutting down gateway");
            }
        });
        Ok(())
    }

    /// Registers the gateway with each specified federation.
    async fn register_federations(
        &self,
        gateway_config: &GatewayConfiguration,
        federations: &[(FederationId, FederationConfig)],
        register_task_group: &TaskGroup,
    ) {
        if let Ok(lightning_context) = self.get_lightning_context().await {
            let route_hints = lightning_context
                .lnrpc
                .parsed_route_hints(gateway_config.num_route_hints)
                .await;
            if route_hints.is_empty() {
                warn!("Gateway did not retrieve any route hints, may reduce receive success rate.");
            }

            for (federation_id, federation_config) in federations {
                let fed_manager = self.federation_manager.read().await;
                if let Some(client) = fed_manager.client(federation_id) {
                    let client_arc = client.clone().into_value();
                    let route_hints = route_hints.clone();
                    let lightning_context = lightning_context.clone();
                    let federation_config = federation_config.clone();

                    if let Err(e) = register_task_group
                        .spawn_cancellable("register_federation", async move {
                            let gateway_client = client_arc
                                .get_first_module::<GatewayClientModule>()
                                .expect("No GatewayClientModule exists");
                            gateway_client
                                .try_register_with_federation(
                                    route_hints,
                                    GW_ANNOUNCEMENT_TTL,
                                    federation_config.fees,
                                    lightning_context,
                                )
                                .await;
                        })
                        .await
                    {
                        warn!(?e, "Failed to shutdown register federation task");
                    }
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
    async fn get_gateway_configuration(
        gateway_db: Database,
        gateway_parameters: &GatewayParameters,
    ) -> Option<GatewayConfiguration> {
        let mut dbtx = gateway_db.begin_transaction_nc().await;

        // Always use the gateway configuration from the database if it exists.
        if let Some(gateway_config) = dbtx.load_gateway_config().await {
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
                    info!("Using provided mnemonic from environment variable");
                    Mnemonic::parse_in_normalized(Language::English, words.as_str()).map_err(
                        |e| {
                            AdminGatewayError::MnemonicError(anyhow!(format!(
                                "Seed phrase provided in environment was invalid {e:?}"
                            )))
                        },
                    )?
                } else {
                    info!("Generating mnemonic and writing entropy to client storage");
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

        let mnemonic = Self::load_or_generate_mnemonic(&self.gateway_db).await?;

        for (federation_id, config) in configs {
            let federation_index = config.federation_index;
            if let Ok(client) = Box::pin(Spanned::try_new(
                info_span!("client", federation_id  = %federation_id.clone()),
                self.client_builder
                    .build(config, Arc::new(self.clone()), &mnemonic),
            ))
            .await
            {
                federation_manager.add_client(federation_index, client);
            } else {
                warn!("Failed to load client for federation: {federation_id}");
            }
        }

        Ok(())
    }

    /// Legacy mechanism for registering the Gateway with connected federations.
    /// This will spawn a task that will re-register the Gateway with
    /// connected federations every 8.5 mins. Only registers the Gateway if it
    /// has successfully connected to the Lightning node, so that it can
    /// include route hints in the registration.
    fn register_clients_timer(&self, task_group: &TaskGroup) {
        // Only spawn background registration thread if gateway is running LNv1
        if self.is_running_lnv1() {
            let lightning_module_mode = self.lightning_module_mode;
            info!(?lightning_module_mode, "Spawning register task...");
            let gateway = self.clone();
            let register_task_group = task_group.make_subgroup();
            task_group.spawn_cancellable("register clients", async move {
                loop {
                    let gateway_config = gateway.clone_gateway_config().await;
                    if let Some(gateway_config) = gateway_config {
                        let gateway_state = gateway.get_state().await;
                        if let GatewayState::Running { .. } = &gateway_state {
                            let mut dbtx = gateway.gateway_db.begin_transaction_nc().await;
                            let all_federations_configs: Vec<_> = dbtx.load_federation_configs().await.into_iter().collect();
                            gateway.register_federations(&gateway_config, &all_federations_configs, &register_task_group).await;
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

        if ln_cfg.network != network {
            error!(
                "Federation {federation_id} runs on {} but this gateway supports {network}",
                ln_cfg.network,
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
            error!(
                "Federation {federation_id} runs on {} but this gateway supports {network}",
                ln_cfg.network,
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
        let mut dbtx = self.gateway_db.begin_transaction_nc().await;
        let gateway_keypair = dbtx.load_gateway_keypair_assert_exists().await;

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

        Ok(self
            .public_key_v2(federation_id)
            .await
            .map(|module_public_key| RoutingInfo {
                lightning_public_key: context.lightning_public_key,
                module_public_key,
                send_fee_default: PaymentFee::SEND_FEE_LIMIT,
                // The base fee ensures that the gateway does not loose sats sending the payment due
                // to fees paid on the transaction claiming the outgoing contract or
                // subsequent transactions spending the newly issued ecash
                send_fee_minimum: PaymentFee {
                    base: Amount::from_sats(50),
                    parts_per_million: 5_000,
                },
                expiration_delta_default: 1440,
                expiration_delta_minimum: EXPIRATION_DELTA_MINIMUM_V2,
                // The base fee ensures that the gateway does not loose sats receiving the payment
                // due to fees paid on the transaction funding the incoming contract
                receive_fee: PaymentFee::RECEIVE_FEE_LIMIT,
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
