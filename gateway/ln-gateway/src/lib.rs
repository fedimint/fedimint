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
#![allow(clippy::wildcard_imports)]

pub mod client;
mod config;
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
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Display;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bip39::Mnemonic;
use bitcoin::{Address, Network, Txid};
use bitcoin_hashes::{sha256, Hash};
use clap::Parser;
use client::GatewayClientBuilder;
use config::GatewayOpts;
pub use config::GatewayParameters;
use db::{
    GatewayConfiguration, GatewayConfigurationKey, GatewayDbtxNcExt, GATEWAYD_DATABASE_VERSION,
};
use federation_manager::FederationManager;
use fedimint_api_client::api::net::Connector;
use fedimint_api_client::api::FederationError;
use fedimint_bip39::Bip39RootSecretStrategy;
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::secret::RootSecretStrategy;
use fedimint_client::{Client, ClientHandleArc};
use fedimint_core::config::FederationId;
use fedimint_core::core::{
    ModuleInstanceId, ModuleKind, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::{apply_migrations_server, Database, DatabaseTransaction, DatabaseValue};
use fedimint_core::endpoint_constants::REGISTER_GATEWAY_ENDPOINT;
use fedimint_core::fmt_utils::OptStacktrace;
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
use fedimint_lnv2_client::{
    Bolt11InvoiceDescription, CreateBolt11InvoicePayload, PaymentFee, RoutingInfo,
    SendPaymentPayload, EXPIRATION_DELTA_LIMIT_DEFAULT,
};
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_mint_client::{
    MintClientInit, MintClientModule, MintCommonInit, SelectNotesWithAtleastAmount,
    SelectNotesWithExactAmount,
};
use fedimint_wallet_client::{
    WalletClientInit, WalletClientModule, WalletCommonInit, WithdrawState,
};
use futures::stream::StreamExt;
use gateway_lnrpc::intercept_htlc_response::{Action, Cancel};
use gateway_lnrpc::{CloseChannelsWithPeerResponse, InterceptHtlcRequest, InterceptHtlcResponse};
use lightning::{ILnRpcClient, LightningBuilder, LightningRpcError};
use lightning_invoice::{Bolt11Invoice, RoutingFees};
use rand::{thread_rng, Rng};
use rpc::{
    CloseChannelsWithPeerPayload, CreateInvoiceForSelfPayload, FederationInfo, GatewayFedConfig,
    GatewayInfo, LeaveFedPayload, MnemonicResponse, OpenChannelPayload, PayInvoicePayload,
    ReceiveEcashPayload, ReceiveEcashResponse, SetConfigurationPayload, SpendEcashPayload,
    SpendEcashResponse, SyncToChainPayload, V1_API_ENDPOINT,
};
use state_machine::pay::OutgoingPaymentError;
use state_machine::{GatewayClientModule, GatewayExtPayStates};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, info_span, warn, Instrument};

use crate::db::{get_gatewayd_database_migrations, FederationConfig};
use crate::envs::FM_GATEWAY_MNEMONIC_ENV;
use crate::gateway_lnrpc::create_invoice_request::Description;
use crate::gateway_lnrpc::intercept_htlc_response::Forward;
use crate::gateway_lnrpc::CreateInvoiceRequest;
use crate::gateway_module_v2::GatewayClientModuleV2;
use crate::lightning::{GatewayLightningBuilder, LightningContext, RouteHtlcStream};
use crate::rpc::rpc_server::{hash_password, run_webserver};
use crate::rpc::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, FederationBalanceInfo,
    GatewayBalances, WithdrawPayload,
};
use crate::types::PrettyInterceptHtlcRequest;

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
    ShuttingDown { lightning_context: LightningContext },
}

impl Display for GatewayState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GatewayState::Initializing => write!(f, "Initializing"),
            GatewayState::Configuring => write!(f, "Configuring"),
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
            gateway_id: Self::load_or_create_gateway_id(&gateway_db).await,
            gateway_db,
            versioned_api: gateway_parameters.versioned_api,
            listen: gateway_parameters.listen,
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

    pub async fn get_state(&self) -> GatewayState {
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
    /// begins listening for intercepted HTLCs, and starts the webserver to
    /// service requests.
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

    /// Begins the task for listening for intercepted HTLCs from the Lightning
    /// node.
    fn start_gateway(&self, task_group: &TaskGroup) {
        const HTLC_STREAM_RETRY_SECONDS: u64 = 5;

        let self_copy = self.clone();
        let tg = task_group.clone();
        task_group.spawn(
            "Subscribe to intercepted HTLCs in stream",
            |handle| async move {
                // Repeatedly attempt to establish a connection to the lightning node and create an HTLC stream, re-trying if the connection is broken.
                loop {
                    if handle.is_shutting_down() {
                        info!("Gateway HTLC handler loop is shutting down");
                        break;
                    }

                    let htlc_task_group = tg.make_subgroup();
                    let lnrpc_route = self_copy.lightning_builder.build().await;

                    debug!("Establishing HTLC stream...");
                    let (stream, ln_client) = match lnrpc_route.route_htlcs(&htlc_task_group).await
                    {
                        Ok((stream, ln_client)) => (stream, ln_client),
                        Err(e) => {
                            warn!(?e, "Failed to open HTLC stream");
                            continue
                        }
                    };

                    // Successful calls to route_htlcs establish a connection
                    self_copy.set_gateway_state(GatewayState::Connected).await;
                    info!("Established HTLC stream");

                    let route_htlcs_response =
                        self_copy.route_htlcs(&handle, stream, ln_client).await;

                    self_copy.set_gateway_state(GatewayState::Disconnected).await;
                    if let Err(e) = htlc_task_group.shutdown_join_all(None).await {
                        error!("HTLC task group shutdown errors: {}", e);
                    }

                    match route_htlcs_response {
                        ReceivePaymentStreamAction::ImmediatelyRetry => {},
                        ReceivePaymentStreamAction::RetryAfterDelay => {
                            warn!("Disconnected from Lightning Node. Waiting {HTLC_STREAM_RETRY_SECONDS} seconds and trying again");
                            sleep(Duration::from_secs(HTLC_STREAM_RETRY_SECONDS)).await;
                        }
                        ReceivePaymentStreamAction::NoRetry => break,
                    }
                }
            },
        );
    }

    /// Handles an incoming payment stream from the lightning node after
    /// ensuring the gateway is properly configured. Blocks until the stream
    /// is closed, then returns with the appropriate action to take.
    async fn route_htlcs<'a>(
        &'a self,
        handle: &TaskHandle,
        mut stream: RouteHtlcStream<'a>,
        ln_client: Arc<dyn ILnRpcClient>,
    ) -> ReceivePaymentStreamAction {
        let (lightning_public_key, lightning_alias, lightning_network) =
            match ln_client.parsed_node_info().await {
                Ok((
                    lightning_public_key,
                    lightning_alias,
                    lightning_network,
                    _block_height,
                    _synced_to_chain,
                )) => (lightning_public_key, lightning_alias, lightning_network),
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
                    let state = self.get_state().await;
                    let GatewayState::Running { lightning_context } = state else {
                        warn!(
                            ?state,
                            "Gateway isn't in a running state, cannot handle incoming payments."
                        );
                        break;
                    };

                    let htlc_request = match stream.next().await {
                        Some(Ok(htlc_request)) => htlc_request,
                        other => {
                            warn!(
                                ?other,
                                "Unexpected response from incoming lightning payment stream. Exiting from loop..."
                            );
                            break;
                        }
                    };

                    self.handle_htlc(htlc_request, &lightning_context).await;
                }
            })
            .await
            .is_ok()
        {
            warn!("HTLC Stream Lightning connection broken. Gateway is disconnected");
            ReceivePaymentStreamAction::RetryAfterDelay
        } else {
            info!("Received shutdown signal");
            ReceivePaymentStreamAction::NoRetry
        }
    }

    /// Handles an intercepted HTLC. If the HTLC is part of an incoming payment
    /// to a federation, spawns a state machine and hands off the HTLC to it.
    /// Otherwise, forwards the HTLC to the next hop like a normal lightning
    /// node.
    async fn handle_htlc(
        &self,
        htlc_request: InterceptHtlcRequest,
        lightning_context: &LightningContext,
    ) {
        info!(
            "Intercepting HTLC {}",
            PrettyInterceptHtlcRequest(&htlc_request)
        );

        if self
            .try_handle_htlc_lnv2(&htlc_request, lightning_context)
            .await
            .is_ok()
        {
            return;
        }

        if self.try_handle_htlc_ln_legacy(&htlc_request).await.is_ok() {
            return;
        }

        Self::forward_htlc(htlc_request, lightning_context).await;
    }

    /// Tries to handle an HTLC using the LNv2 protocol.
    /// Returns `Ok` if the HTLC was handled, `Err` otherwise.
    async fn try_handle_htlc_lnv2(
        &self,
        htlc_request: &InterceptHtlcRequest,
        lightning_context: &LightningContext,
    ) -> Result<()> {
        let payment_hash =
            bitcoin_hashes::sha256::Hash::from_slice(&htlc_request.payment_hash).expect("32 bytes");

        // If `payment_hash` has been registered as a LNv2 payment, we try to complete
        // the payment by getting the preimage from the federation
        // using the LNv2 protocol. If the `payment_hash` is not registered,
        // this HTLC is either a legacy Lightning payment or the end destination is not
        // a Fedimint.
        let (contract, client) = self
            .get_registered_incoming_contract_and_client_v2(
                PaymentImage::Hash(payment_hash),
                htlc_request.incoming_amount_msat,
            )
            .await?;

        if let Err(error) = client
            .get_first_module::<GatewayClientModuleV2>()
            .expect("Must have client module")
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
                payment_hash: payment_hash.to_bytes(),
                incoming_chan_id: htlc_request.incoming_chan_id,
                htlc_id: htlc_request.htlc_id,
            };

            if let Err(error) = lightning_context.lnrpc.complete_htlc(outcome).await {
                error!("Error sending HTLC response to lightning node: {error:?}");
            }
        }

        Ok(())
    }

    /// Tries to handle an HTLC using the legacy lightning protocol.
    /// Returns `Ok` if the HTLC was handled, `Err` otherwise.
    async fn try_handle_htlc_ln_legacy(&self, htlc_request: &InterceptHtlcRequest) -> Result<()> {
        // Check if the HTLC corresponds to a federation supporting legacy Lightning.
        let Some(federation_index) = htlc_request.short_channel_id else {
            return Err(GatewayError::IncomingLNv1PaymentError(anyhow::anyhow!(
                "Incoming payment has no last hop short channel id"
            )));
        };

        // Just forward the HTLC if we do not have a federation that
        // corresponds to the short channel id
        let Some(client) = self
            .federation_manager
            .read()
            .await
            .get_client_for_index(federation_index)
        else {
            return Err(GatewayError::IncomingLNv1PaymentError(anyhow::anyhow!(
                "Incoming payment has a last hop short channel id that does not map to a known federation"
            )));
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
                        Ok(_) => return Ok(()),
                        Err(e) => {
                            error!("Got error intercepting HTLC: {e:?}, will retry...");
                        }
                    }
                } else {
                    error!("Got no HTLC result");
                }
                Err(GatewayError::IncomingLNv1PaymentError(anyhow::anyhow!(
                    "Incoming payment could not be handled"
                )))
            })
            .await
    }

    /// Forwards an HTLC to the next hop like a normal lightning node.
    async fn forward_htlc(
        htlc_request: InterceptHtlcRequest,
        lightning_context: &LightningContext,
    ) {
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
            .expect("Must have client module")
            .allocate_deposit_address_expert_only(())
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

    /// Creates an invoice that is directly payable to the gateway's lightning
    /// node.
    async fn handle_create_invoice_for_self_msg(
        &self,
        payload: CreateInvoiceForSelfPayload,
    ) -> Result<Bolt11Invoice> {
        let GatewayState::Running { lightning_context } = self.get_state().await else {
            return Err(GatewayError::Disconnected);
        };

        Bolt11Invoice::from_str(
            &lightning_context
                .lnrpc
                .create_invoice(CreateInvoiceRequest {
                    payment_hash: Vec::new(), /* Empty payment hash indicates an invoice payable
                                               * directly to the gateway. */
                    amount_msat: payload.amount_msats,
                    expiry_secs: payload.expiry_secs,
                    description: payload.description.map(Description::Direct),
                })
                .await?
                .invoice,
        )
        .map_err(|e| GatewayError::UnexpectedState(e.to_string()))
    }

    /// Requests the gateway to pay an outgoing LN invoice using its own funds.
    /// Returns the payment hash's preimage on success.
    async fn handle_pay_invoice_self_msg(&self, payload: PayInvoicePayload) -> Result<Preimage> {
        if let GatewayState::Running { lightning_context } = self.get_state().await {
            let res = lightning_context
                .lnrpc
                .pay(payload.invoice, payload.max_delay, payload.max_fee)
                .await?;
            Ok(Preimage(
                res.preimage.try_into().expect("preimage is 32 bytes"),
            ))
        } else {
            warn!("Gateway is not connected to lightning node, cannot pay invoice");
            Err(GatewayError::Disconnected)
        }
    }

    /// Requests the gateway to pay an outgoing LN invoice on behalf of a
    /// Fedimint client. Returns the payment hash's preimage on success.
    async fn handle_pay_invoice_msg(
        &self,
        payload: fedimint_ln_client::pay::PayInvoicePayload,
    ) -> Result<Preimage> {
        if let GatewayState::Running { .. } = self.get_state().await {
            debug!("Handling pay invoice message: {payload:?}");
            let client = self.select_client(payload.federation_id).await?;
            let contract_id = payload.contract_id;
            let gateway_module = &client.value().get_first_module::<GatewayClientModule>()?;
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

        #[cfg(feature = "tor")]
        let connector = match &payload.use_tor {
            Some(use_tor) => match use_tor {
                true => Connector::tor(),
                false => Connector::default(),
            },
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
            return Err(GatewayError::FederationAlreadyConnected);
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

        Self::check_federation_network(&client, gateway_config.network).await?;

        client
            .get_first_module::<GatewayClientModule>()?
            .register_with_federation(
                // Route hints will be updated in the background
                Vec::new(),
                GW_ANNOUNCEMENT_TTL,
                federation_config.fees,
                lightning_context,
            )
            .await?;

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
        dbtx.commit_tx_result()
            .await
            .map_err(GatewayError::DatabaseError)?;
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
    ) -> Result<FederationInfo> {
        // Lock the federation manager before starting the db transaction to reduce the
        // chance of db write conflicts.
        let mut federation_manager = self.federation_manager.write().await;
        let mut dbtx = self.gateway_db.begin_transaction().await;

        let federation_info = federation_manager
            .leave_federation(payload.federation_id, &mut dbtx.to_ref_nc())
            .await?;

        dbtx.remove_federation_config(payload.federation_id).await;
        dbtx.commit_tx_result()
            .await
            .map_err(GatewayError::DatabaseError)?;
        Ok(federation_info)
    }

    /// Handles a request for the gateway to backup a connected federation's
    /// ecash.
    pub async fn handle_backup_msg(
        &self,
        BackupPayload { federation_id }: BackupPayload,
    ) -> Result<()> {
        let federation_manager = self.federation_manager.read().await;
        let client = federation_manager
            .client(&federation_id)
            .ok_or(GatewayError::ClientCreationError(format!(
                "Gateway does has not connected to {federation_id}"
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
    pub async fn handle_mnemonic_msg(&self) -> Result<MnemonicResponse> {
        let mnemonic = Self::load_or_generate_mnemonic(&self.gateway_db).await?;
        let words = mnemonic
            .word_iter()
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
        if num_route_hints.is_some() {
            let all_federations_configs: Vec<_> =
                dbtx.load_federation_configs().await.into_iter().collect();
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

    /// Generates an onchain address to fund the gateway's lightning node.
    pub async fn handle_get_ln_onchain_address_msg(&self) -> Result<Address> {
        let context = self.get_lightning_context().await?;
        let response = context.lnrpc.get_ln_onchain_address().await?;
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
    ) -> Result<Txid> {
        let context = self.get_lightning_context().await?;
        let res = context
            .lnrpc
            .open_channel(pubkey, host, channel_size_sats, push_amount_sats)
            .await?;
        Txid::from_str(&res.funding_txid).map_err(|e| {
            GatewayError::InvalidMetadata(format!(
                "Received invalid channel funding txid string: {e}"
            ))
        })
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

    /// Returns the ecash, lightning, and onchain balances for the gateway and
    /// the gateway's lightning node.
    pub async fn handle_get_balances_msg(&self) -> Result<GatewayBalances> {
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
        })
    }

    pub async fn handle_sync_to_chain_msg(&self, payload: SyncToChainPayload) -> Result<()> {
        self.get_lightning_context()
            .await?
            .lnrpc
            .sync_to_chain(payload.block_height)
            .await?;

        Ok(())
    }

    // Handles a request the spend the gateway's ecash for a given federation.
    pub async fn handle_spend_ecash_msg(
        &self,
        payload: SpendEcashPayload,
    ) -> Result<SpendEcashResponse> {
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
            .ok_or(anyhow!("Client not found"))?;
        let mint = client.value().get_first_module::<MintClientModule>()?;

        let operation_id = mint.reissue_external_notes(payload.notes, ()).await?;
        if payload.wait {
            let mut updates = mint
                .subscribe_reissue_external_notes(operation_id)
                .await
                .unwrap()
                .into_stream();

            while let Some(update) = updates.next().await {
                if let fedimint_mint_client::ReissueExternalNotesState::Failed(e) = update {
                    return Err(GatewayError::UnexpectedState(e));
                }
            }
        }

        Ok(ReceiveEcashResponse { amount })
    }

    pub async fn handle_shutdown_msg(&self, task_group: TaskGroup) -> Result<()> {
        if let GatewayState::Running { lightning_context } = self.get_state().await {
            self.set_gateway_state(GatewayState::ShuttingDown { lightning_context })
                .await;
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
                            .get_first_module::<GatewayClientModule>()?
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

    /// Loads a mnemonic from the database or generates a new one if the
    /// mnemonic does not exist. Before generating a new mnemonic, this
    /// function will check if a mnemonic has been provided in the environment
    /// variable and use that if provided.
    async fn load_or_generate_mnemonic(gateway_db: &Database) -> Result<Mnemonic> {
        Ok(
            if let Ok(entropy) = Client::load_decodable_client_secret::<Vec<u8>>(gateway_db).await {
                Mnemonic::from_entropy(&entropy)
                    .map_err(|e| GatewayError::ClientCreationError(e.to_string()))?
            } else {
                let mnemonic = if let Ok(words) = std::env::var(FM_GATEWAY_MNEMONIC_ENV) {
                    info!("Using provided mnemonic from environment variable");
                    Mnemonic::parse_in_normalized(bip39::Language::English, words.as_str())
                        .map_err(|e| {
                            GatewayError::InvalidMetadata(format!(
                                "Seed phrase provided in environment variable was invalid: {e:?}"
                            ))
                        })?
                } else {
                    info!("Generating mnemonic and writing entropy to client storage");
                    Bip39RootSecretStrategy::<12>::random(&mut thread_rng())
                };

                Client::store_encodable_client_secret(gateway_db, mnemonic.to_entropy())
                    .await
                    .map_err(|e| GatewayError::ClientCreationError(e.to_string()))?;
                mnemonic
            },
        )
    }

    /// Reads the connected federation client configs from the Gateway's
    /// database and reconstructs the clients necessary for interacting with
    /// connection federations.
    async fn load_clients(&self) -> Result<()> {
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
        let gateway = self.clone();
        task_group.spawn_cancellable("register clients", async move {
            loop {
                let mut registration_result: Option<Result<()>> = None;
                let gateway_config = gateway.clone_gateway_config().await;
                if let Some(gateway_config) = gateway_config {
                    let gateway_state = gateway.get_state().await;
                    if let GatewayState::Running { .. } = &gateway_state {
                        let mut dbtx = gateway.gateway_db.begin_transaction_nc().await;
                        let all_federations_configs: Vec<_> = dbtx.load_federation_configs().await.into_iter().collect();
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
    async fn check_federation_network(client: &ClientHandleArc, network: Network) -> Result<()> {
        let federation_id = client.federation_id();
        let config = client.config().await;
        let cfg = config
            .modules
            .values()
            .find(|m| LightningCommonInit::KIND == m.kind)
            .ok_or_else(|| {
                GatewayError::InvalidMetadata(format!(
                    "Federation {federation_id} does not have a lightning module",
                ))
            })?;
        let ln_cfg: &LightningClientConfig = cfg.cast()?;

        if ln_cfg.network != network {
            error!(
                "Federation {federation_id} runs on {} but this gateway supports {network}",
                ln_cfg.network,
            );
            return Err(GatewayError::UnsupportedNetwork(ln_cfg.network));
        }

        Ok(())
    }

    /// Checks the Gateway's current state and returns the proper
    /// `LightningContext` if it is available. Sometimes the lightning node
    /// will not be connected and this will return an error.
    pub async fn get_lightning_context(&self) -> Result<LightningContext> {
        match self.get_state().await {
            GatewayState::Running { lightning_context }
            | GatewayState::ShuttingDown { lightning_context } => Ok(lightning_context),
            _ => Err(GatewayError::LightningRpcError(
                LightningRpcError::FailedToConnect,
            )),
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
                send_fee_default: PaymentFee::SEND_FEE_LIMIT_DEFAULT,
                // The base fee ensures that the gateway does not loose sats sending the payment due
                // to fees paid on the transaction claiming the outgoing contract or
                // subsequent transactions spending the newly issued ecash
                send_fee_minimum: PaymentFee::SEND_FEE_MINIMUM,
                // The base fee ensures that the gateway does not loose sats receiving the payment
                // due to fees paid on the transaction funding the incoming contract
                receive_fee: PaymentFee::RECEIVE_FEE_LIMIT_DEFAULT,
                expiration_delta_default: EXPIRATION_DELTA_LIMIT_DEFAULT,
                expiration_delta_minimum: EXPIRATION_DELTA_MINIMUM_V2,
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
            .map_err(GatewayError::LNv2OutgoingError)
    }

    /// For the LNv2 protocol, this will create an invoice by fetching it from
    /// the connected Lightning node, then save the payment hash so that
    /// incoming HTLCs can be matched as a receive attempt to a specific
    /// federation.
    async fn create_bolt11_invoice_v2(
        &self,
        payload: CreateBolt11InvoicePayload,
    ) -> Result<Bolt11Invoice> {
        if !payload.contract.verify() {
            return Err(GatewayError::IncomingContractError(
                "The contract is invalid".to_string(),
            ));
        }

        let payment_info = self
            .routing_info_v2(&payload.federation_id)
            .await?
            .ok_or(anyhow!("Unknown federation"))?;

        if payload.contract.commitment.refund_pk != payment_info.module_public_key {
            return Err(GatewayError::IncomingContractError(
                "The incoming contract is keyed to another gateway".to_string(),
            ));
        }

        let contract_amount = payment_info
            .receive_fee
            .subtract_fee(payload.invoice_amount.msats);

        if contract_amount == Amount::ZERO {
            return Err(GatewayError::IncomingContractError(
                "Zero amount incoming contracts are not supported".to_string(),
            ));
        }

        if contract_amount != payload.contract.commitment.amount {
            return Err(GatewayError::IncomingContractError(
                "The contract amount does not pay the correct amount of fees".to_string(),
            ));
        }

        if payload.contract.commitment.expiration <= duration_since_epoch().as_secs() {
            return Err(GatewayError::IncomingContractError(
                "The contract has already expired".to_string(),
            ));
        }

        let payment_hash = match payload.contract.commitment.payment_image {
            PaymentImage::Hash(payment_hash) => payment_hash,
            PaymentImage::Point(..) => {
                return Err(GatewayError::IncomingContractError(
                    "PaymentImage is not a payment hash".to_string(),
                ))
            }
        };

        let invoice = self
            .create_invoice_via_lnrpc_v2(
                payment_hash,
                payload.invoice_amount,
                payload.description.clone(),
                payload.expiry_time,
            )
            .await
            .map_err(|e| anyhow!(e))?;

        let mut dbtx = self.gateway_db.begin_transaction().await;

        if dbtx
            .save_registered_incoming_contract(
                payload.federation_id,
                payload.invoice_amount,
                payload.contract,
            )
            .await
            .is_some()
        {
            return Err(GatewayError::IncomingContractError(
                "Payment hash is already registered".to_string(),
            ));
        }

        dbtx.commit_tx_result()
            .await
            .map_err(|_| anyhow!("Payment hash is already registered"))?;

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
    ) -> Result<Bolt11Invoice> {
        let lnrpc = self.get_lightning_context().await?.lnrpc;

        let response = match description {
            Bolt11InvoiceDescription::Direct(description) => {
                lnrpc
                    .create_invoice(CreateInvoiceRequest {
                        payment_hash: payment_hash.to_byte_array().to_vec(),
                        amount_msat: amount.msats,
                        expiry_secs: expiry_time,
                        description: Some(Description::Direct(description)),
                    })
                    .await?
            }
            Bolt11InvoiceDescription::Hash(hash) => {
                lnrpc
                    .create_invoice(CreateInvoiceRequest {
                        payment_hash: payment_hash.to_byte_array().to_vec(),
                        amount_msat: amount.msats,
                        expiry_secs: expiry_time,
                        description: Some(Description::Hash(hash.to_byte_array().to_vec())),
                    })
                    .await?
            }
        };

        Bolt11Invoice::from_str(&response.invoice).map_err(|e| {
            GatewayError::LightningRpcError(LightningRpcError::FailedToGetInvoice {
                failure_reason: e.to_string(),
            })
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
            .ok_or(anyhow!("No corresponding decryption contract available"))?;

        if registered_incoming_contract.incoming_amount != amount_msats {
            return Err(GatewayError::IncomingContractError(
                "The available decryption contract's amount is not equal to the requested amount"
                    .to_string(),
            ));
        }

        let client = self
            .select_client(registered_incoming_contract.federation_id)
            .await?
            .into_value();

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
    #[error("An incoming payment was unable to be handled by the LNv1 module")]
    IncomingLNv1PaymentError(anyhow::Error),
    #[error("Failed to create client: {}", .0)]
    ClientCreationError(String),
    #[error("Incoming contract error: {}", OptStacktrace(.0))]
    IncomingContractError(String),
    #[error("Error while sending LNv2 payment: {}", OptStacktrace(.0))]
    LNv2OutgoingError(anyhow::Error),
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
