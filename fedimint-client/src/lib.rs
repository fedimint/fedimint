#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::explicit_deref_methods)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]

//! # Client library for fedimintd
//!
//! This library provides a client interface to build module clients that can be
//! plugged together into a fedimint client that exposes a high-level interface
//! for application authors to integrate with.
//!
//! ## Module Clients
//! Module clients have to at least implement the [`module::ClientModule`] trait
//! and a factory struct implementing [`module::init::ClientModuleInit`]. The
//! `ClientModule` trait defines the module types (tx inputs, outputs, etc.) as
//! well as the module's [state machines](sm::State).
//!
//! ### State machines
//! State machines are spawned when starting operations and drive them
//! forward in the background. All module state machines are run by a central
//! [`sm::Executor`]. This means typically starting an operation shall return
//! instantly.
//!
//! For example when doing a deposit the function starting it would immediately
//! return a deposit address and a [`OperationId`] (important concept, highly
//! recommended to read the docs) while spawning a state machine checking the
//! blockchain for incoming bitcoin transactions. The progress of these state
//! machines can then be *observed* using the operation id, but no further user
//! interaction is required to drive them forward.
//!
//! ### State Machine Contexts
//! State machines have access to both a [global
//! context](`DynGlobalClientContext`) as well as to a [module-specific
//! context](module::ClientModule::context).
//!
//! The global context provides access to the federation API and allows to claim
//! module outputs (and transferring the value into the client's wallet), which
//! can be used for refunds.
//!
//! The client-specific context can be used for other purposes, such as
//! supplying config to the state transitions or giving access to other APIs
//! (e.g. LN gateway in case of the lightning module).
//!
//! ### Extension traits
//! The modules themselves can only create inputs and outputs that then have to
//! be combined into transactions by the user and submitted via
//! [`Client::finalize_and_submit_transaction`]. To make this easier most module
//! client implementations contain an extension trait which is implemented for
//! [`Client`] and allows to create the most typical fedimint transactions with
//! a single function call.
//!
//! To observe the progress each high level operation function should be
//! accompanied by one returning a stream of high-level operation updates.
//! Internally that stream queries the state machines belonging to the
//! operation to determine the high-level operation state.
//!
//! ### Primary Modules
//! Not all modules have the ability to hold money for long. E.g. the lightning
//! module and its smart contracts are only used to incentivize LN payments, not
//! to hold money. The mint module on the other hand holds e-cash note and can
//! thus be used to fund transactions and to absorb change. Module clients with
//! this ability should implement [`ClientModule::supports_being_primary`] and
//! related methods.
//!
//! For a example of a client module see [the mint client](https://github.com/fedimint/fedimint/blob/master/modules/fedimint-mint-client/src/lib.rs).
//!
//! ## Client
//! The [`Client`] struct is the main entry point for application authors. It is
//! constructed using its builder which can be obtained via [`Client::builder`].
//! The supported module clients have to be chosen at compile time while the
//! actually available ones will be determined by the config loaded at runtime.
//!
//! For a hacky instantiation of a complete client see the [`ng` subcommand of `fedimint-cli`](https://github.com/fedimint/fedimint/blob/55f9d88e17d914b92a7018de677d16e57ed42bf6/fedimint-cli/src/ng.rs#L56-L73).

use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::future::pending;
use std::ops::{self, Range};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, format_err, Context};
use api::ClientRawFederationApiExt as _;
use async_stream::{stream, try_stream};
use backup::ClientBackup;
use bitcoin::secp256k1;
use db::event_log::{
    self, run_event_log_ordering_task, DBTransactionEventLogExt, Event, EventKind, EventLogEntry,
    EventLogId,
};
use db::{
    apply_migrations_client, apply_migrations_core_client, get_core_client_database_migrations,
    ApiSecretKey, CachedApiVersionSet, CachedApiVersionSetKey, ClientConfigKey, ClientInitStateKey,
    ClientModuleRecovery, ClientPreRootSecretHashKey, EncodedClientSecretKey, InitMode,
    PeerLastApiVersionsSummary, PeerLastApiVersionsSummaryKey,
};
use fedimint_api_client::api::net::Connector;
use fedimint_api_client::api::{
    ApiVersionSet, DynGlobalApi, DynModuleApi, FederationApiExt, GlobalFederationApiWithCacheExt,
    IGlobalFederationApi, WsFederationApi,
};
use fedimint_core::config::{
    ClientConfig, FederationId, GlobalClientConfig, JsonClientConfig, ModuleInitRegistry,
};
use fedimint_core::core::{
    DynInput, DynOutput, IInput, IOutput, IntoDynInstance as _, ModuleInstanceId, ModuleKind,
    OperationId,
};
use fedimint_core::db::{
    AutocommitError, Database, DatabaseKey, DatabaseRecord, DatabaseTransaction,
    IDatabaseTransactionOpsCoreTyped, NonCommittable,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::endpoint_constants::{CLIENT_CONFIG_ENDPOINT, VERSION_ENDPOINT};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::module::{
    ApiAuth, ApiRequestErased, ApiVersion, MultiApiVersion, SupportedApiVersionsSummary,
    SupportedCoreApiVersions, SupportedModuleApiVersions,
};
use fedimint_core::net::api_announcement::SignedApiAnnouncement;
use fedimint_core::task::{Elapsed, MaybeSend, MaybeSync, TaskGroup};
use fedimint_core::transaction::Transaction;
use fedimint_core::util::{backoff_util, retry, BoxStream, NextOrPending, SafeUrl};
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, fedimint_build_code_version_env,
    maybe_add_send, maybe_add_send_sync, runtime, Amount, NumPeers, OutPoint, PeerId,
    TransactionId,
};
pub use fedimint_derive_secret as derivable_secret;
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::{LOG_CLIENT, LOG_CLIENT_NET_API, LOG_CLIENT_RECOVERY};
use futures::stream::FuturesUnordered;
use futures::{Future, Stream, StreamExt};
use meta::{LegacyMetaSource, MetaService};
use module::recovery::RecoveryProgress;
use module::{DynClientModule, FinalClient};
use rand::thread_rng;
use secp256k1::{PublicKey, Secp256k1};
use secret::{DeriveableSecretClientExt, PlainRootSecretStrategy, RootSecretStrategy as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(not(target_family = "wasm"))]
use tokio::runtime::{Handle as RuntimeHandle, RuntimeFlavor};
use tokio::sync::{broadcast, watch, RwLock};
use tokio_stream::wrappers::WatchStream;
use tracing::{debug, error, info, trace, warn};
use transaction::{
    ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputSM, TxSubmissionStatesSM,
};

use crate::api_announcements::{get_api_urls, run_api_announcement_sync, ApiAnnouncementPrefix};
use crate::api_version_discovery::discover_common_api_versions_set;
use crate::backup::Metadata;
use crate::db::{ClientMetadataKey, ClientModuleRecoveryState, InitState, OperationLogKey};
use crate::module::init::{
    ClientModuleInit, ClientModuleInitRegistry, DynClientModuleInit, IClientModuleInit,
};
use crate::module::{ClientModule, ClientModuleRegistry, IClientModule, StateGenerator};
use crate::oplog::OperationLog;
use crate::sm::executor::{
    ActiveOperationStateKeyPrefix, ContextGen, InactiveOperationStateKeyPrefix,
};
use crate::sm::{ClientSMDatabaseTransaction, DynState, Executor, IState, Notifier, State};
use crate::transaction::{
    tx_submission_sm_decoder, ClientInput, ClientOutputBundle, TransactionBuilder,
    TxSubmissionContext, TxSubmissionStates, TRANSACTION_SUBMISSION_MODULE_INSTANCE,
};

pub mod api;

/// Client backup
pub mod backup;
/// Database keys used by the client
pub mod db;
/// Environment variables
pub mod envs;
/// Module client interface definitions
pub mod module;
/// Operation log subsystem of the client
pub mod oplog;
/// Secret handling & derivation
pub mod secret;
/// Client state machine interfaces and executor implementation
pub mod sm;
/// Structs and interfaces to construct Fedimint transactions
pub mod transaction;

mod api_version_discovery;

pub mod api_announcements;
/// Management of meta fields
pub mod meta;

#[derive(Serialize, Deserialize)]
pub struct TxCreatedEvent {
    txid: TransactionId,
    operation_id: OperationId,
}

impl Event for TxCreatedEvent {
    const MODULE: Option<ModuleKind> = None;

    const KIND: EventKind = EventKind::from_static("tx-created");
}

#[derive(Serialize, Deserialize)]
pub struct TxAcceptedEvent {
    txid: TransactionId,
    operation_id: OperationId,
}

impl Event for TxAcceptedEvent {
    const MODULE: Option<ModuleKind> = None;

    const KIND: EventKind = EventKind::from_static("tx-accepted");
}

#[derive(Serialize, Deserialize)]
pub struct TxRejectedEvent {
    txid: TransactionId,
    error: String,
    operation_id: OperationId,
}
impl Event for TxRejectedEvent {
    const MODULE: Option<ModuleKind> = None;

    const KIND: EventKind = EventKind::from_static("tx-rejected");
}

#[derive(Serialize, Deserialize)]
pub struct ModuleRecoveryStarted {
    module_id: ModuleInstanceId,
}

impl Event for ModuleRecoveryStarted {
    const MODULE: Option<ModuleKind> = None;

    const KIND: EventKind = EventKind::from_static("module-recovery-started");
}

#[derive(Serialize, Deserialize)]
pub struct ModuleRecoveryCompleted {
    module_id: ModuleInstanceId,
}

impl Event for ModuleRecoveryCompleted {
    const MODULE: Option<ModuleKind> = None;

    const KIND: EventKind = EventKind::from_static("module-recovery-completed");
}

pub type InstancelessDynClientInput = ClientInput<Box<maybe_add_send_sync!(dyn IInput + 'static)>>;

pub type InstancelessDynClientInputSM =
    ClientInputSM<Box<maybe_add_send_sync!(dyn IState + 'static)>>;

pub type InstancelessDynClientInputBundle = ClientInputBundle<
    Box<maybe_add_send_sync!(dyn IInput + 'static)>,
    Box<maybe_add_send_sync!(dyn IState + 'static)>,
>;

pub type InstancelessDynClientOutput =
    ClientOutput<Box<maybe_add_send_sync!(dyn IOutput + 'static)>>;

pub type InstancelessDynClientOutputSM =
    ClientOutputSM<Box<maybe_add_send_sync!(dyn IState + 'static)>>;
pub type InstancelessDynClientOutputBundle = ClientOutputBundle<
    Box<maybe_add_send_sync!(dyn IOutput + 'static)>,
    Box<maybe_add_send_sync!(dyn IState + 'static)>,
>;

#[derive(Debug, Error)]
pub enum AddStateMachinesError {
    #[error("State already exists in database")]
    StateAlreadyExists,
    #[error("Got {0}")]
    Other(#[from] anyhow::Error),
}

pub type AddStateMachinesResult = Result<(), AddStateMachinesError>;

#[apply(async_trait_maybe_send!)]
pub trait IGlobalClientContext: Debug + MaybeSend + MaybeSync + 'static {
    /// Returned a reference client's module API client, so that module-specific
    /// calls can be made
    fn module_api(&self) -> DynModuleApi;

    async fn client_config(&self) -> ClientConfig;

    /// Returns a reference to the client's federation API client. The provided
    /// interface [`IGlobalFederationApi`] typically does not provide the
    /// necessary functionality, for this extension traits like
    /// [`fedimint_api_client::api::IGlobalFederationApi`] have to be used.
    // TODO: Could be removed in favor of client() except for testing
    fn api(&self) -> &DynGlobalApi;

    fn decoders(&self) -> &ModuleDecoderRegistry;

    /// This function is mostly meant for internal use, you are probably looking
    /// for [`DynGlobalClientContext::claim_inputs`].
    /// Returns transaction id of the funding transaction and an optional
    /// `OutPoint` that represents change if change was added.
    async fn claim_inputs_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        inputs: InstancelessDynClientInputBundle,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)>;

    /// This function is mostly meant for internal use, you are probably looking
    /// for [`DynGlobalClientContext::fund_output`].
    /// Returns transaction id of the funding transaction and an optional
    /// `OutPoint` that represents change if change was added.
    async fn fund_output_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        outputs: InstancelessDynClientOutputBundle,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)>;

    /// Adds a state machine to the executor.
    async fn add_state_machine_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        sm: Box<maybe_add_send_sync!(dyn IState)>,
    ) -> AddStateMachinesResult;

    async fn log_event_json(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        kind: EventKind,
        module: Option<(ModuleKind, ModuleInstanceId)>,
        payload: serde_json::Value,
        transient: bool,
    );

    async fn transaction_update_stream(&self) -> BoxStream<TxSubmissionStatesSM>;
}

#[apply(async_trait_maybe_send!)]
impl IGlobalClientContext for () {
    fn module_api(&self) -> DynModuleApi {
        unimplemented!("fake implementation, only for tests");
    }

    async fn client_config(&self) -> ClientConfig {
        unimplemented!("fake implementation, only for tests");
    }

    fn api(&self) -> &DynGlobalApi {
        unimplemented!("fake implementation, only for tests");
    }

    fn decoders(&self) -> &ModuleDecoderRegistry {
        unimplemented!("fake implementation, only for tests");
    }

    async fn claim_inputs_dyn(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _input: InstancelessDynClientInputBundle,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)> {
        unimplemented!("fake implementation, only for tests");
    }

    async fn fund_output_dyn(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _outputs: InstancelessDynClientOutputBundle,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)> {
        unimplemented!("fake implementation, only for tests");
    }

    async fn add_state_machine_dyn(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _sm: Box<maybe_add_send_sync!(dyn IState)>,
    ) -> AddStateMachinesResult {
        unimplemented!("fake implementation, only for tests");
    }

    async fn log_event_json(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _kind: EventKind,
        _module: Option<(ModuleKind, ModuleInstanceId)>,
        _payload: serde_json::Value,
        _transient: bool,
    ) {
        unimplemented!("fake implementation, only for tests");
    }

    async fn transaction_update_stream(&self) -> BoxStream<TxSubmissionStatesSM> {
        unimplemented!("fake implementation, only for tests");
    }
}

dyn_newtype_define! {
    /// Global state and functionality provided to all state machines running in the
    /// client
    #[derive(Clone)]
    pub DynGlobalClientContext(Arc<IGlobalClientContext>)
}

impl DynGlobalClientContext {
    pub fn new_fake() -> Self {
        DynGlobalClientContext::from(())
    }

    pub async fn await_tx_accepted(&self, query_txid: TransactionId) -> Result<(), String> {
        self.transaction_update_stream()
            .await
            .filter_map(|tx_update| {
                std::future::ready(match tx_update.state {
                    TxSubmissionStates::Accepted(txid) if txid == query_txid => Some(Ok(())),
                    TxSubmissionStates::Rejected(txid, submit_error) if txid == query_txid => {
                        Some(Err(submit_error))
                    }
                    _ => None,
                })
            })
            .next_or_pending()
            .await
    }

    pub async fn claim_inputs<I, S>(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        inputs: ClientInputBundle<I, S>,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)>
    where
        I: IInput + MaybeSend + MaybeSync + 'static,
        S: IState + MaybeSend + MaybeSync + 'static,
    {
        self.claim_inputs_dyn(dbtx, inputs.into_instanceless())
            .await
    }

    /// Creates a transaction with the supplied output and funding added by the
    /// primary module if possible. If the primary module does not have the
    /// required funds this function fails.
    ///
    /// The transactions submission state machine as well as the state machines
    /// for the funding inputs are generated automatically. The caller is
    /// responsible for the output's state machines, should there be any
    /// required.
    pub async fn fund_output<O, S>(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        outputs: ClientOutputBundle<O, S>,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)>
    where
        O: IOutput + MaybeSend + MaybeSync + 'static,
        S: IState + MaybeSend + MaybeSync + 'static,
    {
        self.fund_output_dyn(dbtx, outputs.into_instanceless())
            .await
    }

    /// Allows adding state machines from inside a transition to the executor.
    /// The added state machine belongs to the same module instance as the state
    /// machine from inside which it was spawned.
    pub async fn add_state_machine<S>(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        sm: S,
    ) -> AddStateMachinesResult
    where
        S: State + MaybeSend + MaybeSync + 'static,
    {
        self.add_state_machine_dyn(dbtx, box_up_state(sm)).await
    }

    async fn log_event<E>(&self, dbtx: &mut ClientSMDatabaseTransaction<'_, '_>, event: E)
    where
        E: Event + Send,
    {
        self.log_event_json(
            dbtx,
            E::KIND,
            E::MODULE.map(|m| (m, dbtx.module_id())),
            serde_json::to_value(&event).expect("Payload serialization can't fail"),
            <E as Event>::PERSIST,
        )
        .await;
    }
}

fn states_to_instanceless_dyn<S: IState + MaybeSend + MaybeSync + 'static>(
    state_gen: StateGenerator<S>,
) -> StateGenerator<Box<maybe_add_send_sync!(dyn IState + 'static)>> {
    Arc::new(move |txid, out_idxs| {
        let states: Vec<S> = state_gen(txid, out_idxs);
        states
            .into_iter()
            .map(|state| box_up_state(state))
            .collect()
    })
}

/// Not sure why I couldn't just directly call `Box::new` ins
/// [`states_to_instanceless_dyn`], but this fixed it.
fn box_up_state(state: impl IState + 'static) -> Box<maybe_add_send_sync!(dyn IState + 'static)> {
    Box::new(state)
}

impl<T> From<Arc<T>> for DynGlobalClientContext
where
    T: IGlobalClientContext,
{
    fn from(inner: Arc<T>) -> Self {
        DynGlobalClientContext { inner }
    }
}

// TODO: impl `Debug` for `Client` and derive here
impl Debug for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Client")
    }
}

/// Global state given to a specific client module and state. It is aware inside
/// which module instance and operation it is used and to avoid module being
/// aware of their instance id etc.
#[derive(Clone, Debug)]
struct ModuleGlobalClientContext {
    client: Arc<Client>,
    module_instance_id: ModuleInstanceId,
    operation: OperationId,
}

#[apply(async_trait_maybe_send!)]
impl IGlobalClientContext for ModuleGlobalClientContext {
    fn module_api(&self) -> DynModuleApi {
        self.api().with_module(self.module_instance_id)
    }

    fn api(&self) -> &DynGlobalApi {
        &self.client.api
    }

    fn decoders(&self) -> &ModuleDecoderRegistry {
        self.client.decoders()
    }

    async fn client_config(&self) -> ClientConfig {
        self.client.config().await
    }

    async fn claim_inputs_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        inputs: InstancelessDynClientInputBundle,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)> {
        let tx_builder =
            TransactionBuilder::new().with_inputs(inputs.into_dyn(self.module_instance_id));

        self.client
            .finalize_and_submit_transaction_inner(
                &mut dbtx.global_tx().to_ref_nc(),
                self.operation,
                tx_builder,
            )
            .await
    }

    async fn fund_output_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        outputs: InstancelessDynClientOutputBundle,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)> {
        let tx_builder =
            TransactionBuilder::new().with_outputs(outputs.into_dyn(self.module_instance_id));

        self.client
            .finalize_and_submit_transaction_inner(
                &mut dbtx.global_tx().to_ref_nc(),
                self.operation,
                tx_builder,
            )
            .await
    }

    async fn add_state_machine_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        sm: Box<maybe_add_send_sync!(dyn IState)>,
    ) -> AddStateMachinesResult {
        let state = DynState::from_parts(self.module_instance_id, sm);

        self.client
            .executor
            .add_state_machines_dbtx(&mut dbtx.global_tx().to_ref_nc(), vec![state])
            .await
    }

    async fn transaction_update_stream(&self) -> BoxStream<TxSubmissionStatesSM> {
        self.client.transaction_update_stream(self.operation).await
    }

    async fn log_event_json(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        kind: EventKind,
        module: Option<(ModuleKind, ModuleInstanceId)>,
        payload: serde_json::Value,
        transient: bool,
    ) {
        self.client
            .log_event_raw_dbtx(
                dbtx.global_tx(),
                kind,
                module,
                serde_json::to_vec(&payload).expect("Serialization can't fail"),
                transient,
            )
            .await;
    }
}

fn states_add_instance(
    module_instance_id: ModuleInstanceId,
    state_gen: StateGenerator<Box<maybe_add_send_sync!(dyn IState + 'static)>>,
) -> StateGenerator<DynState> {
    Arc::new(move |txid, out_idx| {
        let states = state_gen(txid, out_idx);
        Iterator::collect(
            states
                .into_iter()
                .map(|state| DynState::from_parts(module_instance_id, state)),
        )
    })
}

/// User handle to the [`Client`] instance
///
/// On the drop of [`ClientHandle`] the client will be shut-down, and resources
/// it used freed.
///
/// Notably it [`ops::Deref`]s to the [`Client`] where most
/// methods live.
///
/// Put this in an Arc to clone it (see [`ClientHandleArc`]).
#[derive(Debug)]
pub struct ClientHandle {
    inner: Option<Arc<Client>>,
}

/// An alias for a reference counted [`ClientHandle`]
pub type ClientHandleArc = Arc<ClientHandle>;

impl ClientHandle {
    /// Create
    fn new(inner: Arc<Client>) -> Self {
        ClientHandle {
            inner: inner.into(),
        }
    }

    fn as_inner(&self) -> &Arc<Client> {
        self.inner.as_ref().expect("Inner always set")
    }

    pub fn start_executor(&self) {
        self.as_inner().start_executor();
    }

    /// Shutdown the client.
    pub async fn shutdown(mut self) {
        self.shutdown_inner().await;
    }

    async fn shutdown_inner(&mut self) {
        let Some(inner) = self.inner.take() else {
            error!("ClientHandleShared::shutdown called twice");
            return;
        };
        inner.executor.stop_executor();
        let db = inner.db.clone();
        debug!(target: LOG_CLIENT, "Waiting for client task group to shut down");
        if let Err(err) = inner
            .task_group
            .clone()
            .shutdown_join_all(Some(Duration::from_secs(30)))
            .await
        {
            warn!(target: LOG_CLIENT, %err, "Error waiting for client task group to shut down");
        }

        let client_strong_count = Arc::strong_count(&inner);
        debug!(target: LOG_CLIENT, "Dropping last handle to Client");
        // We are sure that no background tasks are running in the client anymore, so we
        // can drop the (usually) last inner reference.
        drop(inner);

        if client_strong_count != 1 {
            debug!(target: LOG_CLIENT, count = client_strong_count - 1, LOG_CLIENT, "External Client references remaining after last handle dropped");
        }

        let db_strong_count = db.strong_count();
        if db_strong_count != 1 {
            debug!(target: LOG_CLIENT, count = db_strong_count - 1, "External DB references remaining after last handle dropped");
        }
        trace!(target: LOG_CLIENT, "Dropped last handle to Client");
    }

    /// Restart the client
    ///
    /// Returns false if there are other clones of [`ClientHandle`], or starting
    /// the client again failed for some reason.
    ///
    /// Notably it will re-use the original [`Database`] handle, and not attempt
    /// to open it again.
    pub async fn restart(self) -> anyhow::Result<ClientHandle> {
        let (builder, config, api_secret, root_secret) = {
            let client = self
                .inner
                .as_ref()
                .ok_or_else(|| format_err!("Already stopped"))?;
            let builder = ClientBuilder::from_existing(client);
            let config = client.config().await;
            let api_secret = client.api_secret.clone();
            let root_secret = client.root_secret.clone();

            (builder, config, api_secret, root_secret)
        };
        self.shutdown().await;

        builder.build(root_secret, config, api_secret, false).await
    }
}

impl ops::Deref for ClientHandle {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().expect("Must have inner client set")
    }
}

impl ClientHandle {
    pub(crate) fn downgrade(&self) -> ClientWeak {
        ClientWeak {
            inner: Arc::downgrade(self.inner.as_ref().expect("Inner always set")),
        }
    }
}

/// Internal self-reference to [`Client`]
#[derive(Debug, Clone)]
pub(crate) struct ClientStrong {
    inner: Arc<Client>,
}

impl ops::Deref for ClientStrong {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

/// Like [`ClientStrong`] but using a [`Weak`] handle to [`Client`]
///
/// This is not meant to be used by external code.
#[derive(Debug, Clone)]
pub(crate) struct ClientWeak {
    inner: Weak<Client>,
}

impl ClientWeak {
    pub fn upgrade(&self) -> Option<ClientStrong> {
        Weak::upgrade(&self.inner).map(|inner| ClientStrong { inner })
    }
}

/// We need a separate drop implementation for `Client` that triggers
/// `Executor::stop_executor` even though the `Drop` implementation of
/// `ExecutorInner` should already take care of that. The reason is that as long
/// as the executor task is active there may be a cycle in the
/// `Arc<Client>`s such that at least one `Executor` never gets dropped.
impl Drop for ClientHandle {
    fn drop(&mut self) {
        if self.inner.is_none() {
            return;
        }

        // We can't use block_on in single-threaded mode or wasm
        #[cfg(target_family = "wasm")]
        let can_block = false;
        #[cfg(not(target_family = "wasm"))]
        // nosemgrep: ban-raw-block-on
        let can_block = RuntimeHandle::current().runtime_flavor() != RuntimeFlavor::CurrentThread;
        if !can_block {
            let inner = self.inner.take().expect("Must have inner client set");
            inner.executor.stop_executor();
            if cfg!(target_family = "wasm") {
                error!(target: LOG_CLIENT, "Automatic client shutdown is not possible on wasm, call ClientHandle::shutdown manually.");
            } else {
                error!(target: LOG_CLIENT, "Automatic client shutdown is not possible on current thread runtime, call ClientHandle::shutdown manually.");
            }
            return;
        }

        debug!(target: LOG_CLIENT, "Shutting down the Client on last handle drop");
        #[cfg(not(target_family = "wasm"))]
        runtime::block_in_place(|| {
            runtime::block_on(self.shutdown_inner());
        });
    }
}

/// List of core api versions supported by the implementation.
/// Notably `major` version is the one being supported, and corresponding
/// `minor` version is the one required (for given `major` version).
const SUPPORTED_CORE_API_VERSIONS: &[fedimint_core::module::ApiVersion] =
    &[ApiVersion { major: 0, minor: 0 }];

pub type ModuleGlobalContextGen = ContextGen;

/// Resources particular to a module instance
pub struct ClientModuleInstance<'m, M: ClientModule> {
    /// Instance id of the module
    pub id: ModuleInstanceId,
    /// Module-specific DB
    pub db: Database,
    /// Module-specific API
    pub api: DynModuleApi,

    module: &'m M,
}

impl<'m, M: ClientModule> ClientModuleInstance<'m, M> {
    /// Get a reference to the module
    pub fn inner(&self) -> &'m M {
        self.module
    }
}

impl<'m, M> ops::Deref for ClientModuleInstance<'m, M>
where
    M: ClientModule,
{
    type Target = M;

    fn deref(&self) -> &Self::Target {
        self.module
    }
}

/// Main client type
///
/// A handle and API to interacting with a single federation. End user
/// applications that want to support interacting with multiple federations at
/// the same time, will need to instantiate and manage multiple instances of
/// this struct.
///
/// Under the hood it is starting and managing service tasks, state machines,
/// database and other resources required.
///
/// This type is shared externally and internally, and
/// [`ClientHandle`] is responsible for external lifecycle management
/// and resource freeing of the [`Client`].
pub struct Client {
    config: RwLock<ClientConfig>,
    api_secret: Option<String>,
    decoders: ModuleDecoderRegistry,
    db: Database,
    federation_id: FederationId,
    federation_meta: BTreeMap<String, String>,
    primary_module_instance: ModuleInstanceId,
    modules: ClientModuleRegistry,
    module_inits: ClientModuleInitRegistry,
    executor: Executor,
    api: DynGlobalApi,
    root_secret: DerivableSecret,
    operation_log: OperationLog,
    secp_ctx: Secp256k1<secp256k1::All>,
    meta_service: Arc<MetaService>,
    connector: Connector,

    task_group: TaskGroup,

    /// Updates about client recovery progress
    client_recovery_progress_receiver:
        watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryProgress>>,

    /// Internal client sender to wake up log ordering task every time a
    /// (unuordered) log event is added.
    log_ordering_wakeup_tx: watch::Sender<()>,
    /// Receiver for events fired every time (ordered) log event is added.
    log_event_added_rx: watch::Receiver<()>,
    log_event_added_transient_tx: broadcast::Sender<EventLogEntry>,
}

impl Client {
    /// Initialize a client builder that can be configured to create a new
    /// client.
    pub async fn builder(db: Database) -> anyhow::Result<ClientBuilder> {
        apply_migrations_core_client(
            &db,
            "fedimint-client".to_string(),
            get_core_client_database_migrations(),
        )
        .await?;
        Ok(ClientBuilder::new(db))
    }

    pub fn api(&self) -> &(dyn IGlobalFederationApi + 'static) {
        self.api.as_ref()
    }

    pub fn api_clone(&self) -> DynGlobalApi {
        self.api.clone()
    }

    /// Get the [`TaskGroup`] that is tied to Client's lifetime.
    pub fn task_group(&self) -> &TaskGroup {
        &self.task_group
    }

    /// Useful for our CLI tooling, not meant for external use
    #[doc(hidden)]
    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    pub async fn get_config_from_db(db: &Database) -> Option<ClientConfig> {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.get_value(&ClientConfigKey).await
    }

    pub async fn get_api_secret_from_db(db: &Database) -> Option<String> {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.get_value(&ApiSecretKey).await
    }

    pub async fn store_encodable_client_secret<T: Encodable>(
        db: &Database,
        secret: T,
    ) -> anyhow::Result<()> {
        let mut dbtx = db.begin_transaction().await;

        // Don't overwrite an existing secret
        if dbtx.get_value(&EncodedClientSecretKey).await.is_some() {
            bail!("Encoded client secret already exists, cannot overwrite")
        }

        let encoded_secret = T::consensus_encode_to_vec(&secret);
        dbtx.insert_entry(&EncodedClientSecretKey, &encoded_secret)
            .await;
        dbtx.commit_tx().await;
        Ok(())
    }

    pub async fn load_decodable_client_secret<T: Decodable>(db: &Database) -> anyhow::Result<T> {
        let Some(secret) = Self::load_decodable_client_secret_opt(db).await? else {
            bail!("Encoded client secret not present in DB")
        };

        Ok(secret)
    }
    pub async fn load_decodable_client_secret_opt<T: Decodable>(
        db: &Database,
    ) -> anyhow::Result<Option<T>> {
        let mut dbtx = db.begin_transaction_nc().await;

        let client_secret = dbtx.get_value(&EncodedClientSecretKey).await;

        Ok(match client_secret {
            Some(client_secret) => Some(
                T::consensus_decode(&mut client_secret.as_slice(), &ModuleRegistry::default())
                    .map_err(|e| anyhow!("Decoding failed: {e}"))?,
            ),
            None => None,
        })
    }

    pub async fn load_or_generate_client_secret(db: &Database) -> anyhow::Result<[u8; 64]> {
        let client_secret =
            if let Ok(secret) = Self::load_decodable_client_secret::<[u8; 64]>(db).await {
                secret
            } else {
                let secret = PlainRootSecretStrategy::random(&mut thread_rng());
                Self::store_encodable_client_secret(db, secret)
                    .await
                    .expect("Storing client secret must work");
                secret
            };
        Ok(client_secret)
    }

    pub async fn is_initialized(db: &Database) -> bool {
        Self::get_config_from_db(db).await.is_some()
    }

    pub fn start_executor(self: &Arc<Self>) {
        debug!(
            "Starting fedimint client executor (version: {})",
            fedimint_build_code_version_env!()
        );
        self.executor.start_executor(self.context_gen());
    }

    pub fn federation_id(&self) -> FederationId {
        self.federation_id
    }

    fn context_gen(self: &Arc<Self>) -> ModuleGlobalContextGen {
        let client_inner = Arc::downgrade(self);
        Arc::new(move |module_instance, operation| {
            ModuleGlobalClientContext {
                client: client_inner
                    .clone()
                    .upgrade()
                    .expect("ModuleGlobalContextGen called after client was dropped"),
                module_instance_id: module_instance,
                operation,
            }
            .into()
        })
    }

    pub async fn config(&self) -> ClientConfig {
        self.config.read().await.clone()
    }

    pub fn api_secret(&self) -> &Option<String> {
        &self.api_secret
    }

    pub fn decoders(&self) -> &ModuleDecoderRegistry {
        &self.decoders
    }

    /// Returns a reference to the module, panics if not found
    fn get_module(&self, instance: ModuleInstanceId) -> &maybe_add_send_sync!(dyn IClientModule) {
        self.try_get_module(instance)
            .expect("Module instance not found")
    }

    fn try_get_module(
        &self,
        instance: ModuleInstanceId,
    ) -> Option<&maybe_add_send_sync!(dyn IClientModule)> {
        Some(self.modules.get(instance)?.as_ref())
    }

    pub fn has_module(&self, instance: ModuleInstanceId) -> bool {
        self.modules.get(instance).is_some()
    }

    /// Returns the input amount and output amount of a transaction
    ///
    /// # Panics
    /// If any of the input or output versions in the transaction builder are
    /// unknown by the respective module.
    fn transaction_builder_balance(&self, builder: &TransactionBuilder) -> (Amount, Amount) {
        // FIXME: prevent overflows, currently not suitable for untrusted input
        let mut in_amount = Amount::ZERO;
        let mut out_amount = Amount::ZERO;
        let mut fee_amount = Amount::ZERO;

        for input in builder.inputs() {
            let module = self.get_module(input.input.module_instance_id());

            let item_fee = module.input_fee(input.amount, &input.input).expect(
                "We only build transactions with input versions that are supported by the module",
            );

            in_amount += input.amount;
            fee_amount += item_fee;
        }

        for output in builder.outputs() {
            let module = self.get_module(output.output.module_instance_id());

            let item_fee = module.output_fee(output.amount, &output.output).expect(
                "We only build transactions with output versions that are supported by the module",
            );

            out_amount += output.amount;
            fee_amount += item_fee;
        }

        (in_amount, out_amount + fee_amount)
    }

    pub fn get_internal_payment_markers(&self) -> anyhow::Result<(PublicKey, u64)> {
        Ok((self.federation_id().to_fake_ln_pub_key(&self.secp_ctx)?, 0))
    }

    pub fn get_meta(&self, key: &str) -> Option<String> {
        self.federation_meta.get(key).cloned()
    }

    fn root_secret(&self) -> DerivableSecret {
        self.root_secret.clone()
    }

    pub async fn add_state_machines(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        states: Vec<DynState>,
    ) -> AddStateMachinesResult {
        self.executor.add_state_machines_dbtx(dbtx, states).await
    }

    // TODO: implement as part of [`OperationLog`]
    pub async fn get_active_operations(&self) -> HashSet<OperationId> {
        let active_states = self.executor.get_active_states().await;
        let mut active_operations = HashSet::with_capacity(active_states.len());
        let mut dbtx = self.db().begin_transaction_nc().await;
        for (state, _) in active_states {
            let operation_id = state.operation_id();
            if dbtx
                .get_value(&OperationLogKey { operation_id })
                .await
                .is_some()
            {
                active_operations.insert(operation_id);
            }
        }
        active_operations
    }

    pub fn operation_log(&self) -> &OperationLog {
        &self.operation_log
    }

    /// Get the meta manager to read meta fields.
    pub fn meta_service(&self) -> &Arc<MetaService> {
        &self.meta_service
    }

    /// Adds funding to a transaction or removes over-funding via change.
    async fn finalize_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        mut partial_transaction: TransactionBuilder,
    ) -> anyhow::Result<(Transaction, Vec<DynState>, Range<u64>)> {
        let (input_amount, output_amount) = self.transaction_builder_balance(&partial_transaction);

        let (added_input_bundle, change_outputs) = self
            .primary_module()
            .create_final_inputs_and_outputs(
                self.primary_module_instance,
                dbtx,
                operation_id,
                input_amount,
                output_amount,
            )
            .await?;

        // This is the range of  outputs that will be added to the transaction
        // in order to balance it. Notice that it may stay empty in case the transaction
        // is already balanced.
        let change_range = Range {
            start: partial_transaction.outputs().count() as u64,
            end: (partial_transaction.outputs().count() + change_outputs.outputs.len()) as u64,
        };

        partial_transaction = partial_transaction
            .with_inputs(added_input_bundle)
            .with_outputs(change_outputs);

        let (input_amount, output_amount) = self.transaction_builder_balance(&partial_transaction);

        assert!(input_amount >= output_amount, "Transaction is underfunded");

        let (tx, states) = partial_transaction.build(&self.secp_ctx, thread_rng());

        Ok((tx, states, change_range))
    }

    /// Add funding and/or change to the transaction builder as needed, finalize
    /// the transaction and submit it to the federation.
    ///
    /// ## Errors
    /// The function will return an error if the operation with given ID already
    /// exists.
    ///
    /// ## Panics
    /// The function will panic if the database transaction collides with
    /// other and fails with others too often, this should not happen except for
    /// excessively concurrent scenarios.
    pub async fn finalize_and_submit_transaction<F, M>(
        &self,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta: F,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)>
    where
        F: Fn(TransactionId, Vec<OutPoint>) -> M + Clone + MaybeSend + MaybeSync,
        M: serde::Serialize + MaybeSend,
    {
        let operation_type = operation_type.to_owned();

        let autocommit_res = self
            .db
            .autocommit(
                |dbtx, _| {
                    let operation_type = operation_type.clone();
                    let tx_builder = tx_builder.clone();
                    let operation_meta = operation_meta.clone();
                    Box::pin(async move {
                        if Client::operation_exists_dbtx(dbtx, operation_id).await {
                            bail!("There already exists an operation with id {operation_id:?}")
                        }

                        let (txid, change) = self
                            .finalize_and_submit_transaction_inner(dbtx, operation_id, tx_builder)
                            .await?;

                        self.operation_log()
                            .add_operation_log_entry(
                                dbtx,
                                operation_id,
                                &operation_type,
                                operation_meta(txid, change.clone()),
                            )
                            .await;

                        Ok((txid, change))
                    })
                },
                Some(100), // TODO: handle what happens after 100 retries
            )
            .await;

        match autocommit_res {
            Ok(txid) => Ok(txid),
            Err(AutocommitError::ClosureError { error, .. }) => Err(error),
            Err(AutocommitError::CommitFailed {
                attempts,
                last_error,
            }) => panic!(
                "Failed to commit tx submission dbtx after {attempts} attempts: {last_error}"
            ),
        }
    }

    async fn finalize_and_submit_transaction_inner(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)> {
        let (transaction, mut states, change_range) = self
            .finalize_transaction(&mut dbtx.to_ref_nc(), operation_id, tx_builder)
            .await?;

        if transaction.consensus_encode_to_vec().len() > Transaction::MAX_TX_SIZE {
            let inputs = transaction
                .inputs
                .iter()
                .map(DynInput::module_instance_id)
                .collect::<Vec<_>>();
            let outputs = transaction
                .outputs
                .iter()
                .map(DynOutput::module_instance_id)
                .collect::<Vec<_>>();
            warn!(
                target: LOG_CLIENT_NET_API,
                size=%transaction.consensus_encode_to_vec().len(),
                ?inputs,
                ?outputs,
                "Transaction too large",
            );
            debug!(target: LOG_CLIENT_NET_API, ?transaction, "transaction details");
            bail!(
                "The generated transaction would be rejected by the federation for being too large."
            );
        }

        let txid = transaction.tx_hash();

        debug!(target: LOG_CLIENT_NET_API, %txid, ?transaction,  "Finalized and submitting transaction");

        let change_outpoints = change_range
            .into_iter()
            .map(|out_idx| OutPoint { txid, out_idx })
            .collect();

        let tx_submission_sm = DynState::from_typed(
            TRANSACTION_SUBMISSION_MODULE_INSTANCE,
            TxSubmissionStatesSM {
                operation_id,
                state: TxSubmissionStates::Created(transaction),
            },
        );
        states.push(tx_submission_sm);

        self.executor.add_state_machines_dbtx(dbtx, states).await?;

        self.log_event_dbtx(dbtx, None, TxCreatedEvent { txid, operation_id })
            .await;

        Ok((txid, change_outpoints))
    }

    async fn transaction_update_stream(
        &self,
        operation_id: OperationId,
    ) -> BoxStream<'static, TxSubmissionStatesSM> {
        self.executor
            .notifier()
            .module_notifier::<TxSubmissionStatesSM>(TRANSACTION_SUBMISSION_MODULE_INSTANCE)
            .subscribe(operation_id)
            .await
    }

    pub async fn operation_exists(&self, operation_id: OperationId) -> bool {
        let mut dbtx = self.db().begin_transaction_nc().await;

        Client::operation_exists_dbtx(&mut dbtx, operation_id).await
    }

    pub async fn operation_exists_dbtx(
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
    ) -> bool {
        let active_state_exists = dbtx
            .find_by_prefix(&ActiveOperationStateKeyPrefix { operation_id })
            .await
            .next()
            .await
            .is_some();

        let inactive_state_exists = dbtx
            .find_by_prefix(&InactiveOperationStateKeyPrefix { operation_id })
            .await
            .next()
            .await
            .is_some();

        active_state_exists || inactive_state_exists
    }

    pub async fn has_active_states(&self, operation_id: OperationId) -> bool {
        self.db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&ActiveOperationStateKeyPrefix { operation_id })
            .await
            .next()
            .await
            .is_some()
    }

    /// Waits for an output from the primary module to reach its final
    /// state.
    pub async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<Amount> {
        self.primary_module()
            .await_primary_module_output(operation_id, out_point)
            .await
    }

    /// Returns a reference to a typed module client instance by kind
    pub fn get_first_module<M: ClientModule>(&self) -> anyhow::Result<ClientModuleInstance<M>> {
        let module_kind = M::kind();
        let id = self
            .get_first_instance(&module_kind)
            .ok_or_else(|| format_err!("No modules found of kind {module_kind}"))?;
        let module: &M = self
            .try_get_module(id)
            .ok_or_else(|| format_err!("Unknown module instance {id}"))?
            .as_any()
            .downcast_ref::<M>()
            .ok_or_else(|| format_err!("Module is not of type {}", std::any::type_name::<M>()))?;
        let (db, _) = self.db().with_prefix_module_id(id);
        Ok(ClientModuleInstance {
            id,
            db,
            api: self.api().with_module(id),
            module,
        })
    }

    pub fn get_module_client_dyn(
        &self,
        instance_id: ModuleInstanceId,
    ) -> anyhow::Result<&maybe_add_send_sync!(dyn IClientModule)> {
        self.try_get_module(instance_id)
            .ok_or(anyhow!("Unknown module instance {}", instance_id))
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Returns a stream of transaction updates for the given operation id that
    /// can later be used to watch for a specific transaction being accepted.
    pub async fn transaction_updates(&self, operation_id: OperationId) -> TransactionUpdates {
        TransactionUpdates {
            update_stream: self.transaction_update_stream(operation_id).await,
        }
    }

    /// Returns the instance id of the first module of the given kind. The
    /// primary module will always be returned before any other modules (which
    /// themselves are ordered by their instance ID).
    pub fn get_first_instance(&self, module_kind: &ModuleKind) -> Option<ModuleInstanceId> {
        if self
            .modules
            .get_with_kind(self.primary_module_instance)
            .is_some_and(|(kind, _)| kind == module_kind)
        {
            return Some(self.primary_module_instance);
        }

        self.modules
            .iter_modules()
            .find(|(_, kind, _module)| *kind == module_kind)
            .map(|(instance_id, _, _)| instance_id)
    }

    /// Returns the data from which the client's root secret is derived (e.g.
    /// BIP39 seed phrase struct).
    pub async fn root_secret_encoding<T: Decodable>(&self) -> anyhow::Result<T> {
        get_decoded_client_secret::<T>(self.db()).await
    }

    /// Waits for outputs from the primary module to reach its final
    /// state.
    pub async fn await_primary_module_outputs(
        &self,
        operation_id: OperationId,
        outputs: Vec<OutPoint>,
    ) -> anyhow::Result<Amount> {
        let mut amount = Amount::ZERO;

        for out_point in outputs {
            amount += self
                .await_primary_module_output(operation_id, out_point)
                .await?;
        }

        Ok(amount)
    }

    /// Returns the config of the client in JSON format.
    ///
    /// Compared to the consensus module format where module configs are binary
    /// encoded this format cannot be cryptographically verified but is easier
    /// to consume and to some degree human-readable.
    pub async fn get_config_json(&self) -> JsonClientConfig {
        self.config().await.to_json()
    }

    /// Get the primary module
    pub fn primary_module(&self) -> &DynClientModule {
        self.modules
            .get(self.primary_module_instance)
            .expect("primary module must be present")
    }

    /// Balance available to the client for spending
    pub async fn get_balance(&self) -> Amount {
        self.primary_module()
            .get_balance(
                self.primary_module_instance,
                &mut self.db().begin_transaction_nc().await,
            )
            .await
    }

    /// Returns a stream that yields the current client balance every time it
    /// changes.
    pub async fn subscribe_balance_changes(&self) -> BoxStream<'static, Amount> {
        let mut balance_changes = self.primary_module().subscribe_balance_changes().await;
        let initial_balance = self.get_balance().await;
        let db = self.db().clone();
        let primary_module = self.primary_module().clone();
        let primary_module_instance = self.primary_module_instance;

        Box::pin(stream! {
            yield initial_balance;
            let mut prev_balance = initial_balance;
            while let Some(()) = balance_changes.next().await {
                let mut dbtx = db.begin_transaction_nc().await;
                let balance = primary_module
                    .get_balance(primary_module_instance, &mut dbtx)
                    .await;

                // Deduplicate in case modules cannot always tell if the balance actually changed
                if balance != prev_balance {
                    prev_balance = balance;
                    yield balance;
                }
            }
        })
    }

    /// Query the federation for API version support and then calculate
    /// the best API version to use (supported by most guardians).
    pub async fn refresh_peers_api_versions(
        num_peers: NumPeers,
        api: DynGlobalApi,
        db: Database,
        num_responses_sender: watch::Sender<usize>,
    ) {
        // Make a single request to a peer after a delay
        //
        // The delay is here to unify the type of a future both for initial request and
        // possible retries.
        async fn make_request(
            delay: Duration,
            peer_id: PeerId,
            api: &DynGlobalApi,
        ) -> (
            PeerId,
            Result<SupportedApiVersionsSummary, fedimint_api_client::api::PeerError>,
        ) {
            runtime::sleep(delay).await;
            (
                peer_id,
                api.request_single_peer_typed::<SupportedApiVersionsSummary>(
                    None,
                    VERSION_ENDPOINT.to_owned(),
                    ApiRequestErased::default(),
                    peer_id,
                )
                .await,
            )
        }

        // NOTE: `FuturesUnordered` is a footgun, but since we only poll it for result
        // and make a single async db write operation, it should be OK.
        let mut requests = FuturesUnordered::new();

        for peer_id in num_peers.peer_ids() {
            requests.push(make_request(Duration::ZERO, peer_id, &api));
        }

        let mut num_responses = 0;

        while let Some((peer_id, response)) = requests.next().await {
            match response {
                Err(err) => {
                    if db
                        .begin_transaction_nc()
                        .await
                        .get_value(&PeerLastApiVersionsSummaryKey(peer_id))
                        .await
                        .is_some()
                    {
                        debug!(target: LOG_CLIENT, %peer_id, %err, "Failed to refresh API versions of a peer, but we have a previous response");
                    } else {
                        debug!(target: LOG_CLIENT, %peer_id, %err, "Failed to refresh API versions of a peer, will retry");
                        requests.push(make_request(Duration::from_secs(15), peer_id, &api));
                    }
                }
                Ok(o) => {
                    // Save the response to the database right away, just to
                    // not lose it
                    let mut dbtx = db.begin_transaction().await;
                    dbtx.insert_entry(
                        &PeerLastApiVersionsSummaryKey(peer_id),
                        &PeerLastApiVersionsSummary(o),
                    )
                    .await;
                    dbtx.commit_tx().await;
                    num_responses += 1;
                    // ignore errors: we don't care if anyone is still listening
                    let _ = num_responses_sender.send(num_responses);
                }
            }
        }
    }

    /// [`SupportedApiVersionsSummary`] that the client and its modules support
    pub fn supported_api_versions_summary_static(
        config: &ClientConfig,
        client_module_init: &ClientModuleInitRegistry,
    ) -> SupportedApiVersionsSummary {
        SupportedApiVersionsSummary {
            core: SupportedCoreApiVersions {
                core_consensus: config.global.consensus_version,
                api: MultiApiVersion::try_from_iter(SUPPORTED_CORE_API_VERSIONS.to_owned())
                    .expect("must not have conflicting versions"),
            },
            modules: config
                .modules
                .iter()
                .filter_map(|(&module_instance_id, module_config)| {
                    client_module_init
                        .get(module_config.kind())
                        .map(|module_init| {
                            (
                                module_instance_id,
                                SupportedModuleApiVersions {
                                    core_consensus: config.global.consensus_version,
                                    module_consensus: module_config.version,
                                    api: module_init.supported_api_versions(),
                                },
                            )
                        })
                })
                .collect(),
        }
    }

    pub async fn load_and_refresh_common_api_version(&self) -> anyhow::Result<ApiVersionSet> {
        Self::load_and_refresh_common_api_version_static(
            &self.config().await,
            &self.module_inits,
            &self.api,
            &self.db,
            &self.task_group,
        )
        .await
    }

    /// Load the common api versions to use from cache and start a background
    /// process to refresh them.
    ///
    /// This is a compromise, so we not have to wait for version discovery to
    /// complete every time a [`Client`] is being built.
    async fn load_and_refresh_common_api_version_static(
        config: &ClientConfig,
        module_init: &ClientModuleInitRegistry,
        api: &DynGlobalApi,
        db: &Database,
        task_group: &TaskGroup,
    ) -> anyhow::Result<ApiVersionSet> {
        if let Some(v) = db
            .begin_transaction_nc()
            .await
            .get_value(&CachedApiVersionSetKey)
            .await
        {
            debug!("Found existing cached common api versions");
            let config = config.clone();
            let client_module_init = module_init.clone();
            let api = api.clone();
            let db = db.clone();
            let task_group = task_group.clone();
            // Separate task group, because we actually don't want to be waiting for this to
            // finish, and it's just best effort.
            task_group
                .clone()
                .spawn_cancellable("refresh_common_api_version_static", async move {
                    if let Err(error) = Self::refresh_common_api_version_static(
                        &config,
                        &client_module_init,
                        &api,
                        &db,
                        task_group,
                    )
                    .await
                    {
                        warn!(%error, "Failed to discover common api versions");
                    }
                });

            return Ok(v.0);
        }

        debug!("No existing cached common api versions found, waiting for initial discovery");
        Self::refresh_common_api_version_static(config, module_init, api, db, task_group.clone())
            .await
    }

    async fn refresh_common_api_version_static(
        config: &ClientConfig,
        client_module_init: &ClientModuleInitRegistry,
        api: &DynGlobalApi,
        db: &Database,
        task_group: TaskGroup,
    ) -> anyhow::Result<ApiVersionSet> {
        debug!("Refreshing common api versions");

        let (num_responses_sender, mut num_responses_receiver) = tokio::sync::watch::channel(0);
        let num_peers = NumPeers::from(config.global.api_endpoints.len());

        task_group.spawn_cancellable("refresh peers api versions", {
            Client::refresh_peers_api_versions(
                num_peers,
                api.clone(),
                db.clone(),
                num_responses_sender,
            )
        });

        // Wait at most 15 seconds before calculating a set of common api versions to
        // use. Note that all peers individual responses from previous attempts
        // are still being used, and requests, or even retries for response of
        // peers are not actually cancelled, as they are happening on a separate
        // task. This is all just to bound the time user can be waiting
        // for the join operation to finish, at the risk of picking wrong version in
        // very rare circumstances.
        let _: Result<_, Elapsed> = runtime::timeout(
            Duration::from_secs(15),
            num_responses_receiver.wait_for(|num| num_peers.threshold() <= *num),
        )
        .await;

        let peer_api_version_sets = Self::load_peers_last_api_versions(db, num_peers).await;

        let common_api_versions = discover_common_api_versions_set(
            &Self::supported_api_versions_summary_static(config, client_module_init),
            &peer_api_version_sets,
        )?;

        debug!(
            value = ?common_api_versions,
            "Updating the cached common api versions"
        );
        let mut dbtx = db.begin_transaction().await;
        let _ = dbtx
            .insert_entry(
                &CachedApiVersionSetKey,
                &CachedApiVersionSet(common_api_versions.clone()),
            )
            .await;

        dbtx.commit_tx().await;

        Ok(common_api_versions)
    }

    /// Get the client [`Metadata`]
    pub async fn get_metadata(&self) -> Metadata {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&ClientMetadataKey)
            .await
            .unwrap_or_else(|| {
                warn!("Missing existing metadata. This key should have been set on Client init");
                Metadata::empty()
            })
    }

    /// Set the client [`Metadata`]
    pub async fn set_metadata(&self, metadata: &Metadata) {
        self.db
            .autocommit::<_, _, anyhow::Error>(
                |dbtx, _| {
                    Box::pin(async {
                        Self::set_metadata_dbtx(dbtx, metadata).await;
                        Ok(())
                    })
                },
                None,
            )
            .await
            .expect("Failed to autocommit metadata");
    }

    pub fn has_pending_recoveries(&self) -> bool {
        !self
            .client_recovery_progress_receiver
            .borrow()
            .iter()
            .all(|(_id, progress)| progress.is_done())
    }

    /// Wait for all module recoveries to finish
    ///
    /// This will block until the recovery task is done with recoveries.
    /// Returns success if all recovery tasks are complete (success case),
    /// or an error if some modules could not complete the recovery at the time.
    ///
    /// A bit of a heavy approach.
    pub async fn wait_for_all_recoveries(&self) -> anyhow::Result<()> {
        let mut recovery_receiver = self.client_recovery_progress_receiver.clone();
        recovery_receiver
            .wait_for(|in_progress| {
                in_progress
                    .iter()
                    .all(|(_id, progress)| progress.is_done())
            })
            .await
            .context("Recovery task completed and update receiver disconnected, but some modules failed to recover")?;

        Ok(())
    }

    /// Subscribe to recover progress for all the modules.
    ///
    /// This stream can contain duplicate progress for a module.
    /// Don't use this stream for detecting completion of recovery.
    pub fn subscribe_to_recovery_progress(
        &self,
    ) -> impl Stream<Item = (ModuleInstanceId, RecoveryProgress)> {
        WatchStream::new(self.client_recovery_progress_receiver.clone())
            .flat_map(futures::stream::iter)
    }

    pub async fn wait_for_module_kind_recovery(
        &self,
        module_kind: ModuleKind,
    ) -> anyhow::Result<()> {
        let mut recovery_receiver = self.client_recovery_progress_receiver.clone();
        let config = self.config().await;
        recovery_receiver
            .wait_for(|in_progress| {
                !in_progress
                    .iter()
                    .filter(|(module_instance_id, _progress)| {
                        config.modules[module_instance_id].kind == module_kind
                    })
                    .any(|(_id, progress)| !progress.is_done())
            })
            .await
            .context("Recovery task completed and update receiver disconnected, but the desired modules are still unavailable or failed to recover")?;

        Ok(())
    }

    pub async fn wait_for_all_active_state_machines(&self) -> anyhow::Result<()> {
        loop {
            if self.executor.get_active_states().await.is_empty() {
                break;
            }
            fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    /// Set the client [`Metadata`]
    pub async fn set_metadata_dbtx(dbtx: &mut DatabaseTransaction<'_>, metadata: &Metadata) {
        dbtx.insert_new_entry(&ClientMetadataKey, metadata).await;
    }

    fn spawn_module_recoveries_task(
        &self,
        recovery_sender: watch::Sender<BTreeMap<ModuleInstanceId, RecoveryProgress>>,
        module_recoveries: BTreeMap<
            ModuleInstanceId,
            Pin<Box<maybe_add_send!(dyn Future<Output = anyhow::Result<()>>)>>,
        >,
        module_recovery_progress_receivers: BTreeMap<
            ModuleInstanceId,
            watch::Receiver<RecoveryProgress>,
        >,
    ) {
        let db = self.db.clone();
        let log_ordering_wakeup_tx = self.log_ordering_wakeup_tx.clone();
        self.task_group
            .spawn("module recoveries", |_task_handle| async {
                Self::run_module_recoveries_task(
                    db,
                    log_ordering_wakeup_tx,
                    recovery_sender,
                    module_recoveries,
                    module_recovery_progress_receivers,
                )
                .await;
            });
    }

    async fn run_module_recoveries_task(
        db: Database,
        log_ordering_wakeup_tx: watch::Sender<()>,
        recovery_sender: watch::Sender<BTreeMap<ModuleInstanceId, RecoveryProgress>>,
        module_recoveries: BTreeMap<
            ModuleInstanceId,
            Pin<Box<maybe_add_send!(dyn Future<Output = anyhow::Result<()>>)>>,
        >,
        module_recovery_progress_receivers: BTreeMap<
            ModuleInstanceId,
            watch::Receiver<RecoveryProgress>,
        >,
    ) {
        debug!(target:LOG_CLIENT_RECOVERY, num_modules=%module_recovery_progress_receivers.len(), "Staring module recoveries");
        let mut completed_stream = Vec::new();
        let progress_stream = futures::stream::FuturesUnordered::new();

        for (module_instance_id, f) in module_recoveries {
            completed_stream.push(futures::stream::once(Box::pin(async move {
                match f.await {
                    Ok(()) => (module_instance_id, None),
                    Err(err) => {
                        warn!(%err, module_instance_id, "Module recovery failed");
                        // a module recovery that failed reports and error and
                        // just never finishes, so we don't need a separate state
                        // for it
                        futures::future::pending::<()>().await;
                        unreachable!()
                    }
                }
            })));
        }

        for (module_instance_id, rx) in module_recovery_progress_receivers {
            progress_stream.push(
                tokio_stream::wrappers::WatchStream::new(rx)
                    .fuse()
                    .map(move |progress| (module_instance_id, Some(progress))),
            );
        }

        let mut futures = futures::stream::select(
            futures::stream::select_all(progress_stream),
            futures::stream::select_all(completed_stream),
        );

        while let Some((module_instance_id, progress)) = futures.next().await {
            let mut dbtx = db.begin_transaction().await;

            let prev_progress = *recovery_sender
                .borrow()
                .get(&module_instance_id)
                .expect("existing progress must be present");

            let progress = if prev_progress.is_done() {
                // since updates might be out of order, once done, stick with it
                prev_progress
            } else if let Some(progress) = progress {
                progress
            } else {
                prev_progress.to_complete()
            };

            if !prev_progress.is_done() && progress.is_done() {
                info!(
                    module_instance_id,
                    prev_progress = format!("{}/{}", prev_progress.complete, prev_progress.total),
                    progress = format!("{}/{}", progress.complete, progress.total),
                    "Recovery complete"
                );
                dbtx.log_event(
                    log_ordering_wakeup_tx.clone(),
                    None,
                    ModuleRecoveryCompleted {
                        module_id: module_instance_id,
                    },
                )
                .await;
            } else {
                info!(
                    module_instance_id,
                    prev_progress = format!("{}/{}", prev_progress.complete, prev_progress.total),
                    progress = format!("{}/{}", progress.complete, progress.total),
                    "Recovery progress"
                );
            }

            dbtx.insert_entry(
                &ClientModuleRecovery { module_instance_id },
                &ClientModuleRecoveryState { progress },
            )
            .await;
            dbtx.commit_tx().await;

            recovery_sender.send_modify(|v| {
                v.insert(module_instance_id, progress);
            });
        }
        debug!(target: LOG_CLIENT_RECOVERY, "Recovery executor stopped");
    }

    async fn load_peers_last_api_versions(
        db: &Database,
        num_peers: NumPeers,
    ) -> BTreeMap<PeerId, SupportedApiVersionsSummary> {
        let mut peer_api_version_sets = BTreeMap::new();

        let mut dbtx = db.begin_transaction_nc().await;
        for peer_id in num_peers.peer_ids() {
            if let Some(v) = dbtx
                .get_value(&PeerLastApiVersionsSummaryKey(peer_id))
                .await
            {
                peer_api_version_sets.insert(peer_id, v.0);
            }
        }
        drop(dbtx);
        peer_api_version_sets
    }

    /// You likely want to use [`Client::get_peer_urls`]. This function returns
    /// only the announcements and doesn't use the config as fallback.
    pub async fn get_peer_url_announcements(&self) -> BTreeMap<PeerId, SignedApiAnnouncement> {
        self.db()
            .begin_transaction_nc()
            .await
            .find_by_prefix(&ApiAnnouncementPrefix)
            .await
            .map(|(announcement_key, announcement)| (announcement_key.0, announcement))
            .collect()
            .await
    }

    /// Returns a list of guardian API URLs
    pub async fn get_peer_urls(&self) -> BTreeMap<PeerId, SafeUrl> {
        get_api_urls(&self.db, &self.config().await).await
    }

    /// Create an invite code with the api endpoint of the given peer which can
    /// be used to download this client config
    pub async fn invite_code(&self, peer: PeerId) -> Option<InviteCode> {
        self.get_peer_urls()
            .await
            .into_iter()
            .find_map(|(peer_id, url)| (peer == peer_id).then_some(url))
            .map(|peer_url| {
                InviteCode::new(
                    peer_url.clone(),
                    peer,
                    self.federation_id(),
                    self.api_secret.clone(),
                )
            })
    }

    /// Blocks till the client has synced the guardian public key set
    /// (introduced in version 0.4) and returns it. Once it has been fetched
    /// once this function is guaranteed to return immediately.
    pub async fn get_guardian_public_keys_blocking(
        &self,
    ) -> BTreeMap<PeerId, fedimint_core::secp256k1::PublicKey> {
        self.db.autocommit(|dbtx, _| Box::pin(async move {
            let config = self.config().await;

            let guardian_pub_keys = if let Some(guardian_pub_keys) = config.global.broadcast_public_keys {guardian_pub_keys}else{
                let fetched_config = retry(
                    "Fetching guardian public keys",
                    backoff_util::background_backoff(),
                    || async {
                        Ok(self.api.request_current_consensus::<ClientConfig>(
                            CLIENT_CONFIG_ENDPOINT.to_owned(),
                            ApiRequestErased::default(),
                        ).await?)
                    },
                )
                .await
                .expect("Will never return on error");

                let Some(guardian_pub_keys) = fetched_config.global.broadcast_public_keys else {
                    warn!("Guardian public keys not found in fetched config, server not updated to 0.4 yet");
                    pending::<()>().await;
                    unreachable!("Pending will never return");
                };

                let new_config = ClientConfig {
                    global: GlobalClientConfig {
                        broadcast_public_keys: Some(guardian_pub_keys.clone()),
                        ..config.global
                    },
                    modules: config.modules,
                };

                dbtx.insert_entry(&ClientConfigKey, &new_config).await;
                *(self.config.write().await) = new_config;
                guardian_pub_keys
            };

            Result::<_, ()>::Ok(guardian_pub_keys)
        }), None).await.expect("Will retry forever")
    }

    pub fn handle_global_rpc(
        &self,
        method: String,
        params: serde_json::Value,
    ) -> BoxStream<'_, anyhow::Result<serde_json::Value>> {
        Box::pin(try_stream! {
            match method.as_str() {
                "get_balance" => {
                    let balance = self.get_balance().await;
                    yield serde_json::to_value(balance)?;
                }
                "subscribe_balance_changes" => {
                    let mut stream = self.subscribe_balance_changes().await;
                    while let Some(balance) = stream.next().await {
                        yield serde_json::to_value(balance)?;
                    }
                }
                "get_config" => {
                    let config = self.config().await;
                    yield serde_json::to_value(config)?;
                }
                "get_federation_id" => {
                    let federation_id = self.federation_id();
                    yield serde_json::to_value(federation_id)?;
                }
                "get_invite_code" => {
                    let req: GetInviteCodeRequest = serde_json::from_value(params)?;
                    let invite_code = self.invite_code(req.peer).await;
                    yield serde_json::to_value(invite_code)?;
                }
                "list_operations" => {
                    // TODO: support pagination
                    let operations = self.operation_log().list_operations(usize::MAX, None).await;
                    yield serde_json::to_value(operations)?;
                }
                "has_pending_recoveries" => {
                    let has_pending = self.has_pending_recoveries();
                    yield serde_json::to_value(has_pending)?;
                }
                "wait_for_all_recoveries" => {
                    self.wait_for_all_recoveries().await?;
                    yield serde_json::Value::Null;
                }
                "subscribe_to_recovery_progress" => {
                    let mut stream = self.subscribe_to_recovery_progress();
                    while let Some((module_id, progress)) = stream.next().await {
                        yield serde_json::json!({
                            "module_id": module_id,
                            "progress": progress
                        });
                    }
                }
                _ => {
                    Err(anyhow::format_err!("Unknown method: {}", method))?;
                    unreachable!()
                },
            }
        })
    }

    pub async fn log_event<E>(&self, module_id: Option<ModuleInstanceId>, event: E)
    where
        E: Event + Send,
    {
        let mut dbtx = self.db.begin_transaction().await;
        self.log_event_dbtx(&mut dbtx, module_id, event).await;
        dbtx.commit_tx().await;
    }

    pub async fn log_event_dbtx<E, Cap>(
        &self,
        dbtx: &mut DatabaseTransaction<'_, Cap>,
        module_id: Option<ModuleInstanceId>,
        event: E,
    ) where
        E: Event + Send,
        Cap: Send,
    {
        dbtx.log_event(self.log_ordering_wakeup_tx.clone(), module_id, event)
            .await;
    }

    pub async fn log_event_raw_dbtx<Cap>(
        &self,
        dbtx: &mut DatabaseTransaction<'_, Cap>,
        kind: EventKind,
        module: Option<(ModuleKind, ModuleInstanceId)>,
        payload: Vec<u8>,
        transient: bool,
    ) where
        Cap: Send,
    {
        let module_id = module.as_ref().map(|m| m.1);
        let module_kind = module.map(|m| m.0);
        dbtx.log_event_raw(
            self.log_ordering_wakeup_tx.clone(),
            kind,
            module_kind,
            module_id,
            payload,
            transient,
        )
        .await;
    }

    pub async fn handle_events<F, R, K>(&self, pos_key: &K, call_fn: F) -> anyhow::Result<()>
    where
        K: DatabaseKey + DatabaseRecord + MaybeSend + MaybeSync,
        K: DatabaseRecord<Value = EventLogId>,
        F: Fn(&mut DatabaseTransaction<NonCommittable>, EventLogEntry) -> R,
        R: Future<Output = anyhow::Result<()>>,
    {
        event_log::handle_events(
            self.db.clone(),
            pos_key,
            self.log_event_added_rx.clone(),
            call_fn,
        )
        .await
    }

    pub async fn get_event_log(
        &self,
        pos: Option<EventLogId>,
        limit: u64,
    ) -> Vec<(
        EventLogId,
        EventKind,
        Option<(ModuleKind, ModuleInstanceId)>,
        u64,
        serde_json::Value,
    )> {
        self.get_event_log_dbtx(&mut self.db.begin_transaction_nc().await, pos, limit)
            .await
    }

    pub async fn get_event_log_dbtx<Cap>(
        &self,
        dbtx: &mut DatabaseTransaction<'_, Cap>,
        pos: Option<EventLogId>,
        limit: u64,
    ) -> Vec<(
        EventLogId,
        EventKind,
        Option<(ModuleKind, ModuleInstanceId)>,
        u64,
        serde_json::Value,
    )>
    where
        Cap: Send,
    {
        dbtx.get_event_log(pos, limit).await
    }

    /// Register to receiver all new transient (unpersisted) events
    pub fn get_event_log_transient_receiver(&self) -> broadcast::Receiver<EventLogEntry> {
        self.log_event_added_transient_tx.subscribe()
    }
}

#[derive(Deserialize)]
struct GetInviteCodeRequest {
    peer: PeerId,
}

/// See [`Client::transaction_updates`]
pub struct TransactionUpdates {
    update_stream: BoxStream<'static, TxSubmissionStatesSM>,
}

impl TransactionUpdates {
    /// Waits for the transaction to be accepted or rejected as part of the
    /// operation to which the `TransactionUpdates` object is subscribed.
    pub async fn await_tx_accepted(self, await_txid: TransactionId) -> Result<(), String> {
        debug!(target: LOG_CLIENT, %await_txid, "Await tx accepted");
        self.update_stream
            .filter_map(|tx_update| {
                std::future::ready(match tx_update.state {
                    TxSubmissionStates::Accepted(txid) if txid == await_txid => Some(Ok(())),
                    TxSubmissionStates::Rejected(txid, submit_error) if txid == await_txid => {
                        Some(Err(submit_error))
                    }
                    _ => None,
                })
            })
            .next_or_pending()
            .await?;
        debug!(target: LOG_CLIENT, %await_txid, "Tx accepted");
        Ok(())
    }
}

/// Admin (guardian) identification and authentication
pub struct AdminCreds {
    /// Guardian's own `peer_id`
    pub peer_id: PeerId,
    /// Authentication details
    pub auth: ApiAuth,
}

/// Used to configure, assemble and build [`Client`]
pub struct ClientBuilder {
    module_inits: ClientModuleInitRegistry,
    primary_module_instance: Option<ModuleInstanceId>,
    admin_creds: Option<AdminCreds>,
    db_no_decoders: Database,
    meta_service: Arc<MetaService>,
    connector: Connector,
    stopped: bool,
    log_event_added_transient_tx: broadcast::Sender<EventLogEntry>,
}

impl ClientBuilder {
    fn new(db: Database) -> Self {
        let meta_service = MetaService::new(LegacyMetaSource::default());
        let (log_event_added_transient_tx, _log_event_added_transient_rx) =
            broadcast::channel(1024);
        ClientBuilder {
            module_inits: ModuleInitRegistry::new(),
            primary_module_instance: None,
            connector: Connector::default(),
            admin_creds: None,
            db_no_decoders: db,
            stopped: false,
            meta_service,
            log_event_added_transient_tx,
        }
    }

    fn from_existing(client: &Client) -> Self {
        ClientBuilder {
            module_inits: client.module_inits.clone(),
            primary_module_instance: Some(client.primary_module_instance),
            admin_creds: None,
            db_no_decoders: client.db.with_decoders(ModuleRegistry::default()),
            stopped: false,
            // non unique
            meta_service: client.meta_service.clone(),
            connector: client.connector,
            log_event_added_transient_tx: client.log_event_added_transient_tx.clone(),
        }
    }

    /// Replace module generator registry entirely
    pub fn with_module_inits(&mut self, module_inits: ClientModuleInitRegistry) {
        self.module_inits = module_inits;
    }

    /// Make module generator available when reading the config
    pub fn with_module<M: ClientModuleInit>(&mut self, module_init: M) {
        self.module_inits.attach(module_init);
    }

    pub fn stopped(&mut self) {
        self.stopped = true;
    }

    /// Uses this module with the given instance id as the primary module. See
    /// [`ClientModule::supports_being_primary`] for more information.
    ///
    /// ## Panics
    /// If there was a primary module specified previously
    pub fn with_primary_module(&mut self, primary_module_instance: ModuleInstanceId) {
        let was_replaced = self
            .primary_module_instance
            .replace(primary_module_instance)
            .is_some();
        assert!(
            !was_replaced,
            "Only one primary module can be given to the builder."
        );
    }

    pub fn with_meta_service(&mut self, meta_service: Arc<MetaService>) {
        self.meta_service = meta_service;
    }

    async fn migrate_database(&self, db: &Database) -> anyhow::Result<()> {
        // Only apply the client database migrations if the database has been
        // initialized.
        // This only works as long as you don't change the client config
        if let Ok(client_config) = self.load_existing_config().await {
            for (module_id, module_cfg) in client_config.modules {
                let kind = module_cfg.kind.clone();
                let Some(init) = self.module_inits.get(&kind) else {
                    // normal, expected and already logged about when building the client
                    continue;
                };

                apply_migrations_client(
                    db,
                    kind.to_string(),
                    init.get_database_migrations(),
                    module_id,
                )
                .await?;
            }
        }

        Ok(())
    }

    pub fn db_no_decoders(&self) -> &Database {
        &self.db_no_decoders
    }

    pub async fn load_existing_config(&self) -> anyhow::Result<ClientConfig> {
        let Some(config) = Client::get_config_from_db(&self.db_no_decoders).await else {
            bail!("Client database not initialized")
        };

        Ok(config)
    }

    pub fn set_admin_creds(&mut self, creds: AdminCreds) {
        self.admin_creds = Some(creds);
    }

    pub fn with_connector(&mut self, connector: Connector) {
        self.connector = connector;
    }

    #[cfg(feature = "tor")]
    pub fn with_tor_connector(&mut self) {
        self.with_connector(Connector::tor());
    }

    async fn init(
        self,
        pre_root_secret: DerivableSecret,
        config: ClientConfig,
        api_secret: Option<String>,
        init_mode: InitMode,
    ) -> anyhow::Result<ClientHandle> {
        if Client::is_initialized(&self.db_no_decoders).await {
            bail!("Client database already initialized")
        }

        // Note: It's important all client initialization is performed as one big
        // transaction to avoid half-initialized client state.
        {
            debug!(target: LOG_CLIENT, "Initializing client database");
            let mut dbtx = self.db_no_decoders.begin_transaction().await;
            // Save config to DB
            dbtx.insert_new_entry(&ClientConfigKey, &config).await;
            dbtx.insert_entry(
                &ClientPreRootSecretHashKey,
                &pre_root_secret.derive_pre_root_secret_hash(),
            )
            .await;

            if let Some(api_secret) = api_secret.as_ref() {
                dbtx.insert_new_entry(&ApiSecretKey, api_secret).await;
            }

            let init_state = InitState::Pending(init_mode);
            dbtx.insert_entry(&ClientInitStateKey, &init_state).await;

            let metadata = init_state
                .does_require_recovery()
                .flatten()
                .map_or(Metadata::empty(), |s| s.metadata);

            dbtx.insert_new_entry(&ClientMetadataKey, &metadata).await;

            dbtx.commit_tx_result().await?;
        }

        let stopped = self.stopped;
        self.build(pre_root_secret, config, api_secret, stopped)
            .await
    }

    /// Join a new Federation
    ///
    /// When a user wants to connect to a new federation this function fetches
    /// the federation config and initializes the client database. If a user
    /// already joined the federation in the past and has a preexisting database
    /// use [`ClientBuilder::open`] instead.
    ///
    /// **Warning**: Calling `join` with a `root_secret` key that was used
    /// previous to `join` a Federation will lead to all sorts of malfunctions
    /// including likely loss of funds.
    ///
    /// This should be generally called only if the `root_secret` key is known
    /// not to have been used before (e.g. just randomly generated). For keys
    /// that might have been previous used (e.g. provided by the user),
    /// it's safer to call [`Self::recover`] which will attempt to recover
    /// client module states for the Federation.
    ///
    /// A typical "join federation" flow would look as follows:
    /// ```no_run
    /// # use std::str::FromStr;
    /// # use fedimint_core::invite_code::InviteCode;
    /// # use fedimint_core::config::ClientConfig;
    /// # use fedimint_derive_secret::DerivableSecret;
    /// # use fedimint_client::{Client, ClientBuilder};
    /// # use fedimint_core::db::Database;
    /// # use fedimint_core::config::META_FEDERATION_NAME_KEY;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let root_secret: DerivableSecret = unimplemented!();
    /// // Create a root secret, e.g. via fedimint-bip39, see also:
    /// // https://github.com/fedimint/fedimint/blob/master/docs/secret_derivation.md
    /// // let root_secret = …;
    ///
    /// // Get invite code from user
    /// let invite_code = InviteCode::from_str("fed11qgqpw9thwvaz7te3xgmjuvpwxqhrzw3jxumrvvf0qqqjpetvlg8glnpvzcufhffgzhv8m75f7y34ryk7suamh8x7zetly8h0v9v0rm")
    ///     .expect("Invalid invite code");
    /// let config = fedimint_api_client::api::net::Connector::default().download_from_invite_code(&invite_code).await
    ///     .expect("Error downloading config");
    ///
    /// // Tell the user the federation name, bitcoin network
    /// // (e.g. from wallet module config), and other details
    /// // that are typically contained in the federation's
    /// // meta fields.
    ///
    /// // let network = config.get_first_module_by_kind::<WalletClientConfig>("wallet")
    /// //     .expect("Module not found")
    /// //     .network;
    ///
    /// println!(
    ///     "The federation name is: {}",
    ///     config.meta::<String>(META_FEDERATION_NAME_KEY)
    ///         .expect("Could not decode name field")
    ///         .expect("Name isn't set")
    /// );
    ///
    /// // Open the client's database, using the federation ID
    /// // as the DB name is a common pattern:
    ///
    /// // let db_path = format!("./path/to/db/{}", config.federation_id());
    /// // let db = RocksDb::open(db_path).expect("error opening DB");
    /// # let db: Database = unimplemented!();
    ///
    /// let client = Client::builder(db).await.expect("Error building client")
    ///     // Mount the modules the client should support:
    ///     // .with_module(LightningClientInit)
    ///     // .with_module(MintClientInit)
    ///     // .with_module(WalletClientInit::default())
    ///     .join(root_secret, config, None)
    ///     .await
    ///     .expect("Error joining federation");
    /// # }
    /// ```
    pub async fn join(
        self,
        pre_root_secret: DerivableSecret,
        config: ClientConfig,
        api_secret: Option<String>,
    ) -> anyhow::Result<ClientHandle> {
        self.init(pre_root_secret, config, api_secret, InitMode::Fresh)
            .await
    }

    /// Download most recent valid backup found from the Federation
    pub async fn download_backup_from_federation(
        &self,
        root_secret: &DerivableSecret,
        config: &ClientConfig,
        api_secret: Option<String>,
    ) -> anyhow::Result<Option<ClientBackup>> {
        let connector = self.connector;
        let api = DynGlobalApi::from_endpoints(
            // TODO: change join logic to use FederationId v2
            config
                .global
                .api_endpoints
                .iter()
                .map(|(peer_id, peer_url)| (*peer_id, peer_url.url.clone())),
            &api_secret,
            &connector,
        );
        Client::download_backup_from_federation_static(
            &api,
            &Self::federation_root_secret(root_secret, config),
            &self.decoders(config),
        )
        .await
    }

    /// Join a (possibly) previous joined Federation
    ///
    /// Unlike [`Self::join`], `recover` will run client module recovery for
    /// each client module attempting to recover any previous module state.
    ///
    /// Recovery process takes time during which each recovering client module
    /// will not be available for use.
    ///
    /// Calling `recovery` with a `root_secret` that was not actually previous
    /// used in a given Federation is safe.
    pub async fn recover(
        self,
        root_secret: DerivableSecret,
        config: ClientConfig,
        api_secret: Option<String>,
        backup: Option<ClientBackup>,
    ) -> anyhow::Result<ClientHandle> {
        let client = self
            .init(
                root_secret,
                config,
                api_secret,
                InitMode::Recover {
                    snapshot: backup.clone(),
                },
            )
            .await?;

        Ok(client)
    }

    pub async fn open(self, pre_root_secret: DerivableSecret) -> anyhow::Result<ClientHandle> {
        let Some(config) = Client::get_config_from_db(&self.db_no_decoders).await else {
            bail!("Client database not initialized")
        };

        if let Some(secret_hash) = self
            .db_no_decoders()
            .begin_transaction_nc()
            .await
            .get_value(&ClientPreRootSecretHashKey)
            .await
        {
            ensure!(
                pre_root_secret.derive_pre_root_secret_hash() == secret_hash,
                "Secret hash does not match. Incorrect secret"
            );
        } else {
            debug!(target: LOG_CLIENT, "Backfilling secret hash");
            // Note: no need for dbtx autocommit, we are the only writer ATM
            let mut dbtx = self.db_no_decoders.begin_transaction().await;
            dbtx.insert_entry(
                &ClientPreRootSecretHashKey,
                &pre_root_secret.derive_pre_root_secret_hash(),
            )
            .await;
            dbtx.commit_tx().await;
        }

        let api_secret = Client::get_api_secret_from_db(&self.db_no_decoders).await;
        let stopped = self.stopped;

        let log_event_added_transient_tx = self.log_event_added_transient_tx.clone();
        let client = self
            .build_stopped(
                pre_root_secret,
                &config,
                api_secret,
                log_event_added_transient_tx,
            )
            .await?;
        if !stopped {
            client.as_inner().start_executor();
        }
        Ok(client)
    }

    /// Build a [`Client`] and start the executor
    async fn build(
        self,
        pre_root_secret: DerivableSecret,
        config: ClientConfig,
        api_secret: Option<String>,
        stopped: bool,
    ) -> anyhow::Result<ClientHandle> {
        let log_event_added_transient_tx = self.log_event_added_transient_tx.clone();
        let client = self
            .build_stopped(
                pre_root_secret,
                &config,
                api_secret,
                log_event_added_transient_tx,
            )
            .await?;
        if !stopped {
            client.as_inner().start_executor();
        }

        Ok(client)
    }

    // TODO: remove config argument
    /// Build a [`Client`] but do not start the executor
    async fn build_stopped(
        self,
        root_secret: DerivableSecret,
        config: &ClientConfig,
        api_secret: Option<String>,
        log_event_added_transient_tx: broadcast::Sender<EventLogEntry>,
    ) -> anyhow::Result<ClientHandle> {
        let (log_event_added_tx, log_event_added_rx) = watch::channel(());
        let (log_ordering_wakeup_tx, log_ordering_wakeup_rx) = watch::channel(());

        let decoders = self.decoders(config);
        let config = Self::config_decoded(config, &decoders)?;
        let fed_id = config.calculate_federation_id();
        let db = self.db_no_decoders.with_decoders(decoders.clone());
        let connector = self.connector;
        let peer_urls = get_api_urls(&db, &config).await;
        let api = if let Some(admin_creds) = self.admin_creds.as_ref() {
            WsFederationApi::new_admin(
                admin_creds.peer_id,
                peer_urls
                    .into_iter()
                    .find_map(|(peer, api_url)| (admin_creds.peer_id == peer).then_some(api_url))
                    .context("Admin creds should match a peer")?,
                &api_secret,
                &connector,
            )
            .with_client_ext(db.clone(), log_ordering_wakeup_tx.clone())
            .with_cache()
            .into()
        } else {
            WsFederationApi::from_endpoints(peer_urls, &api_secret, &connector)
                .with_client_ext(db.clone(), log_ordering_wakeup_tx.clone())
                .with_cache()
                .into()
        };
        let task_group = TaskGroup::new();

        // Migrate the database before interacting with it in case any on-disk data
        // structures have changed.
        self.migrate_database(&db).await?;

        let init_state = Self::load_init_state(&db).await;

        let primary_module_instance = self
            .primary_module_instance
            .ok_or(anyhow!("No primary module instance id was provided"))?;

        let notifier = Notifier::new(db.clone());

        let common_api_versions = Client::load_and_refresh_common_api_version_static(
            &config,
            &self.module_inits,
            &api,
            &db,
            &task_group,
        )
        .await
        .inspect_err(|err| {
            warn!(target: LOG_CLIENT, %err, "Failed to discover initial API version to use.");
        })
        .unwrap_or(ApiVersionSet {
            core: ApiVersion::new(0, 0),
            // This will cause all modules to skip initialization
            modules: BTreeMap::new(),
        });

        debug!(?common_api_versions, "Completed api version negotiation");

        let mut module_recoveries: BTreeMap<
            ModuleInstanceId,
            Pin<Box<maybe_add_send!(dyn Future<Output = anyhow::Result<()>>)>>,
        > = BTreeMap::new();
        let mut module_recovery_progress_receivers: BTreeMap<
            ModuleInstanceId,
            watch::Receiver<RecoveryProgress>,
        > = BTreeMap::new();

        let final_client = FinalClient::default();

        let root_secret = Self::federation_root_secret(&root_secret, &config);

        let modules = {
            let mut modules = ClientModuleRegistry::default();
            for (module_instance_id, module_config) in config.modules.clone() {
                let kind = module_config.kind().clone();
                let Some(module_init) = self.module_inits.get(&kind).cloned() else {
                    debug!("Module kind {kind} of instance {module_instance_id} not found in module gens, skipping");
                    continue;
                };

                let Some(&api_version) = common_api_versions.modules.get(&module_instance_id)
                else {
                    warn!("Module kind {kind} of instance {module_instance_id} has not compatible api version, skipping");
                    continue;
                };

                // since the exact logic of when to start recovery is a bit gnarly,
                // the recovery call is extracted here.
                let start_module_recover_fn =
                    |snapshot: Option<ClientBackup>, progress: RecoveryProgress| {
                        let module_config = module_config.clone();
                        let num_peers = NumPeers::from(config.global.api_endpoints.len());
                        let db = db.clone();
                        let kind = kind.clone();
                        let notifier = notifier.clone();
                        let api = api.clone();
                        let root_secret = root_secret.clone();
                        let admin_auth = self.admin_creds.as_ref().map(|creds| creds.auth.clone());
                        let final_client = final_client.clone();
                        let (progress_tx, progress_rx) = tokio::sync::watch::channel(progress);
                        let task_group = task_group.clone();
                        let module_init = module_init.clone();
                        (
                            Box::pin(async move {
                                module_init
                                    .recover(
                                        final_client.clone(),
                                        fed_id,
                                        num_peers,
                                        module_config.clone(),
                                        db.clone(),
                                        module_instance_id,
                                        common_api_versions.core,
                                        api_version,
                                        root_secret.derive_module_secret(module_instance_id),
                                        notifier.clone(),
                                        api.clone(),
                                        admin_auth,
                                        snapshot.as_ref().and_then(|s| s.modules.get(&module_instance_id)),
                                        progress_tx,
                                        task_group,
                                    )
                                    .await
                                    .map_err(|err| {
                                        warn!(
                                                module_id = module_instance_id, %kind, %err, "Module failed to recover"
                                            );
                                        err
                                    })
                            }),
                            progress_rx,
                        )
                    };

                let recovery = if let Some(snapshot) = init_state.does_require_recovery() {
                    if let Some(module_recovery_state) = db
                        .begin_transaction_nc()
                        .await
                        .get_value(&ClientModuleRecovery { module_instance_id })
                        .await
                    {
                        if module_recovery_state.is_done() {
                            debug!(
                                id = %module_instance_id,
                                %kind, "Module recovery already complete"
                            );
                            None
                        } else {
                            debug!(
                                id = %module_instance_id,
                                %kind,
                                progress = %module_recovery_state.progress,
                                "Starting module recovery with an existing progress"
                            );
                            Some(start_module_recover_fn(
                                snapshot,
                                module_recovery_state.progress,
                            ))
                        }
                    } else {
                        let progress = RecoveryProgress::none();
                        let mut dbtx = db.begin_transaction().await;
                        dbtx.log_event(
                            log_ordering_wakeup_tx.clone(),
                            None,
                            ModuleRecoveryStarted {
                                module_id: module_instance_id,
                            },
                        )
                        .await;
                        dbtx.insert_entry(
                            &ClientModuleRecovery { module_instance_id },
                            &ClientModuleRecoveryState { progress },
                        )
                        .await;

                        dbtx.commit_tx().await;

                        debug!(
                            id = %module_instance_id,
                            %kind, "Starting new module recovery"
                        );
                        Some(start_module_recover_fn(snapshot, progress))
                    }
                } else {
                    None
                };

                if let Some((recovery, recovery_progress_rx)) = recovery {
                    module_recoveries.insert(module_instance_id, recovery);
                    module_recovery_progress_receivers
                        .insert(module_instance_id, recovery_progress_rx);
                } else {
                    let module = module_init
                        .init(
                            final_client.clone(),
                            fed_id,
                            config.global.api_endpoints.len(),
                            module_config,
                            db.clone(),
                            module_instance_id,
                            common_api_versions.core,
                            api_version,
                            // This is a divergence from the legacy client, where the child secret
                            // keys were derived using *module kind*-specific derivation paths.
                            // Since the new client has to support multiple, segregated modules of
                            // the same kind we have to use the instance id instead.
                            root_secret.derive_module_secret(module_instance_id),
                            notifier.clone(),
                            api.clone(),
                            self.admin_creds.as_ref().map(|cred| cred.auth.clone()),
                            task_group.clone(),
                        )
                        .await?;

                    if primary_module_instance == module_instance_id
                        && !module.supports_being_primary()
                    {
                        bail!("Module instance {primary_module_instance} of kind {kind} does not support being a primary module");
                    }

                    modules.register_module(module_instance_id, kind, module);
                }
            }
            modules
        };

        if init_state.is_pending() && module_recoveries.is_empty() {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(&ClientInitStateKey, &init_state.into_complete())
                .await;
            dbtx.commit_tx().await;
        }

        let executor = {
            let mut executor_builder = Executor::builder();
            executor_builder
                .with_module(TRANSACTION_SUBMISSION_MODULE_INSTANCE, TxSubmissionContext);

            for (module_instance_id, _, module) in modules.iter_modules() {
                executor_builder.with_module_dyn(module.context(module_instance_id));
            }

            for module_instance_id in module_recoveries.keys() {
                executor_builder.with_valid_module_id(*module_instance_id);
            }

            executor_builder.build(db.clone(), notifier, task_group.clone())
        };

        let recovery_receiver_init_val = module_recovery_progress_receivers
            .iter()
            .map(|(module_instance_id, rx)| (*module_instance_id, *rx.borrow()))
            .collect::<BTreeMap<_, _>>();
        let (client_recovery_progress_sender, client_recovery_progress_receiver) =
            watch::channel(recovery_receiver_init_val);

        let client_inner = Arc::new(Client {
            config: RwLock::new(config.clone()),
            api_secret,
            decoders,
            db: db.clone(),
            federation_id: fed_id,
            federation_meta: config.global.meta,
            primary_module_instance,
            modules,
            module_inits: self.module_inits.clone(),
            log_ordering_wakeup_tx,
            log_event_added_rx,
            log_event_added_transient_tx: log_event_added_transient_tx.clone(),
            executor,
            api,
            secp_ctx: Secp256k1::new(),
            root_secret,
            task_group,
            operation_log: OperationLog::new(db.clone()),
            client_recovery_progress_receiver,
            meta_service: self.meta_service,
            connector,
        });
        client_inner
            .task_group
            .spawn_cancellable("MetaService::update_continuously", {
                let client_inner = client_inner.clone();
                async move {
                    client_inner
                        .meta_service
                        .update_continuously(&client_inner)
                        .await;
                }
            });

        client_inner.task_group.spawn_cancellable(
            "update-api-announcements",
            run_api_announcement_sync(client_inner.clone()),
        );

        client_inner.task_group.spawn_cancellable(
            "event log ordering task",
            run_event_log_ordering_task(
                db.clone(),
                log_ordering_wakeup_rx,
                log_event_added_tx,
                log_event_added_transient_tx,
            ),
        );
        let client_arc = ClientHandle::new(client_inner);

        for (_, _, module) in client_arc.modules.iter_modules() {
            module.start().await;
        }

        final_client.set(client_arc.downgrade());

        if !module_recoveries.is_empty() {
            client_arc.spawn_module_recoveries_task(
                client_recovery_progress_sender,
                module_recoveries,
                module_recovery_progress_receivers,
            );
        }

        Ok(client_arc)
    }

    async fn load_init_state(db: &Database) -> InitState {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.get_value(&ClientInitStateKey)
            .await
            .unwrap_or_else(|| {
                // could be turned in a hard error in the future, but for now
                // no need to break backward compat.
                warn!("Client missing ClientRequiresRecovery: assuming complete");
                db::InitState::Complete(db::InitModeComplete::Fresh)
            })
    }

    fn decoders(&self, config: &ClientConfig) -> ModuleDecoderRegistry {
        let mut decoders = client_decoders(
            &self.module_inits,
            config
                .modules
                .iter()
                .map(|(module_instance, module_config)| (*module_instance, module_config.kind())),
        );

        decoders.register_module(
            TRANSACTION_SUBMISSION_MODULE_INSTANCE,
            ModuleKind::from_static_str("tx_submission"),
            tx_submission_sm_decoder(),
        );

        decoders
    }

    fn config_decoded(
        config: &ClientConfig,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<ClientConfig, fedimint_core::encoding::DecodeError> {
        config.clone().redecode_raw(decoders)
    }

    /// Re-derive client's `root_secret` using the federation ID. This
    /// eliminates the possibility of having the same client `root_secret`
    /// across multiple federations.
    fn federation_root_secret(
        root_secret: &DerivableSecret,
        config: &ClientConfig,
    ) -> DerivableSecret {
        root_secret.federation_key(&config.global.calculate_federation_id())
    }

    /// Register to receiver all new transient (unpersisted) events
    pub fn get_event_log_transient_receiver(&self) -> broadcast::Receiver<EventLogEntry> {
        self.log_event_added_transient_tx.subscribe()
    }
}

/// Fetches the encoded client secret from the database and decodes it.
/// If an encoded client secret is not present in the database, or if
/// decoding fails, an error is returned.
pub async fn get_decoded_client_secret<T: Decodable>(db: &Database) -> anyhow::Result<T> {
    let mut tx = db.begin_transaction_nc().await;
    let client_secret = tx.get_value(&EncodedClientSecretKey).await;

    match client_secret {
        Some(client_secret) => {
            T::consensus_decode(&mut client_secret.as_slice(), &ModuleRegistry::default())
                .map_err(|e| anyhow!("Decoding failed: {e}"))
        }
        None => bail!("Encoded client secret not present in DB"),
    }
}

pub fn client_decoders<'a>(
    registry: &ModuleInitRegistry<DynClientModuleInit>,
    module_kinds: impl Iterator<Item = (ModuleInstanceId, &'a ModuleKind)>,
) -> ModuleDecoderRegistry {
    let mut modules = BTreeMap::new();
    for (id, kind) in module_kinds {
        let Some(init) = registry.get(kind) else {
            debug!("Detected configuration for unsupported module id: {id}, kind: {kind}");
            continue;
        };

        modules.insert(
            id,
            (
                kind.clone(),
                IClientModuleInit::decoder(AsRef::<dyn IClientModuleInit + 'static>::as_ref(init)),
            ),
        );
    }
    ModuleDecoderRegistry::from(modules)
}
