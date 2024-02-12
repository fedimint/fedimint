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
//! this ability should implement [`ClientModule::  supports_being_primary`] and
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

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::ops::{self, Range};
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context};
use async_stream::stream;
use backup::ClientBackup;
use db::{
    CachedApiVersionSet, CachedApiVersionSetKey, ClientConfigKey, ClientConfigKeyPrefix,
    ClientInitStateKey, ClientInviteCodeKey, ClientInviteCodeKeyPrefix, ClientModuleRecovery,
    EncodedClientSecretKey, InitMode,
};
use fedimint_core::api::{
    ApiVersionSet, DynGlobalApi, DynModuleApi, IGlobalFederationApi, InviteCode,
};
use fedimint_core::config::{
    ClientConfig, ClientModuleConfig, FederationId, JsonClientConfig, JsonWithKind,
    ModuleInitRegistry,
};
use fedimint_core::core::{
    DynInput, DynOutput, IInput, IOutput, ModuleInstanceId, ModuleKind, OperationId,
};
use fedimint_core::db::{
    apply_migrations, AutocommitError, Database, DatabaseTransaction,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{
    ApiVersion, MultiApiVersion, SupportedApiVersionsSummary, SupportedCoreApiVersions,
    SupportedModuleApiVersions,
};
use fedimint_core::task::{sleep, MaybeSend, MaybeSync, TaskGroup};
use fedimint_core::transaction::Transaction;
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, fedimint_build_code_version_env,
    maybe_add_send, maybe_add_send_sync, Amount, OutPoint, TransactionId,
};
pub use fedimint_derive_secret as derivable_secret;
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::LOG_CLIENT;
use futures::{Future, StreamExt};
use module::recovery::RecoveryProgress;
use module::{DynClientModule, FinalClient};
use rand::thread_rng;
use secp256k1_zkp::{PublicKey, Secp256k1};
use secret::{DeriveableSecretClientExt, PlainRootSecretStrategy, RootSecretStrategy as _};
use thiserror::Error;
#[cfg(not(target_family = "wasm"))]
use tokio::runtime::{Handle as RuntimeHandle, RuntimeFlavor};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

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
use crate::sm::{
    ClientSMDatabaseTransaction, DynState, Executor, IState, Notifier, OperationState, State,
};
use crate::transaction::{
    tx_submission_sm_decoder, ClientInput, ClientOutput, TransactionBuilder,
    TransactionBuilderBalance, TxSubmissionContext, TxSubmissionStates,
    TRANSACTION_SUBMISSION_MODULE_INSTANCE,
};

/// Client backup
pub mod backup;
/// Database keys used by the client
pub mod db;
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

pub type InstancelessDynClientInput = ClientInput<
    Box<maybe_add_send_sync!(dyn IInput + 'static)>,
    Box<maybe_add_send_sync!(dyn IState + 'static)>,
>;

pub type InstancelessDynClientOutput = ClientOutput<
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

    fn client_config(&self) -> &ClientConfig;

    /// Returns a reference to the client's federation API client. The provided
    /// interface [`IGlobalFederationApi`] typically does not provide the
    /// necessary functionality, for this extension traits like
    /// [`fedimint_core::api::IGlobalFederationApi`] have to be used.
    // TODO: Could be removed in favor of client() except for testing
    fn api(&self) -> &DynGlobalApi;

    fn decoders(&self) -> &ModuleDecoderRegistry;

    /// This function is mostly meant for internal use, you are probably looking
    /// for [`DynGlobalClientContext::claim_input`].
    /// Returns transaction id of the funding transaction and an optional
    /// `OutPoint` that represents change if change was added.
    async fn claim_input_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        input: InstancelessDynClientInput,
    ) -> (TransactionId, Vec<OutPoint>);

    /// This function is mostly meant for internal use, you are probably looking
    /// for [`DynGlobalClientContext::fund_output`].
    /// Returns transaction id of the funding transaction and an optional
    /// `OutPoint` that represents change if change was added.
    async fn fund_output_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        output: InstancelessDynClientOutput,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)>;

    /// Adds a state machine to the executor.
    async fn add_state_machine_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        sm: Box<maybe_add_send_sync!(dyn IState)>,
    ) -> AddStateMachinesResult;

    async fn transaction_update_stream(&self) -> BoxStream<OperationState<TxSubmissionStates>>;
}

#[apply(async_trait_maybe_send!)]
impl IGlobalClientContext for () {
    fn module_api(&self) -> DynModuleApi {
        unimplemented!("fake implementation, only for tests");
    }

    fn client_config(&self) -> &ClientConfig {
        unimplemented!("fake implementation, only for tests");
    }

    fn api(&self) -> &DynGlobalApi {
        unimplemented!("fake implementation, only for tests");
    }

    fn decoders(&self) -> &ModuleDecoderRegistry {
        unimplemented!("fake implementation, only for tests");
    }

    async fn claim_input_dyn(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _input: InstancelessDynClientInput,
    ) -> (TransactionId, Vec<OutPoint>) {
        unimplemented!("fake implementation, only for tests");
    }

    async fn fund_output_dyn(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _output: InstancelessDynClientOutput,
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

    async fn transaction_update_stream(&self) -> BoxStream<OperationState<TxSubmissionStates>> {
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

    /// Creates a transaction that with an output of the primary module,
    /// claiming the given input and transferring its value into the client's
    /// wallet.
    ///
    /// The transactions submission state machine as well as the state
    /// machines responsible for the generated output are generated
    /// automatically. The caller is responsible for the input's state machines,
    /// should there be any required.
    pub async fn claim_input<I, S>(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        input: ClientInput<I, S>,
    ) -> (TransactionId, Vec<OutPoint>)
    where
        I: IInput + MaybeSend + MaybeSync + 'static,
        S: IState + MaybeSend + MaybeSync + 'static,
    {
        self.claim_input_dyn(
            dbtx,
            InstancelessDynClientInput {
                input: Box::new(input.input),
                keys: input.keys,
                state_machines: states_to_instanceless_dyn(input.state_machines),
            },
        )
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
        output: ClientOutput<O, S>,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)>
    where
        O: IOutput + MaybeSend + MaybeSync + 'static,
        S: IState + MaybeSend + MaybeSync + 'static,
    {
        self.fund_output_dyn(
            dbtx,
            InstancelessDynClientOutput {
                output: Box::new(output.output),
                state_machines: states_to_instanceless_dyn(output.state_machines),
            },
        )
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
}

fn states_to_instanceless_dyn<S: IState + MaybeSend + MaybeSync + 'static>(
    state_gen: StateGenerator<S>,
) -> StateGenerator<Box<maybe_add_send_sync!(dyn IState + 'static)>> {
    Arc::new(move |txid, out_idx| {
        let states: Vec<S> = state_gen(txid, out_idx);
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

    fn client_config(&self) -> &ClientConfig {
        self.client.config()
    }

    async fn claim_input_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        input: InstancelessDynClientInput,
    ) -> (TransactionId, Vec<OutPoint>) {
        let instance_input = ClientInput {
            input: DynInput::from_parts(self.module_instance_id, input.input),
            keys: input.keys,
            state_machines: states_add_instance(self.module_instance_id, input.state_machines),
        };

        self.client
            .finalize_and_submit_transaction_inner(
                &mut dbtx.global_tx().to_ref_nc(),
                self.operation,
                TransactionBuilder::new().with_input(instance_input),
            )
            .await
            .expect("Can only fail if additional funding is needed")
    }

    async fn fund_output_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        output: InstancelessDynClientOutput,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)> {
        let instance_output = ClientOutput {
            output: DynOutput::from_parts(self.module_instance_id, output.output),
            state_machines: states_add_instance(self.module_instance_id, output.state_machines),
        };

        self.client
            .finalize_and_submit_transaction_inner(
                &mut dbtx.global_tx().to_ref_nc(),
                self.operation,
                TransactionBuilder::new().with_output(instance_output),
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

    async fn transaction_update_stream(&self) -> BoxStream<OperationState<TxSubmissionStates>> {
        self.client.transaction_update_stream(self.operation).await
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

/// Atomically-counted ([`Arc`]) handle to [`Client`]
///
/// Notably it `deref`-s to the [`Client`] where most
/// methods live.
#[derive(Debug)]
pub struct ClientArc {
    // Use [`ClientArc::new`] instead
    inner: Option<Arc<Client>>,

    __use_constructor_to_create: (),
}

impl ClientArc {
    /// Create
    fn new(inner: Arc<Client>) -> Self {
        inner
            .client_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            inner: Some(inner),
            // this is the constructor
            __use_constructor_to_create: (),
        }
    }

    fn as_inner(&self) -> &Arc<Client> {
        self.inner.as_ref().expect("Inner always set")
    }

    pub async fn start_executor(&self) {
        self.as_inner().start_executor().await
    }

    /// Block for the `client` to no longer contain any strong references.
    ///
    /// Some parts of the code can temporarily clone client to perform some
    /// actions. No further strong references guarantees that the `client`
    /// is no longer used inside the system.
    pub async fn wait_until_fully_dropped(self) {
        let weak = self.downgrade();
        drop(self);

        for attempt in 0u64.. {
            if Weak::strong_count(&weak.inner) == 0 {
                break;
            }
            // we want to retry fast, give feedback, but not spam
            if attempt % 100 == 0 {
                info!("Waiting for ArcClient to stop being used");
            }
            fedimint_core::task::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl ops::Deref for ClientArc {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().expect("Must have inner client set")
    }
}

impl ClientArc {
    pub fn downgrade(&self) -> ClientWeak {
        ClientWeak {
            inner: Arc::downgrade(self.inner.as_ref().expect("Inner always set")),
        }
    }
}

impl Clone for ClientArc {
    fn clone(&self) -> Self {
        ClientArc::new(self.inner.clone().expect("Must have inner client set"))
    }
}

/// Like [`ClientArc`] but using a [`Weak`] handle to [`Client`]
#[derive(Debug, Clone)]
pub struct ClientWeak {
    inner: Weak<Client>,
}

impl ClientWeak {
    pub fn upgrade(&self) -> Option<ClientArc> {
        Weak::upgrade(&self.inner).map(ClientArc::new)
    }
}

/// We need a separate drop implementation for `Client` that triggers
/// `Executor::stop_executor` even though the `Drop` implementation of
/// `ExecutorInner` should already take care of that. The reason is that as long
/// as the executor task is active there may be a cycle in the
/// `Arc<Client>`s such that at least one `Executor` never gets dropped.
impl Drop for ClientArc {
    fn drop(&mut self) {
        // Not sure if Ordering::SeqCst is strictly needed here, but better safe than
        // sorry.
        let client_count = self
            .as_inner()
            .client_count
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

        // `fetch_sub` returns previous value, so if it is 1, it means this is the last
        // client reference
        if client_count == 1 {
            info!("Last client reference dropped, shutting down client task group");
            let inner = self.inner.take().expect("Must have inner client set");
            inner.executor.stop_executor();

            #[cfg(not(target_family = "wasm"))]
            {
                if RuntimeHandle::current().runtime_flavor() == RuntimeFlavor::CurrentThread {
                    // We can't use block_on in single-threaded mode
                    return;
                }

                let db = inner.db.clone();
                let federation_id = inner.federation_id();

                drop(inner);

                // wait until `self.inner.db` is the only strong reference
                for attempt in 0u64.. {
                    let strong_count = db.strong_count();
                    if strong_count <= 1 {
                        break;
                    }
                    tokio::task::block_in_place(|| {
                        futures::executor::block_on(async {
                            // we want to retry fast, give feedback, but not spam
                            if attempt % 100 == 0 {
                                info!(
                                    %federation_id,
                                    strong_count,
                                    "Waiting for client database to stop being used"
                                );
                            }
                            fedimint_core::task::sleep(Duration::from_millis(10)).await;
                        });
                    });
                }
            }
        }
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

impl<'m, M> ops::Deref for ClientModuleInstance<'m, M>
where
    M: ClientModule,
{
    type Target = M;

    fn deref(&self) -> &Self::Target {
        self.module
    }
}

pub struct Client {
    config: ClientConfig,
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
    secp_ctx: Secp256k1<secp256k1_zkp::All>,

    task_group: TaskGroup,
    /// Number of [`ClientArc`] instances using this `Client`.
    ///
    /// The `Client` struct is both used for the client itself as well as
    /// for the global context used in the state machine executor. This means we
    /// cannot rely on the reference count of the `Arc<Client>` to
    /// determine if the client should shut down.
    client_count: AtomicUsize,

    /// Updates about client recovery progress
    client_recovery_progress_receiver:
        watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryProgress>>,
}

impl Client {
    /// Initialize a client builder that can be configured to create a new
    /// client.
    pub fn builder(db: Database) -> ClientBuilder {
        ClientBuilder::new(db)
    }

    pub fn api(&self) -> &(dyn IGlobalFederationApi + 'static) {
        self.api.as_ref()
    }

    pub fn api_clone(&self) -> DynGlobalApi {
        self.api.clone()
    }

    pub async fn get_config_from_db(db: &Database) -> Option<ClientConfig> {
        let mut dbtx = db.begin_transaction().await;
        #[allow(clippy::let_and_return)]
        let config = dbtx
            .find_by_prefix(&ClientConfigKeyPrefix)
            .await
            .next()
            .await
            .map(|(_, config)| config);
        config
    }

    pub async fn store_encodable_client_secret<T: Encodable>(
        db: &Database,
        secret: T,
    ) -> anyhow::Result<()> {
        let mut dbtx = db.begin_transaction().await;

        // Don't overwrite an existing secret
        match dbtx.get_value(&EncodedClientSecretKey).await {
            Some(_) => bail!("Encoded client secret already exists, cannot overwrite"),
            None => {
                let encoded_secret = T::consensus_encode_to_vec(&secret);
                dbtx.insert_entry(&EncodedClientSecretKey, &encoded_secret)
                    .await;
                dbtx.commit_tx().await;
                Ok(())
            }
        }
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
                T::consensus_decode(&mut client_secret.as_slice(), &Default::default())
                    .map_err(|e| anyhow!("Decoding failed: {e}"))?,
            ),
            None => None,
        })
    }

    pub async fn load_or_generate_client_secret(db: &Database) -> anyhow::Result<[u8; 64]> {
        let client_secret = match Self::load_decodable_client_secret::<[u8; 64]>(db).await {
            Ok(secret) => secret,
            Err(_) => {
                let secret = PlainRootSecretStrategy::random(&mut thread_rng());
                Self::store_encodable_client_secret(db, secret)
                    .await
                    .expect("Storing client secret must work");
                secret
            }
        };
        Ok(client_secret)
    }

    pub async fn is_initialized(db: &Database) -> bool {
        Self::get_config_from_db(db).await.is_some()
    }

    pub async fn start_executor(self: &Arc<Self>) {
        debug!(
            "Starting fedimint client executor (version: {})",
            fedimint_build_code_version_env!()
        );
        self.executor.start_executor(self.context_gen()).await;
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

    fn config(&self) -> &ClientConfig {
        &self.config
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

    /// Determines if a transaction is underfunded, overfunded or balanced
    ///
    /// # Panics
    /// If any of the input or output versions in the transaction builder are
    /// unknown by the respective module.
    fn transaction_builder_balance(
        &self,
        builder: &TransactionBuilder,
    ) -> TransactionBuilderBalance {
        // FIXME: prevent overflows, currently not suitable for untrusted input
        let mut in_amount = Amount::ZERO;
        let mut out_amount = Amount::ZERO;
        let mut fee_amount = Amount::ZERO;

        for input in &builder.inputs {
            let module = self.get_module(input.input.module_instance_id());
            let item_amount = module.input_amount(&input.input).expect(
                "We only build transactions with input versions that are supported by the module",
            );
            in_amount += item_amount.amount;
            fee_amount += item_amount.fee;
        }

        for output in &builder.outputs {
            let module = self.get_module(output.output.module_instance_id());
            let item_amount = module.output_amount(&output.output).expect(
                "We only build transactions with output versions that are supported by the module",
            );
            out_amount += item_amount.amount;
            fee_amount += item_amount.fee;
        }

        let total_out_amount = out_amount + fee_amount;

        match total_out_amount.cmp(&in_amount) {
            Ordering::Equal => TransactionBuilderBalance::Balanced,
            Ordering::Less => TransactionBuilderBalance::Overfunded(in_amount - total_out_amount),
            Ordering::Greater => {
                TransactionBuilderBalance::Underfunded(total_out_amount - in_amount)
            }
        }
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

    /// Adds funding to a transaction or removes over-funding via change.
    async fn finalize_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        mut partial_transaction: TransactionBuilder,
    ) -> anyhow::Result<(Transaction, Vec<DynState>, Range<u64>)> {
        if let TransactionBuilderBalance::Underfunded(missing_amount) =
            self.transaction_builder_balance(&partial_transaction)
        {
            let inputs = self
                .primary_module()
                .create_sufficient_input(
                    self.primary_module_instance,
                    dbtx,
                    operation_id,
                    missing_amount,
                )
                .await?;
            partial_transaction.inputs.extend(inputs);
        }

        // This is the range of mint outputs that will be added to the transaction
        // in order to balance it. Notice that it may stay empty in case the transaction
        // is already balanced.
        let mut change_range = Range {
            start: partial_transaction.outputs.len() as u64,
            end: partial_transaction.outputs.len() as u64,
        };

        if let TransactionBuilderBalance::Overfunded(excess_amount) =
            self.transaction_builder_balance(&partial_transaction)
        {
            let change_outputs = self
                .primary_module()
                .create_exact_output(
                    self.primary_module_instance,
                    dbtx,
                    operation_id,
                    excess_amount,
                )
                .await;

            // We add our new mint outputs to the change range
            change_range.end += change_outputs.len() as u64;
            partial_transaction.outputs.extend(change_outputs);
        }

        assert!(
            matches!(
                self.transaction_builder_balance(&partial_transaction),
                TransactionBuilderBalance::Balanced
            ),
            "Transaction is balanced after the previous two operations"
        );

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
                        if Client::operation_exists(dbtx, operation_id).await {
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

        ensure!(
            transaction.consensus_encode_to_vec().len() <= Transaction::MAX_TX_SIZE,
            "The generated transaction would be rejected by the federation for being too large."
        );

        let txid = transaction.tx_hash();
        let change_outpoints = change_range
            .into_iter()
            .map(|out_idx| OutPoint { txid, out_idx })
            .collect();

        let tx_submission_sm = DynState::from_typed(
            TRANSACTION_SUBMISSION_MODULE_INSTANCE,
            OperationState {
                operation_id,
                state: TxSubmissionStates::Created(transaction),
            },
        );
        states.push(tx_submission_sm);

        self.executor.add_state_machines_dbtx(dbtx, states).await?;

        Ok((txid, change_outpoints))
    }

    async fn transaction_update_stream(
        &self,
        operation_id: OperationId,
    ) -> BoxStream<'static, OperationState<TxSubmissionStates>> {
        self.executor
            .notifier()
            .module_notifier::<OperationState<TxSubmissionStates>>(
                TRANSACTION_SUBMISSION_MODULE_INSTANCE,
            )
            .subscribe(operation_id)
            .await
    }

    async fn operation_exists(
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

    pub async fn has_active_states(&self, operation_id: OperationId) -> bool {
        let all_active_states = self.executor.get_active_states().await;
        all_active_states
            .into_iter()
            .any(|context| context.0.operation_id() == operation_id)
    }

    /// Returns a reference to a typed module client instance by kind
    pub fn get_first_module<M: ClientModule>(&self) -> ClientModuleInstance<M> {
        let module_kind = M::kind();
        let id = self
            .get_first_instance(&module_kind)
            .unwrap_or_else(|| panic!("No modules found of kind {module_kind}"));
        let module: &M = self
            .try_get_module(id)
            .unwrap_or_else(|| panic!("Unknown module instance {id}"))
            .as_any()
            .downcast_ref::<M>()
            .unwrap_or_else(|| panic!("Module is not of type {}", std::any::type_name::<M>()));
        ClientModuleInstance {
            id,
            db: self.db().with_prefix_module_id(id),
            api: self.api().with_module(id),
            module,
        }
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
            .map(|(kind, _)| kind == module_kind)
            .unwrap_or(false)
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

    /// Returns the config with which the client was initialized.
    pub fn get_config(&self) -> &ClientConfig {
        &self.config
    }

    /// Returns the config of the client in JSON format.
    ///
    /// Compared to the consensus module format where module configs are binary
    /// encoded this format cannot be cryptographically verified but is easier
    /// to consume and to some degree human-readable.
    pub fn get_config_json(&self) -> JsonClientConfig {
        JsonClientConfig {
            global: self.get_config().global.clone(),
            modules: self
                .get_config()
                .modules
                .iter()
                .map(|(instance_id, ClientModuleConfig { kind, config, .. })| {
                    (
                        *instance_id,
                        JsonWithKind::new(
                            kind.clone(),
                            config.clone().expect_decoded().to_json().into(),
                        ),
                    )
                })
                .collect(),
        }
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

    pub async fn discover_common_api_version(&self) -> anyhow::Result<ApiVersionSet> {
        Ok(self
            .api()
            .discover_api_version_set(
                &Self::supported_api_versions_summary_static(self.get_config(), &self.module_inits)
                    .await,
            )
            .await?)
    }

    /// Query the federation for API version support and then calculate
    /// the best API version to use (supported by most guardians).
    pub async fn discover_common_api_version_static(
        config: &ClientConfig,
        client_module_init: &ClientModuleInitRegistry,
        api: &DynGlobalApi,
    ) -> anyhow::Result<ApiVersionSet> {
        Ok(api
            .discover_api_version_set(
                &Self::supported_api_versions_summary_static(config, client_module_init).await,
            )
            .await?)
    }

    /// [`SupportedApiVersionsSummary`] that the client and its modules support
    pub async fn supported_api_versions_summary_static(
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

    /// Load the common api versions to use from cache and start a background
    /// process to refresh them.
    ///
    /// This is a compromise, so we not have to wait for version discovery to
    /// complete every time a [`Client`] is being built.
    async fn load_and_refresh_common_api_version_static(
        config: &ClientConfig,
        module_inits: &ModuleInitRegistry<DynClientModuleInit>,
        api: &DynGlobalApi,
        db: &Database,
    ) -> anyhow::Result<ApiVersionSet> {
        if let Some(v) = db
            .begin_transaction()
            .await
            .get_value(&CachedApiVersionSetKey)
            .await
        {
            debug!("Found existing cached common api versions");
            let config = config.clone();
            let module_inits = module_inits.clone();
            let api = api.clone();
            let db = db.clone();
            // Separate task group, because we actually don't want to be waiting for this to
            // finish, and it's just best effort.
            TaskGroup::new()
                .spawn("refresh_common_api_version_static", |_| async move {
                    if let Err(e) =
                        Self::refresh_common_api_version_static(&config, &module_inits, &api, &db)
                            .await
                    {
                        warn!("Failed to discover common api versions: {e}");
                    }
                })
                .await;

            return Ok(v.0);
        }

        debug!("No existing cached common api versions found, waiting for initial discovery");
        Self::refresh_common_api_version_static(config, module_inits, api, db).await
    }

    async fn refresh_common_api_version_static(
        config: &ClientConfig,
        module_inits: &ModuleInitRegistry<DynClientModuleInit>,
        api: &DynGlobalApi,
        db: &Database,
    ) -> anyhow::Result<ApiVersionSet> {
        debug!("Refreshing common api versions");

        let common_api_versions =
            Client::discover_common_api_version_static(config, module_inits, api).await?;

        debug!("Updating the cached common api versions");
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
                move |dbtx, _| {
                    Box::pin(async move {
                        Self::set_metadata_dbtx(dbtx, metadata).await;
                        Ok(())
                    })
                },
                None,
            )
            .await
            .expect("Failed to autocommit metadata")
    }

    pub async fn has_pending_recoveries(&self) -> bool {
        !self
            .client_recovery_progress_receiver
            .borrow()
            .iter()
            .any(|(_id, progress)| !progress.is_done())
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
                !in_progress
                    .iter()
                    .any(|(_id, progress)| !progress.is_done())
            })
            .await
            .context("Recovery task completed and update receiver disconnected, but some modules failed to recover")?;

        Ok(())
    }

    pub async fn wait_for_module_kind_recovery(
        &self,
        module_kind: ModuleKind,
    ) -> anyhow::Result<()> {
        let mut recovery_receiver = self.client_recovery_progress_receiver.clone();
        recovery_receiver
            .wait_for(|in_progress| {
                !in_progress
                    .iter()
                    .filter(|(module_instance_id, _progress)| {
                        self.config.modules[module_instance_id].kind == module_kind
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
            fedimint_core::task::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    /// Set the client [`Metadata`]
    pub async fn set_metadata_dbtx(dbtx: &mut DatabaseTransaction<'_>, metadata: &Metadata) {
        dbtx.insert_new_entry(&ClientMetadataKey, metadata).await;
    }

    async fn spawn_module_recoveries_task(
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
        self.task_group
            .spawn("module recoveries", move |_task_handle| async move {
                Self::run_module_recoveries_task(
                    db,
                    recovery_sender,
                    module_recoveries,
                    module_recovery_progress_receivers,
                )
                .await
            })
            .await;
    }

    async fn run_module_recoveries_task(
        db: Database,
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
        let mut completed_stream = Vec::new();
        let progress_stream = futures::stream::FuturesUnordered::new();

        for (module_instance_id, f) in module_recoveries.into_iter() {
            completed_stream.push(futures::stream::once(Box::pin(async move {
                match f.await {
                    Ok(_) => (module_instance_id, None),
                    Err(err) => {
                        warn!(%err, module_instance_id, "Module recovery failed");
                        // a module recovery that failed reports and error and
                        // just never finishes, so we don't need a separate state
                        // for it
                        futures::future::pending::<Option<RecoveryProgress>>().await;
                        unreachable!()
                    }
                }
            })));
        }

        for (module_instance_id, rx) in module_recovery_progress_receivers.into_iter() {
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

            let progress = if let Some(progress) = progress {
                progress
            } else {
                recovery_sender
                    .borrow()
                    .get(&module_instance_id)
                    .expect("existing progress must be present")
                    .to_complete()
            };

            info!(
                module_instance_id,
                progress = format!("{}/{}", progress.complete, progress.total),
                "Recovery progress"
            );

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
    }
}

/// See [`Client::transaction_updates`]
pub struct TransactionUpdates {
    update_stream: BoxStream<'static, OperationState<TxSubmissionStates>>,
}

impl TransactionUpdates {
    /// Waits for the transaction to be accepted or rejected as part of the
    /// operation to which the `TransactionUpdates` object is subscribed.
    pub async fn await_tx_accepted(self, await_txid: TransactionId) -> Result<(), String> {
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
            .await
    }
}

/// Federation config and meta data that can be used to show a preview of the
/// federation one is about to join or to initialize a client.
#[derive(Debug, Clone)]
pub struct FederationInfo {
    config: ClientConfig,
    // TODO: make non-optional or remove
    invite_code: Option<InviteCode>,
}

impl FederationInfo {
    /// Download federation info using invitation code
    pub async fn from_invite_code(invite: InviteCode) -> anyhow::Result<FederationInfo> {
        let config = try_download_config(invite.clone(), 10).await?;
        Ok(FederationInfo {
            config,
            invite_code: Some(invite),
        })
    }

    /// Create `FederationInfo` from config, may download further meta data in
    /// the future
    pub async fn from_config(config: ClientConfig) -> anyhow::Result<FederationInfo> {
        // The return type is a result in case we want to fallibly fetch additional meta
        // data in the future
        Ok(FederationInfo {
            config,
            invite_code: None,
        })
    }

    /// Returns the federations configuration
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// If the federation info was created from
    pub fn invite_code(&self) -> Option<InviteCode> {
        self.invite_code.clone()
    }

    /// Get the value of a given meta field
    pub fn meta<V: serde::de::DeserializeOwned>(&self, key: &str) -> anyhow::Result<Option<V>> {
        let Some(str_value) = self.config.global.meta.get(key) else {
            return Ok(None);
        };
        serde_json::from_str(str_value).context(format!("Decoding meta field '{key}' failed"))
    }

    /// Creates an API client for the federation
    pub fn api(&self) -> DynGlobalApi {
        DynGlobalApi::from_config(&self.config)
    }

    pub fn federation_id(&self) -> FederationId {
        self.config.global.federation_id()
    }
}

pub struct ClientBuilder {
    module_inits: ClientModuleInitRegistry,
    primary_module_instance: Option<ModuleInstanceId>,
    db: Database,
    stopped: bool,
}

impl ClientBuilder {
    fn new(db: Database) -> Self {
        ClientBuilder {
            module_inits: Default::default(),
            primary_module_instance: Default::default(),
            db,
            stopped: false,
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
        )
    }

    async fn migrate_database(&self) -> anyhow::Result<()> {
        // Only apply the client database migrations if the database has been
        // initialized.
        if let Ok(client_config) = self.load_existing_config().await {
            for (module_id, module_cfg) in client_config.modules {
                let kind = module_cfg.kind.clone();
                let Some(init) = self.module_inits.get(&kind) else {
                    warn!("Detected configuration for unsupported module id: {module_id}, kind: {kind}");
                    continue;
                };

                apply_migrations(
                    self.db(),
                    kind.to_string(),
                    init.database_version(),
                    init.get_database_migrations(),
                    Some(module_id),
                )
                .await?;
            }
        }

        Ok(())
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub async fn load_existing_config(&self) -> anyhow::Result<ClientConfig> {
        let Some(config) = Client::get_config_from_db(&self.db).await else {
            bail!("Client database not initialized")
        };

        Ok(config)
    }

    async fn init(
        self,
        root_secret: DerivableSecret,
        config: ClientConfig,
        invite_code: InviteCode,
        init_mode: InitMode,
    ) -> anyhow::Result<ClientArc> {
        if Client::is_initialized(&self.db).await {
            bail!("Client database already initialized")
        }

        // Note: It's important all client initialization is performed as one big
        // transaction to avoid half-initialized client state.
        {
            debug!(target: LOG_CLIENT, "Initializing client database");
            let mut dbtx = self.db.begin_transaction().await;
            // Save config to DB
            dbtx.insert_new_entry(
                &ClientConfigKey {
                    id: config.federation_id(),
                },
                &config,
            )
            .await;
            dbtx.insert_new_entry(&ClientInviteCodeKey {}, &invite_code)
                .await;

            let init_state = InitState::Pending(init_mode);
            dbtx.insert_entry(&ClientInitStateKey, &init_state).await;

            let metadata = init_state
                .does_require_recovery()
                .flatten()
                .map(|s| s.metadata)
                .unwrap_or(Metadata::empty());

            dbtx.insert_new_entry(&ClientMetadataKey, &metadata).await;

            dbtx.commit_tx_result().await?;
        }
        let stopped = self.stopped;

        let client = self.build_stopped(root_secret, config).await?;
        if !stopped {
            client.as_inner().start_executor().await;
        }
        Ok(client)
    }

    /// Join a new Federation
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
    pub async fn join(
        self,
        root_secret: DerivableSecret,
        config: ClientConfig,
        invite_code: InviteCode,
    ) -> anyhow::Result<ClientArc> {
        self.init(root_secret, config, invite_code, InitMode::Fresh)
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
        invite_code: InviteCode,
    ) -> anyhow::Result<ClientArc> {
        let api = DynGlobalApi::from_config(&config);
        let snapshot = Client::download_backup_from_federation_static(
            &api,
            &Self::federation_root_secret(&root_secret, &config),
            &self.decoders(&config),
        )
        .await?;

        let client = self
            .init(
                root_secret,
                config,
                invite_code,
                InitMode::Recover {
                    snapshot: snapshot.clone(),
                },
            )
            .await?;

        Ok(client)
    }

    pub async fn open(self, root_secret: DerivableSecret) -> anyhow::Result<ClientArc> {
        let Some(config) = Client::get_config_from_db(&self.db).await else {
            bail!("Client database not initialized")
        };
        let stopped = self.stopped;

        let client = self.build_stopped(root_secret, config).await?;
        if !stopped {
            client.as_inner().start_executor().await;
        }
        Ok(client)
    }

    /// Build a [`Client`] but do not start the executor
    async fn build_stopped(
        self,
        root_secret: DerivableSecret,
        config: ClientConfig,
    ) -> anyhow::Result<ClientArc> {
        let decoders = self.decoders(&config);
        let config = Self::config_decoded(config, &decoders)?;
        let db = self.db.with_decoders(decoders.clone());
        let api = DynGlobalApi::from_config(&config);

        // Migrate the database before interacting with it in case any on-disk data
        // structures have changed.
        self.migrate_database().await?;

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
        )
        .await?;

        let mut module_recoveries: BTreeMap<
            ModuleInstanceId,
            Pin<Box<maybe_add_send!(dyn Future<Output = anyhow::Result<()>>)>>,
        > = Default::default();
        let mut module_recovery_progress_receivers: BTreeMap<
            ModuleInstanceId,
            watch::Receiver<RecoveryProgress>,
        > = Default::default();

        let final_client = FinalClient::default();

        let root_secret = Self::federation_root_secret(&root_secret, &config);

        let modules = {
            let mut modules = ClientModuleRegistry::default();
            for (module_instance_id, module_config) in config.modules.clone() {
                let kind = module_config.kind().clone();
                let Some(module_init) = self.module_inits.get(&kind).cloned() else {
                    warn!("Module kind {kind} of instance {module_instance_id} not found in module gens, skipping");
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
                        let config = config.clone();
                        let module_config = module_config.clone();
                        let db = db.clone();
                        let kind = kind.clone();
                        let notifier = notifier.clone();
                        let api = api.clone();
                        let root_secret = root_secret.clone();
                        let final_client = final_client.clone();
                        let (progress_tx, progress_rx) = tokio::sync::watch::channel(progress);
                        let module_init = module_init.clone();
                        (
                            Box::pin(async move {
                                module_init
                                        .recover(
                                            final_client.clone(),
                                            config.global.federation_id(),
                                            module_config.clone(),
                                            db.clone(),
                                            module_instance_id,
                                            api_version,
                                            root_secret.derive_module_secret(module_instance_id),
                                            notifier.clone(),
                                            api.clone(),
                                            snapshot.as_ref().and_then(|s| s.modules.get(&module_instance_id).to_owned()),
                                            progress_tx,
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
                        debug!(
                            id = %module_instance_id,
                            %kind, "Starting new module recovery"
                        );
                        Some(start_module_recover_fn(snapshot, RecoveryProgress::none()))
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
                            config.global.federation_id(),
                            module_config,
                            db.clone(),
                            module_instance_id,
                            api_version,
                            // This is a divergence from the legacy client, where the child secret
                            // keys were derived using *module kind*-specific derivation paths.
                            // Since the new client has to support multiple, segregated modules of
                            // the same kind we have to use the instance id instead.
                            root_secret.derive_module_secret(module_instance_id),
                            notifier.clone(),
                            api.clone(),
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

            for (module_instance_id, _) in module_recoveries.iter() {
                executor_builder.with_valid_module_id(*module_instance_id);
            }

            executor_builder.build(db.clone(), notifier).await
        };

        let recovery_receiver_init_val = BTreeMap::from_iter(
            module_recovery_progress_receivers
                .iter()
                .map(|(module_instance_id, rx)| (*module_instance_id, *rx.borrow())),
        );
        let (client_recovery_progress_sender, client_recovery_progress_receiver) =
            watch::channel(recovery_receiver_init_val);

        let client_inner = Arc::new(Client {
            config: config.clone(),
            decoders,
            db: db.clone(),
            federation_id: config.global.federation_id(),
            federation_meta: config.global.meta,
            primary_module_instance,
            modules,
            module_inits: self.module_inits.clone(),
            executor,
            api,
            secp_ctx: Secp256k1::new(),
            root_secret,
            task_group: TaskGroup::new(),
            operation_log: OperationLog::new(db),
            client_count: Default::default(),
            client_recovery_progress_receiver,
        });

        let client_arc = ClientArc::new(client_inner);

        final_client.set(client_arc.downgrade());

        if !module_recoveries.is_empty() {
            client_arc
                .spawn_module_recoveries_task(
                    client_recovery_progress_sender,
                    module_recoveries,
                    module_recovery_progress_receivers,
                )
                .await;
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
        config: ClientConfig,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<ClientConfig, fedimint_core::encoding::DecodeError> {
        config.clone().redecode_raw(decoders)
    }

    /// Re-derive client's root_secret using the federation ID. This eliminates
    /// the possibility of having the same client root_secret across
    /// multiple federations.
    fn federation_root_secret(
        root_secret: &DerivableSecret,
        config: &ClientConfig,
    ) -> DerivableSecret {
        root_secret.federation_key(&config.global.federation_id())
    }
}

pub async fn get_invite_code_from_db(db: &Database) -> Option<InviteCode> {
    let mut dbtx = db.begin_transaction().await;
    #[allow(clippy::let_and_return)]
    let invite = dbtx
        .find_by_prefix(&ClientInviteCodeKeyPrefix)
        .await
        .next()
        .await
        .map(|(_, invite)| invite);
    invite
}

/// Tries to download the client config from the federation,
/// attempts up to `retries` number times
async fn try_download_config(
    invite_code: InviteCode,
    max_retries: usize,
) -> anyhow::Result<ClientConfig> {
    debug!(target: LOG_CLIENT, "Download client config");
    let api = DynGlobalApi::from_invite_code(&[invite_code.clone()]);
    let mut num_retries = 0;
    let wait_millis = 500;
    loop {
        if num_retries > max_retries {
            break Err(anyhow!("Failed to download client config"));
        }
        match api.download_client_config(&invite_code).await {
            Ok(cfg) => {
                break Ok(cfg);
            }
            Err(e) => {
                debug!("Failed to download client config {:?}", e);
                sleep(Duration::from_millis(wait_millis)).await;
            }
        }
        num_retries += 1;
    }
}

/// Fetches the encoded client secret from the database and decodes it.
/// If an encoded client secret is not present in the database, or if
/// decoding fails, an error is returned.
pub async fn get_decoded_client_secret<T: Decodable>(db: &Database) -> anyhow::Result<T> {
    let mut tx = db.begin_transaction().await;
    let client_secret = tx.get_value(&EncodedClientSecretKey).await;
    tx.commit_tx().await;

    match client_secret {
        Some(client_secret) => {
            T::consensus_decode(&mut client_secret.as_slice(), &Default::default())
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
            info!("Detected configuration for unsupported module id: {id}, kind: {kind}");
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
