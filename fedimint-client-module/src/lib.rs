#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::explicit_deref_methods)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]

use std::fmt::Debug;
use std::ops::{self};
use std::sync::Arc;

use fedimint_api_client::api::{DynGlobalApi, DynModuleApi};
use fedimint_core::config::ClientConfig;
pub use fedimint_core::core::{IInput, IOutput, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiAuth, ApiVersion};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{
    PeerId, TransactionId, apply, async_trait_maybe_send, dyn_newtype_define, maybe_add_send_sync,
};
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use fedimint_logging::LOG_CLIENT;
use futures::StreamExt;
use module::OutPointRange;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;
use transaction::{
    ClientInputBundle, ClientInputSM, ClientOutput, ClientOutputSM, TxSubmissionStatesSM,
};

pub use crate::module::{ClientModule, StateGenerator};
use crate::sm::executor::ContextGen;
use crate::sm::{ClientSMDatabaseTransaction, DynState, IState, State};
use crate::transaction::{ClientInput, ClientOutputBundle, TxSubmissionStates};

pub mod api;

pub mod db;

pub mod backup;
/// Environment variables
pub mod envs;
pub mod meta;
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

pub mod api_version_discovery;

#[derive(Serialize, Deserialize)]
pub struct TxCreatedEvent {
    pub txid: TransactionId,
    pub operation_id: OperationId,
}

impl Event for TxCreatedEvent {
    const MODULE: Option<ModuleKind> = None;
    const KIND: EventKind = EventKind::from_static("tx-created");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

#[derive(Serialize, Deserialize)]
pub struct TxAcceptedEvent {
    txid: TransactionId,
    operation_id: OperationId,
}

impl Event for TxAcceptedEvent {
    const MODULE: Option<ModuleKind> = None;
    const KIND: EventKind = EventKind::from_static("tx-accepted");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
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
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

#[derive(Serialize, Deserialize)]
pub struct ModuleRecoveryStarted {
    module_id: ModuleInstanceId,
}

impl ModuleRecoveryStarted {
    pub fn new(module_id: ModuleInstanceId) -> Self {
        Self { module_id }
    }
}

impl Event for ModuleRecoveryStarted {
    const MODULE: Option<ModuleKind> = None;
    const KIND: EventKind = EventKind::from_static("module-recovery-started");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

#[derive(Serialize, Deserialize)]
pub struct ModuleRecoveryCompleted {
    pub module_id: ModuleInstanceId,
}

impl Event for ModuleRecoveryCompleted {
    const MODULE: Option<ModuleKind> = None;
    const KIND: EventKind = EventKind::from_static("module-recovery-completed");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
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
    /// interface [`fedimint_api_client::api::IGlobalFederationApi`] typically
    /// does not provide the necessary functionality, for this extension
    /// traits like [`fedimint_api_client::api::IGlobalFederationApi`] have
    /// to be used.
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
    ) -> anyhow::Result<OutPointRange>;

    /// This function is mostly meant for internal use, you are probably looking
    /// for [`DynGlobalClientContext::fund_output`].
    /// Returns transaction id of the funding transaction and an optional
    /// `OutPoint` that represents change if change was added.
    async fn fund_output_dyn(
        &self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        outputs: InstancelessDynClientOutputBundle,
    ) -> anyhow::Result<OutPointRange>;

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
        persist: EventPersistence,
    );

    async fn transaction_update_stream(&self) -> BoxStream<TxSubmissionStatesSM>;

    /// Returns the core API version that the federation supports
    async fn core_api_version(&self) -> ApiVersion;
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
    ) -> anyhow::Result<OutPointRange> {
        unimplemented!("fake implementation, only for tests");
    }

    async fn fund_output_dyn(
        &self,
        _dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        _outputs: InstancelessDynClientOutputBundle,
    ) -> anyhow::Result<OutPointRange> {
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
        _persist: EventPersistence,
    ) {
        unimplemented!("fake implementation, only for tests");
    }

    async fn transaction_update_stream(&self) -> BoxStream<TxSubmissionStatesSM> {
        unimplemented!("fake implementation, only for tests");
    }

    async fn core_api_version(&self) -> ApiVersion {
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
    ) -> anyhow::Result<OutPointRange>
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
    ) -> anyhow::Result<OutPointRange>
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
            <E as Event>::PERSISTENCE,
        )
        .await;
    }
}

fn states_to_instanceless_dyn<S: IState + MaybeSend + MaybeSync + 'static>(
    state_gen: StateGenerator<S>,
) -> StateGenerator<Box<maybe_add_send_sync!(dyn IState + 'static)>> {
    Arc::new(move |out_point_range| {
        let states: Vec<S> = state_gen(out_point_range);
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

fn states_add_instance(
    module_instance_id: ModuleInstanceId,
    state_gen: StateGenerator<Box<maybe_add_send_sync!(dyn IState + 'static)>>,
) -> StateGenerator<DynState> {
    Arc::new(move |out_point_range| {
        let states = state_gen(out_point_range);
        Iterator::collect(
            states
                .into_iter()
                .map(|state| DynState::from_parts(module_instance_id, state)),
        )
    })
}

pub type ModuleGlobalContextGen = ContextGen;

/// Resources particular to a module instance
pub struct ClientModuleInstance<'m, M: ClientModule> {
    /// Instance id of the module
    pub id: ModuleInstanceId,
    /// Module-specific DB
    pub db: Database,
    /// Module-specific API
    pub api: DynModuleApi,

    pub module: &'m M,
}

impl<'m, M: ClientModule> ClientModuleInstance<'m, M> {
    /// Get a reference to the module
    pub fn inner(&self) -> &'m M {
        self.module
    }
}

impl<M> ops::Deref for ClientModuleInstance<'_, M>
where
    M: ClientModule,
{
    type Target = M;

    fn deref(&self) -> &Self::Target {
        self.module
    }
}
#[derive(Deserialize)]
pub struct GetInviteCodeRequest {
    pub peer: PeerId,
}

pub struct TransactionUpdates {
    pub update_stream: BoxStream<'static, TxSubmissionStatesSM>,
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

    pub async fn await_any_tx_accepted(self) -> Result<(), String> {
        self.update_stream
            .filter_map(|tx_update| {
                std::future::ready(match tx_update.state {
                    TxSubmissionStates::Accepted(..) => Some(Ok(())),
                    TxSubmissionStates::Rejected(.., submit_error) => Some(Err(submit_error)),
                    _ => None,
                })
            })
            .next_or_pending()
            .await
    }
}

/// Admin (guardian) identification and authentication
pub struct AdminCreds {
    /// Guardian's own `peer_id`
    pub peer_id: PeerId,
    /// Authentication details
    pub auth: ApiAuth,
}
