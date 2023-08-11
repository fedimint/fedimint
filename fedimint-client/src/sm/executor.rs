use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::io::{Error, Read, Write};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::bail;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{AutocommitError, Database, DatabaseKeyWithNotify, DatabaseTransaction};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::fmt_utils::AbbreviateJson;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::spawn;
use fedimint_core::util::BoxFuture;
use fedimint_core::{maybe_add_send_sync, task};
use futures::future::select_all;
use futures::stream::StreamExt;
use tokio::select;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, error, info, trace, warn};

use super::state::StateTransitionFunction;
use crate::sm::notifier::Notifier;
use crate::sm::state::{DynContext, DynState};
use crate::sm::{ClientSMDatabaseTransaction, GlobalContext, OperationId, State, StateTransition};

/// After how many attempts a DB transaction is aborted with an error
const MAX_DB_ATTEMPTS: Option<usize> = Some(100);

/// Wait time till checking the DB for new state machines when there are no
/// active ones
const EXECUTOR_POLL_INTERVAL: Duration = Duration::from_secs(1);

pub type ContextGen<GC> =
    Arc<maybe_add_send_sync!(dyn Fn(ModuleInstanceId, OperationId) -> GC + 'static)>;

/// Prefixes for executor DB entries
enum ExecutorDbPrefixes {
    /// See [`ActiveStateKey`]
    ActiveStates = 0xa1,
    /// See [`InactiveStateKey`]
    InactiveStates = 0xa2,
}

/// Executor that drives forward state machines under its management.
///
/// Each state transition is atomic and supposed to be idempotent such that a
/// stop/crash of the executor at any point can be recovered from on restart.
/// The executor is aware of the concept of Fedimint modules and can give state
/// machines a different [execution context](super::state::Context) depending on
/// the owning module, making it very flexible.
#[derive(Clone, Debug)]
pub struct Executor<GC: GlobalContext> {
    inner: Arc<ExecutorInner<GC>>,
}

struct ExecutorInner<GC> {
    db: Database,
    context: Mutex<Option<ContextGen<GC>>>,
    module_contexts: BTreeMap<ModuleInstanceId, DynContext>,
    notifier: Notifier<GC>,
    shutdown_executor: Mutex<Option<oneshot::Sender<oneshot::Sender<()>>>>,
}

/// Builder to which module clients can be attached and used to build an
/// [`Executor`] supporting these.
#[derive(Debug, Default)]
pub struct ExecutorBuilder {
    module_contexts: BTreeMap<ModuleInstanceId, DynContext>,
}

impl<GC> Executor<GC>
where
    GC: GlobalContext,
{
    /// Creates an [`ExecutorBuilder`]
    pub fn builder() -> ExecutorBuilder {
        ExecutorBuilder::default()
    }

    pub async fn get_active_states(&self) -> Vec<(DynState<GC>, ActiveState)> {
        self.inner.get_active_states().await
    }

    /// Adds a number of state machines to the executor atomically. They will be
    /// driven to completion automatically in the background.
    ///
    /// **Attention**: do not use before background task is started!
    // TODO: remove warning once finality is an inherent state attribute
    pub async fn add_state_machines(&self, states: Vec<DynState<GC>>) -> anyhow::Result<()> {
        self.inner
            .db
            .autocommit(
                |dbtx| Box::pin(self.add_state_machines_dbtx(dbtx, states.clone())),
                MAX_DB_ATTEMPTS,
            )
            .await
            .map_err(|e| match e {
                AutocommitError::CommitFailed {
                    last_error,
                    attempts,
                } => last_error.context(format!("Failed to commit after {attempts} attempts")),
                AutocommitError::ClosureError { error, .. } => error,
            })?;

        // TODO: notify subscribers to state changes?

        Ok(())
    }

    /// Adds a number of state machines to the executor atomically with other DB
    /// changes is `dbtx`. See [`Executor::add_state_machines`] for more
    /// details.
    ///
    /// ## Panics
    /// If called before background task is started using
    /// [`Executor::start_executor`]!
    // TODO: remove warning once finality is an inherent state attribute
    pub async fn add_state_machines_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        states: Vec<DynState<GC>>,
    ) -> anyhow::Result<()> {
        for state in states {
            if !self
                .inner
                .module_contexts
                .contains_key(&state.module_instance_id())
            {
                bail!("Unknown module");
            }

            let is_active_state = dbtx
                .get_value(&ActiveStateKey::from_state(state.clone()))
                .await
                .is_some();
            let is_inactive_state = dbtx
                .get_value(&InactiveStateKey::from_state(state.clone()))
                .await
                .is_some();

            if is_active_state || is_inactive_state {
                bail!("State already exists in database!")
            }

            let context = {
                let context_gen_guard = self.inner.context.lock().await;
                let context_gen = context_gen_guard
                    .as_ref()
                    .expect("should be initialized at this point");
                context_gen(state.module_instance_id(), state.operation_id())
            };

            if state.is_terminal(
                self.inner
                    .module_contexts
                    .get(&state.module_instance_id())
                    .expect("No such module"),
                &context,
            ) {
                bail!("State is already terminal, adding it to the executor doesn't make sense.")
            }

            dbtx.insert_entry(
                &ActiveStateKey::from_state(state.clone()),
                &ActiveState::new(),
            )
            .await;
            let notify_sender = self.inner.notifier.sender();
            dbtx.on_commit(move || notify_sender.notify(state));
        }

        Ok(())
    }

    /// **Mostly used for testing**
    ///
    /// Check if state exists in the database as part of an actively running
    /// state machine.
    pub async fn contains_active_state<S: State<GlobalContext = GC>>(
        &self,
        instance: ModuleInstanceId,
        state: S,
    ) -> bool {
        let state = DynState::from_typed(instance, state);
        self.inner
            .get_active_states()
            .await
            .into_iter()
            .any(|(s, _)| s == state)
    }

    // TODO: unify querying fns
    /// **Mostly used for testing**
    ///
    /// Check if state exists in the database as inactive. If the state is
    /// terminal it means the corresponding state machine finished its
    /// execution. If the state is non-terminal it means the state machine was
    /// in that state at some point but moved on since then.
    pub async fn contains_inactive_state<S: State<GlobalContext = GC>>(
        &self,
        instance: ModuleInstanceId,
        state: S,
    ) -> bool {
        let state = DynState::from_typed(instance, state);
        self.inner
            .get_inactive_states()
            .await
            .into_iter()
            .any(|(s, _)| s == state)
    }

    pub async fn await_inactive_state(&self, state: DynState<GC>) -> InactiveState {
        self.inner
            .db
            .wait_key_exists(&InactiveStateKey::from_state(state))
            .await
    }

    pub async fn await_active_state(&self, state: DynState<GC>) -> ActiveState {
        self.inner
            .db
            .wait_key_exists(&ActiveStateKey::from_state(state))
            .await
    }

    /// Returns all IDs of operations that have active state machines
    pub async fn get_active_operations(&self) -> HashSet<OperationId> {
        self.inner
            .get_active_states()
            .await
            .into_iter()
            .map(|(state, _)| state.operation_id())
            .collect()
    }

    /// Starts the background thread that runs the state machines. This cannot
    /// be done when building the executor since some global contexts in turn
    /// may depend on the executor, forming a cyclic dependency.
    ///
    /// ## Panics
    /// If called more than once.
    pub async fn start_executor(&self, context_gen: ContextGen<GC>) {
        let replaced_old_context_gen = self
            .inner
            .context
            .lock()
            .await
            .replace(context_gen.clone())
            .is_some();
        assert!(
            !replaced_old_context_gen,
            "start_executor was called previously"
        );

        let (shutdown_sender, shutdown_receiver) =
            tokio::sync::oneshot::channel::<tokio::sync::oneshot::Sender<()>>();

        let replaced_old_shutdown_sender = self
            .inner
            .shutdown_executor
            .lock()
            .await
            .replace(shutdown_sender)
            .is_some();
        assert!(
            !replaced_old_shutdown_sender,
            "start_executor was called previously"
        );

        let task_runner_inner = self.inner.clone();
        let _handle = spawn(async move {
            let executor_runner = task_runner_inner.run(context_gen);
            select! {
                shutdown_happened_sender = shutdown_receiver => {
                    match shutdown_happened_sender {
                        Ok(shutdown_happened_sender) => {
                            info!("Shutting down state machine executor runner due to shutdown signal");
                            let _ = shutdown_happened_sender.send(());
                        },
                        Err(_) => {
                            error!("Shutting down state machine executor runner because the shutdown signal channel was closed (the executor object was dropped)");
                        }
                    }
                },
                _ = executor_runner => {
                    error!("State machine executor runner exited unexpectedly!");
                },
            };
        });
    }

    /// Stops the background task that runs the state machines.
    ///
    /// If a shutdown signal was sent it returns a [`oneshot::Receiver`] that
    /// will be signalled when the main loop of the background task has
    /// exited. This can be useful to block until the executor has stopped
    /// to avoid errors due to the async runtime shutting down while the
    /// task is still running.
    ///
    /// If no shutdown signal was sent it returns `None`. This can happen if
    /// `stop_executor` is called multiple times.
    ///
    /// ## Panics
    /// If called in parallel with [`start_executor`](Self::start_executor).
    pub fn stop_executor(&self) -> Option<oneshot::Receiver<()>> {
        self.inner.stop_executor()
    }

    /// Returns a reference to the [`Notifier`] that can be used to subscribe to
    /// state transitions
    pub fn notifier(&self) -> &Notifier<GC> {
        &self.inner.notifier
    }
}

impl<GC> Drop for ExecutorInner<GC> {
    fn drop(&mut self) {
        self.stop_executor();
    }
}

type TransitionForActiveState<GC> = (
    serde_json::Value,
    DynState<GC>,
    StateTransitionFunction<DynState<GC>>,
    ActiveState,
);
impl<GC> ExecutorInner<GC>
where
    GC: GlobalContext,
{
    async fn run(&self, global_context_gen: ContextGen<GC>) {
        info!("Starting state machine executor task");
        loop {
            if let Err(err) = self
                .execute_next_state_transitions(&global_context_gen)
                .await
            {
                warn!(
                    %err,
                    "An unexpected error occurred during a state transition"
                );
            }
        }
    }

    fn get_transition_for(
        &self,
        state: DynState<GC>,
        meta: ActiveState,
        global_context_gen: &ContextGen<GC>,
    ) -> Option<BoxFuture<TransitionForActiveState<GC>>> {
        let module_instance = state.module_instance_id();
        let context = &self
            .module_contexts
            .get(&module_instance)
            .expect("Unknown module");
        let transitions = state
            .transitions(
                context,
                &global_context_gen(module_instance, state.operation_id()),
            )
            .into_iter()
            .map(|transition| {
                let state = state.clone();
                let f: BoxFuture<TransitionForActiveState<GC>> = Box::pin(async move {
                    let StateTransition {
                        trigger,
                        transition,
                    } = transition;
                    (trigger.await, state, transition, meta)
                });
                f
            })
            .collect::<Vec<_>>();
        if transitions.is_empty() {
            None
        } else {
            Some(Box::pin(async move {
                let (first_completed_result, _index, _unused_transitions) =
                    select_all(transitions).await;
                first_completed_result
            }))
        }
    }

    async fn execute_next_state_transitions(
        &self,
        global_context_gen: &ContextGen<GC>,
    ) -> anyhow::Result<()> {
        let active_states = self.get_active_states().await;
        // TODO: use DB prefix subscription instead of polling
        let mut active_state_count = active_states.len();
        if active_states.is_empty() {
            // FIXME: what to do in this case? Probably best to subscribe to DB eventually
            debug!("No state transitions available, waiting before re-trying");
            task::sleep(EXECUTOR_POLL_INTERVAL).await;
            return Ok(());
        }
        trace!("Active states: {:?}", active_states);

        let mut transitions = active_states
            .into_iter()
            .flat_map(|(state, meta)| self.get_transition_for(state, meta, global_context_gen))
            .collect::<Vec<_>>();

        loop {
            if active_state_count == 0 {
                debug!(
                    "No state transitions remaining, exiting execute_next_state_transitions loops"
                );
                return Ok(());
            }
            let num_states = active_state_count;
            let num_transitions = transitions.len();
            debug!(
                num_states,
                num_transitions, "Awaiting any state transition to become ready"
            );
            let new_state_added = async move {
                loop {
                    // Prioritize existing active states over new states
                    fedimint_core::task::sleep(EXECUTOR_POLL_INTERVAL).await;
                    let new_active_states_count = self.get_active_states().await.len();
                    if new_active_states_count > active_state_count {
                        return;
                    }
                }
            };
            let (completed_result, _index, remaining_transitions) = select! {
                res = select_all(transitions) => res,
                () = new_state_added => {
                    debug!("New state added, re-starting state transitions");
                    return Ok(());
                }
            };
            transitions = remaining_transitions;
            let (transition_outcome, state, transition_fn, meta) = completed_result;
            debug!(
                ?state,
                transition_outcome = ?AbbreviateJson(&transition_outcome),
                "Executing state transition"
            );

            let active_or_inactive_state = self
                .db
                .autocommit(
                    |dbtx| {
                        let state = state.clone();
                        let transition_fn = transition_fn.clone();
                        let transition_outcome = transition_outcome.clone();
                        Box::pin(async move {
                            let new_state = transition_fn(
                                &mut ClientSMDatabaseTransaction::new(
                                    dbtx,
                                    state.module_instance_id(),
                                ),
                                transition_outcome,
                                state.clone(),
                            )
                            .await;
                            dbtx.remove_entry(&ActiveStateKey::from_state(state.clone()))
                                .await;
                            dbtx.insert_entry(
                                &InactiveStateKey::from_state(state.clone()),
                                &meta.into_inactive(),
                            )
                            .await;

                            let context = &self
                                .module_contexts
                                .get(&state.module_instance_id())
                                .expect("Unknown module");

                            let global_context = global_context_gen(
                                state.module_instance_id(),
                                state.operation_id(),
                            );
                            if new_state.is_terminal(context, &global_context) {
                                // TODO: log state machine id or something
                                debug!("State machine reached terminal state");
                                let k = InactiveStateKey::from_state(new_state.clone());
                                let v = ActiveState::new().into_inactive();
                                dbtx.insert_entry(&k, &v).await;
                                Ok(ActiveOrInactiveState::Inactive {
                                    dyn_state: new_state,
                                })
                            } else {
                                let k = ActiveStateKey::from_state(new_state.clone());
                                let v = ActiveState::new();
                                dbtx.insert_entry(&k, &v).await;
                                Ok(ActiveOrInactiveState::Active {
                                    dyn_state: new_state,
                                    active_state: v,
                                })
                            }
                        })
                    },
                    Some(100),
                )
                .await
                .map_err(|e| match e {
                    AutocommitError::CommitFailed {
                        last_error,
                        attempts,
                    } => last_error.context(format!("Failed to commit after {attempts} attempts")),
                    AutocommitError::ClosureError { error, .. } => error,
                })?;

            active_state_count -= 1;
            match active_or_inactive_state {
                ActiveOrInactiveState::Active {
                    dyn_state,
                    active_state,
                } => {
                    if let Some(transition) =
                        self.get_transition_for(dyn_state.clone(), active_state, global_context_gen)
                    {
                        active_state_count += 1;
                        transitions.push(transition);
                    }
                    self.notifier.notify(dyn_state);
                }
                ActiveOrInactiveState::Inactive { dyn_state } => {
                    self.notifier.notify(dyn_state);
                }
            }
        }
    }

    async fn get_active_states(&self) -> Vec<(DynState<GC>, ActiveState)> {
        self.db
            .begin_transaction()
            .await
            .find_by_prefix(&ActiveStateKeyPrefix::<GC>::new())
            .await
            .map(|(state, meta)| (state.state, meta))
            .collect::<Vec<_>>()
            .await
    }

    async fn get_inactive_states(&self) -> Vec<(DynState<GC>, InactiveState)> {
        self.db
            .begin_transaction()
            .await
            .find_by_prefix(&InactiveStateKeyPrefix::new())
            .await
            .map(|(state, meta)| (state.state, meta))
            .collect::<Vec<_>>()
            .await
    }
}

impl<GC> ExecutorInner<GC> {
    /// See [`Executor::stop_executor`].
    fn stop_executor(&self) -> Option<oneshot::Receiver<()>> {
        let Some(shutdown_sender) = self
            .shutdown_executor
            .try_lock()
            .expect("Only locked during startup, no collisions should be possible")
            .take()
        else {
            debug!("Executor already stopped, ignoring stop request");
            return None;
        };

        let (shutdown_confirmation_sender, shutdown_confirmation_receiver) =
            oneshot::channel::<()>();

        if shutdown_sender.send(shutdown_confirmation_sender).is_err() {
            warn!("Failed to send shutdown signal to executor, already dead?");
        }

        Some(shutdown_confirmation_receiver)
    }
}

impl<GC: GlobalContext> Debug for ExecutorInner<GC> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (active, inactive) = futures::executor::block_on(async {
            let active_states = self.get_active_states().await;
            let inactive_states = self.get_inactive_states().await;
            (active_states, inactive_states)
        });
        writeln!(f, "ExecutorInner {{")?;
        writeln!(f, "    active_states: {active:?}")?;
        writeln!(f, "    inactive_states: {inactive:?}")?;
        writeln!(f, "}}")?;

        Ok(())
    }
}

impl ExecutorBuilder {
    /// Allow executor being built to run state machines associated with the
    /// supplied module
    pub fn with_module<C>(&mut self, instance_id: ModuleInstanceId, context: C)
    where
        C: IntoDynInstance<DynType = DynContext>,
    {
        self.with_module_dyn(context.into_dyn(instance_id));
    }

    /// Allow executor being built to run state machines associated with the
    /// supplied module
    pub fn with_module_dyn(&mut self, context: DynContext) {
        if self
            .module_contexts
            .insert(context.module_instance_id(), context)
            .is_some()
        {
            panic!("Tried to add two modules with the same instance id!");
        }
    }

    /// Build [`Executor`] and spawn background task in `tasks` executing active
    /// state machines. The supplied database `db` must support isolation, so
    /// cannot be an isolated DB instance itself.
    pub async fn build<GC>(self, db: Database, notifier: Notifier<GC>) -> Executor<GC>
    where
        GC: GlobalContext,
    {
        let inner = Arc::new(ExecutorInner {
            db,
            context: Mutex::new(None),
            module_contexts: self.module_contexts,
            notifier,
            shutdown_executor: Default::default(),
        });

        debug!(
            instances = ?inner.module_contexts.keys().copied().collect::<Vec<_>>(),
            "Initialized state machine executor with module instances"
        );
        Executor { inner }
    }
}

/// A state that is able to make progress eventually
#[derive(Debug)]
pub struct ActiveStateKey<GC> {
    // TODO: remove redundant operation id from state trait
    pub operation_id: OperationId,
    pub state: DynState<GC>,
}

impl<GC> ActiveStateKey<GC> {
    pub(crate) fn from_state(state: DynState<GC>) -> ActiveStateKey<GC> {
        ActiveStateKey {
            operation_id: state.operation_id(),
            state,
        }
    }
}

impl<GC> Encodable for ActiveStateKey<GC> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += self.state.consensus_encode(writer)?;
        Ok(len)
    }
}

impl<GC> Decodable for ActiveStateKey<GC>
where
    GC: GlobalContext,
{
    fn consensus_decode<R: Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let operation_id = OperationId::consensus_decode(reader, modules)?;
        let state = DynState::consensus_decode(reader, modules)?;

        Ok(ActiveStateKey {
            operation_id,
            state,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ActiveOperationStateKeyPrefix<GC> {
    pub operation_id: OperationId,
    pub _pd: PhantomData<GC>,
}

impl<GC> Encodable for ActiveOperationStateKeyPrefix<GC> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.operation_id.consensus_encode(writer)
    }
}

impl<GC> ::fedimint_core::db::DatabaseLookup for ActiveOperationStateKeyPrefix<GC>
where
    GC: GlobalContext,
{
    type Record = ActiveStateKey<GC>;
}

#[derive(Debug)]
pub(crate) struct ActiveModuleOperationStateKeyPrefix<GC> {
    pub operation_id: OperationId,
    pub module_instance: ModuleInstanceId,
    pub _pd: PhantomData<GC>,
}

impl<GC> Encodable for ActiveModuleOperationStateKeyPrefix<GC> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += self.module_instance.consensus_encode(writer)?;
        Ok(len)
    }
}

impl<GC> ::fedimint_core::db::DatabaseLookup for ActiveModuleOperationStateKeyPrefix<GC>
where
    GC: GlobalContext,
{
    type Record = ActiveStateKey<GC>;
}

#[derive(Debug)]
struct ActiveStateKeyPrefix<GC>(PhantomData<GC>);

impl<GC> ActiveStateKeyPrefix<GC> {
    pub fn new() -> Self {
        ActiveStateKeyPrefix(PhantomData)
    }
}

impl<GC> Encodable for ActiveStateKeyPrefix<GC> {
    fn consensus_encode<W: Write>(&self, _writer: &mut W) -> Result<usize, Error> {
        Ok(0)
    }
}

#[derive(Debug, Copy, Clone, Encodable, Decodable)]
pub struct ActiveState {
    pub created_at: SystemTime,
}

impl<GC> ::fedimint_core::db::DatabaseRecord for ActiveStateKey<GC>
where
    GC: GlobalContext,
{
    const DB_PREFIX: u8 = ExecutorDbPrefixes::ActiveStates as u8;
    const NOTIFY_ON_MODIFY: bool = true;
    type Key = Self;
    type Value = ActiveState;
}

impl<GC> DatabaseKeyWithNotify for ActiveStateKey<GC> where GC: GlobalContext {}

impl<GC> ::fedimint_core::db::DatabaseLookup for ActiveStateKeyPrefix<GC>
where
    GC: GlobalContext,
{
    type Record = ActiveStateKey<GC>;
}

impl ActiveState {
    fn new() -> ActiveState {
        ActiveState {
            created_at: fedimint_core::time::now(),
        }
    }

    fn into_inactive(self) -> InactiveState {
        InactiveState {
            created_at: self.created_at,
            exited_at: fedimint_core::time::now(),
        }
    }
}

/// A past or final state of a state machine
#[derive(Debug, Clone)]
pub struct InactiveStateKey<GC> {
    // TODO: remove redundant operation id from state trait
    pub operation_id: OperationId,
    pub state: DynState<GC>,
}

impl<GC> InactiveStateKey<GC> {
    pub(crate) fn from_state(state: DynState<GC>) -> InactiveStateKey<GC> {
        InactiveStateKey {
            operation_id: state.operation_id(),
            state,
        }
    }
}

impl<GC> Encodable for InactiveStateKey<GC>
where
    GC: GlobalContext,
{
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += self.state.consensus_encode(writer)?;
        Ok(len)
    }
}

impl<GC> Decodable for InactiveStateKey<GC>
where
    GC: GlobalContext,
{
    fn consensus_decode<R: Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let operation_id = OperationId::consensus_decode(reader, modules)?;
        let state = DynState::consensus_decode(reader, modules)?;

        Ok(InactiveStateKey {
            operation_id,
            state,
        })
    }
}

#[derive(Debug)]
pub(crate) struct InactiveOperationStateKeyPrefix<GC> {
    pub operation_id: OperationId,
    pub _pd: PhantomData<GC>,
}

impl<GC> Encodable for InactiveOperationStateKeyPrefix<GC> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.operation_id.consensus_encode(writer)
    }
}

impl<GC> ::fedimint_core::db::DatabaseLookup for InactiveOperationStateKeyPrefix<GC>
where
    GC: GlobalContext,
{
    type Record = InactiveStateKey<GC>;
}

#[derive(Debug)]
pub(crate) struct InactiveModuleOperationStateKeyPrefix<GC> {
    pub operation_id: OperationId,
    pub module_instance: ModuleInstanceId,
    pub _pd: PhantomData<GC>,
}

impl<GC> Encodable for InactiveModuleOperationStateKeyPrefix<GC> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += self.module_instance.consensus_encode(writer)?;
        Ok(len)
    }
}

impl<GC> ::fedimint_core::db::DatabaseLookup for InactiveModuleOperationStateKeyPrefix<GC>
where
    GC: GlobalContext,
{
    type Record = InactiveStateKey<GC>;
}

#[derive(Debug, Clone)]
struct InactiveStateKeyPrefix<GC>(PhantomData<GC>);

impl<GC> InactiveStateKeyPrefix<GC> {
    pub fn new() -> Self {
        InactiveStateKeyPrefix(PhantomData)
    }
}

impl<GC> Encodable for InactiveStateKeyPrefix<GC> {
    fn consensus_encode<W: Write>(&self, _writer: &mut W) -> Result<usize, Error> {
        Ok(0)
    }
}

#[derive(Debug, Copy, Clone, Decodable, Encodable)]
pub struct InactiveState {
    pub created_at: SystemTime,
    pub exited_at: SystemTime,
}

impl<GC> ::fedimint_core::db::DatabaseRecord for InactiveStateKey<GC>
where
    GC: GlobalContext,
{
    const DB_PREFIX: u8 = ExecutorDbPrefixes::InactiveStates as u8;
    const NOTIFY_ON_MODIFY: bool = true;
    type Key = Self;
    type Value = InactiveState;
}

impl<GC> DatabaseKeyWithNotify for InactiveStateKey<GC> where GC: GlobalContext {}

impl<GC> ::fedimint_core::db::DatabaseLookup for InactiveStateKeyPrefix<GC>
where
    GC: GlobalContext,
{
    type Record = InactiveStateKey<GC>;
}

enum ActiveOrInactiveState<GC> {
    Active {
        dyn_state: DynState<GC>,
        active_state: ActiveState,
    },
    Inactive {
        dyn_state: DynState<GC>,
    },
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::sync::Arc;
    use std::time::Duration;

    use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind};
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::task::{self};
    use tokio::sync::broadcast::Sender;
    use tracing::{info, trace};

    use crate::sm::state::{Context, DynContext, DynState};
    use crate::sm::{Executor, Notifier, OperationId, State, StateTransition};

    #[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
    enum MockStateMachine {
        Start,
        ReceivedNonNull(u64),
        Final,
    }

    impl State for MockStateMachine {
        type ModuleContext = MockContext;
        type GlobalContext = ();

        fn transitions(
            &self,
            context: &Self::ModuleContext,
            _global_context: &(),
        ) -> Vec<StateTransition<Self>> {
            match self {
                MockStateMachine::Start => {
                    let mut receiver1 = context.broadcast.subscribe();
                    let mut receiver2 = context.broadcast.subscribe();
                    vec![
                        StateTransition::new(
                            async move {
                                loop {
                                    let val = receiver1.recv().await.unwrap();
                                    if val == 0 {
                                        trace!("State transition Start->Final");
                                        break;
                                    }
                                }
                            },
                            |_dbtx, (), _state| Box::pin(async move { MockStateMachine::Final }),
                        ),
                        StateTransition::new(
                            async move {
                                loop {
                                    let val = receiver2.recv().await.unwrap();
                                    if val != 0 {
                                        trace!("State transition Start->ReceivedNonNull");
                                        break val;
                                    }
                                }
                            },
                            |_dbtx, value, _state| {
                                Box::pin(async move { MockStateMachine::ReceivedNonNull(value) })
                            },
                        ),
                    ]
                }
                MockStateMachine::ReceivedNonNull(prev_val) => {
                    let prev_val = *prev_val;
                    let mut receiver = context.broadcast.subscribe();
                    vec![StateTransition::new(
                        async move {
                            loop {
                                let val = receiver.recv().await.unwrap();
                                if val == prev_val {
                                    trace!("State transition ReceivedNonNull->Final");
                                    break;
                                }
                            }
                        },
                        |_dbtx, (), _state| Box::pin(async move { MockStateMachine::Final }),
                    )]
                }
                MockStateMachine::Final => {
                    vec![]
                }
            }
        }

        fn operation_id(&self) -> OperationId {
            OperationId([0u8; 32])
        }
    }

    impl IntoDynInstance for MockStateMachine {
        type DynType = DynState<()>;

        fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
            DynState::from_typed(instance_id, self)
        }
    }

    #[derive(Debug, Clone)]
    struct MockContext {
        broadcast: tokio::sync::broadcast::Sender<u64>,
    }

    impl IntoDynInstance for MockContext {
        type DynType = DynContext;

        fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
            DynContext::from_typed(instance_id, self)
        }
    }

    impl Context for MockContext {}

    async fn get_executor() -> (Executor<()>, Sender<u64>, Database) {
        let (broadcast, _) = tokio::sync::broadcast::channel(10);

        let mut decoder_builder = Decoder::builder();
        decoder_builder.with_decodable_type::<MockStateMachine>();
        let decoder = decoder_builder.build();

        let decoders =
            ModuleDecoderRegistry::new(vec![(42, ModuleKind::from_static_str("test"), decoder)]);
        let db = Database::new(MemDatabase::new(), decoders);

        let mut executor_builder = Executor::<()>::builder();
        executor_builder.with_module(
            42,
            MockContext {
                broadcast: broadcast.clone(),
            },
        );
        let executor = executor_builder
            .build(db.clone(), Notifier::new(db.clone()))
            .await;
        executor.start_executor(Arc::new(|_, _| ())).await;

        info!("Initialized test executor");
        (executor, broadcast, db)
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_executor() {
        const MOCK_INSTANCE_1: ModuleInstanceId = 42;
        const MOCK_INSTANCE_2: ModuleInstanceId = 21;

        let (executor, sender, _db) = get_executor().await;
        executor
            .add_state_machines(vec![DynState::from_typed(
                MOCK_INSTANCE_1,
                MockStateMachine::Start,
            )])
            .await
            .unwrap();

        assert!(
            executor
                .add_state_machines(vec![DynState::from_typed(
                    MOCK_INSTANCE_1,
                    MockStateMachine::Start
                )])
                .await
                .is_err(),
            "Running the same state machine a second time should fail"
        );

        assert!(
            executor
                .contains_active_state(MOCK_INSTANCE_1, MockStateMachine::Start)
                .await,
            "State was written to DB and waits for broadcast"
        );
        assert!(
            !executor
                .contains_active_state(MOCK_INSTANCE_2, MockStateMachine::Start)
                .await,
            "Instance separation works"
        );

        // TODO build await fn+timeout or allow manual driving of executor
        task::sleep(Duration::from_secs(1)).await;
        sender.send(0).unwrap();
        task::sleep(Duration::from_secs(2)).await;

        assert!(
            executor
                .contains_inactive_state(MOCK_INSTANCE_1, MockStateMachine::Final)
                .await,
            "State was written to DB and waits for broadcast"
        );
    }
}
