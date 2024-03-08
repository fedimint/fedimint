use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use std::io::{Error, Read, Write};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::anyhow;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{
    AutocommitError, Database, DatabaseKeyWithNotify, DatabaseTransaction,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::fmt_utils::AbbreviateJson;
use fedimint_core::maybe_add_send_sync;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::BoxFuture;
use fedimint_logging::LOG_CLIENT_REACTOR;
use futures::future::{self, select_all};
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::select;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, error, info, trace, warn, Instrument};

use super::state::StateTransitionFunction;
use crate::sm::notifier::Notifier;
use crate::sm::state::{DynContext, DynState};
use crate::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use crate::{AddStateMachinesError, AddStateMachinesResult, DynGlobalClientContext};

/// After how many attempts a DB transaction is aborted with an error
const MAX_DB_ATTEMPTS: Option<usize> = Some(100);

pub type ContextGen =
    Arc<maybe_add_send_sync!(dyn Fn(ModuleInstanceId, OperationId) -> DynGlobalClientContext)>;

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
pub struct Executor {
    inner: Arc<ExecutorInner>,
}

struct ExecutorInner {
    db: Database,
    context: Mutex<Option<ContextGen>>,
    module_contexts: BTreeMap<ModuleInstanceId, DynContext>,
    valid_module_ids: BTreeSet<ModuleInstanceId>,
    notifier: Notifier,
    shutdown_executor: Mutex<Option<oneshot::Sender<()>>>,
    /// Any time executor should notice state machine update (e.g. because it
    /// was created), it's must be sent through this channel for it to notice.
    sm_update_tx: mpsc::UnboundedSender<DynState>,
    sm_update_rx: Mutex<Option<mpsc::UnboundedReceiver<DynState>>>,
    client_task_group: TaskGroup,
}

/// Builder to which module clients can be attached and used to build an
/// [`Executor`] supporting these.
#[derive(Debug, Default)]
pub struct ExecutorBuilder {
    module_contexts: BTreeMap<ModuleInstanceId, DynContext>,
    valid_module_ids: BTreeSet<ModuleInstanceId>,
}

impl Executor {
    /// Creates an [`ExecutorBuilder`]
    pub fn builder() -> ExecutorBuilder {
        ExecutorBuilder::default()
    }

    pub async fn get_active_states(&self) -> Vec<(DynState, ActiveStateMeta)> {
        self.inner.get_active_states().await
    }

    /// Adds a number of state machines to the executor atomically. They will be
    /// driven to completion automatically in the background.
    ///
    /// **Attention**: do not use before background task is started!
    // TODO: remove warning once finality is an inherent state attribute
    pub async fn add_state_machines(&self, states: Vec<DynState>) -> anyhow::Result<()> {
        self.inner
            .db
            .autocommit(
                |dbtx, _| Box::pin(self.add_state_machines_dbtx(dbtx, states.clone())),
                MAX_DB_ATTEMPTS,
            )
            .await
            .map_err(|e| match e {
                AutocommitError::CommitFailed {
                    last_error,
                    attempts,
                } => last_error.context(format!("Failed to commit after {attempts} attempts")),
                AutocommitError::ClosureError { error, .. } => anyhow!("{error:?}"),
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
        states: Vec<DynState>,
    ) -> AddStateMachinesResult {
        for state in states {
            if !self
                .inner
                .valid_module_ids
                .contains(&state.module_instance_id())
            {
                return Err(AddStateMachinesError::Other(anyhow!("Unknown module")));
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
                return Err(AddStateMachinesError::StateAlreadyExists);
            }

            // In case of recovery functions, the module itself is not yet initialized,
            // so we can't check if the state is terminal. However the
            // [`Self::get_transitions_for`] function will double check and
            // deactivate any terminal states that would slip past this check.
            if let Some(module_context) =
                self.inner.module_contexts.get(&state.module_instance_id())
            {
                let context = {
                    let context_gen_guard = self.inner.context.lock().await;
                    let context_gen = context_gen_guard
                        .as_ref()
                        .expect("should be initialized at this point");
                    context_gen(state.module_instance_id(), state.operation_id())
                };

                if state.is_terminal(module_context, &context) {
                    return Err(AddStateMachinesError::Other(anyhow!(
                        "State is already terminal, adding it to the executor doesn't make sense."
                    )));
                }
            }

            dbtx.insert_entry(
                &ActiveStateKey::from_state(state.clone()),
                &ActiveStateMeta::default(),
            )
            .await;
            let notify_sender = self.inner.notifier.sender();
            let sm_updates_tx = self.inner.sm_update_tx.clone();
            dbtx.on_commit(move || {
                notify_sender.notify(state.clone());
                let _ = sm_updates_tx.send(state);
            });
        }

        Ok(())
    }

    /// **Mostly used for testing**
    ///
    /// Check if state exists in the database as part of an actively running
    /// state machine.
    pub async fn contains_active_state<S: State>(
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
    pub async fn contains_inactive_state<S: State>(
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

    pub async fn await_inactive_state(&self, state: DynState) -> InactiveStateMeta {
        self.inner
            .db
            .wait_key_exists(&InactiveStateKey::from_state(state))
            .await
    }

    pub async fn await_active_state(&self, state: DynState) -> ActiveStateMeta {
        self.inner
            .db
            .wait_key_exists(&ActiveStateKey::from_state(state))
            .await
    }

    /// Starts the background thread that runs the state machines. This cannot
    /// be done when building the executor since some global contexts in turn
    /// may depend on the executor, forming a cyclic dependency.
    ///
    /// ## Panics
    /// If called more than once.
    pub async fn start_executor(&self, context_gen: ContextGen) {
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
        let sm_update_rx = self
            .inner
            .sm_update_rx
            .lock()
            .await
            .take()
            .expect("start_executor was called previously: no sm_update_rx available");

        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();

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
        let _handle = self.inner.client_task_group.spawn("state machine executor", |task_handle| async move {
            let executor_runner = task_runner_inner.run(context_gen, sm_update_rx);
            let task_group_shutdown_rx = task_handle.make_shutdown_rx().await;
            select! {
                _ = task_group_shutdown_rx => {
                    info!("Shutting down state machine executor runner due to task group shutdown signal");
                },
                shutdown_happened_sender = shutdown_receiver => {
                    match shutdown_happened_sender {
                        Ok(()) => {
                            info!("Shutting down state machine executor runner due to explicit shutdown signal");
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
        }).await;
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
    pub fn stop_executor(&self) -> Option<()> {
        self.inner.stop_executor()
    }

    /// Returns a reference to the [`Notifier`] that can be used to subscribe to
    /// state transitions
    pub fn notifier(&self) -> &Notifier {
        &self.inner.notifier
    }
}

impl Drop for ExecutorInner {
    fn drop(&mut self) {
        self.stop_executor();
    }
}

struct TransitionForActiveState {
    outcome: serde_json::Value,
    state: DynState,
    meta: ActiveStateMeta,
    transition_fn: StateTransitionFunction<DynState>,
}

impl ExecutorInner {
    async fn run(
        &self,
        global_context_gen: ContextGen,
        sm_update_rx: tokio::sync::mpsc::UnboundedReceiver<DynState>,
    ) {
        info!("Starting state machine executor task");
        if let Err(err) = self
            .run_state_machines_executor_inner(global_context_gen, sm_update_rx)
            .await
        {
            warn!(
                %err,
                "An unexpected error occurred during a state transition"
            );
        }
    }

    async fn get_transition_for(
        &self,
        state: &DynState,
        meta: ActiveStateMeta,
        global_context_gen: &ContextGen,
    ) -> Vec<BoxFuture<'static, TransitionForActiveState>> {
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
                let f: BoxFuture<TransitionForActiveState> = Box::pin(async move {
                    let StateTransition {
                        trigger,
                        transition,
                    } = transition;
                    TransitionForActiveState {
                        outcome: trigger.await,
                        state,
                        transition_fn: transition,
                        meta,
                    }
                });
                f
            })
            .collect::<Vec<_>>();
        if transitions.is_empty() {
            // In certain cases a terminal (no transitions) state could get here due to
            // module bug. Inactivate it to prevent accumulation of such states.
            // See [`Self::add_state_machines_dbtx`].
            warn!(module_id = module_instance, "A terminal state where only active states are expected. Please report this bug upstream.");
            self.db
                .autocommit::<_, _, anyhow::Error>(
                    |dbtx, _| {
                        Box::pin(async {
                            let k = InactiveStateKey::from_state(state.clone());
                            let v = ActiveStateMeta::default().into_inactive();
                            dbtx.remove_entry(&ActiveStateKey::from_state(state.clone()))
                                .await;
                            dbtx.insert_entry(&k, &v).await;
                            Ok(())
                        })
                    },
                    None,
                )
                .await
                .expect("Autocommit here can't fail");
        }

        transitions
    }

    async fn run_state_machines_executor_inner(
        &self,
        global_context_gen: ContextGen,
        mut sm_update_rx: tokio::sync::mpsc::UnboundedReceiver<DynState>,
    ) -> anyhow::Result<()> {
        let active_states = self.get_active_states().await;
        trace!(target: LOG_CLIENT_REACTOR, "Starting active states: {:?}", active_states);
        for (state, _meta) in active_states {
            self.sm_update_tx
                .send(state)
                .expect("Must be able to send state machine to own opened channel");
        }

        /// All futures in the executor resolve to this type, so the handling
        /// code can tell them apart.
        enum ExecutorLoopEvent {
            /// Notification about `DynState` arrived and should be handled,
            /// usually added to the list of pending futures.
            New { state: DynState },
            /// One of trigger futures of a state machine finished and
            /// returned transition function to run
            Triggered(TransitionForActiveState),
            /// Transition function and all the accounting around it are done
            Completed {
                state: DynState,
                outcome: ActiveOrInactiveState,
            },
            /// New job receiver disconnected, that can only mean termination
            Disconnected,
        }

        // Keeps track of things already running, so we can deduplicate, just
        // in case.
        let mut currently_running_sms = HashSet::<DynState>::new();
        // All things happening in parallel go into here
        let mut futures: FuturesUnordered<BoxFuture<'_, ExecutorLoopEvent>> =
            FuturesUnordered::new();

        loop {
            let event = tokio::select! {
                new = sm_update_rx.recv() => {
                    if let Some(new) = new {
                        ExecutorLoopEvent::New {
                            state: new,
                        }
                    } else {
                        ExecutorLoopEvent::Disconnected
                    }
                },

                event = futures.next(), if !futures.is_empty() => event.expect("we only .next() if there are pending futures"),
            };

            // main reactor loop: wait for next thing that completed, react (possibly adding
            // more things to `futures`)
            match event {
                ExecutorLoopEvent::New { state } => {
                    if currently_running_sms.contains(&state) {
                        warn!(target: LOG_CLIENT_REACTOR, operation_id = %state.operation_id(), "Received a state machine that is already running. Ignoring");
                        continue;
                    }
                    let Some(meta) = self.get_active_state(&state).await else {
                        warn!(target: LOG_CLIENT_REACTOR, operation_id = %state.operation_id(), "Couldn't look up received state machine. Ignoring.");
                        continue;
                    };

                    let transitions = self
                        .get_transition_for(&state, meta, &global_context_gen)
                        .await;
                    if transitions.is_empty() {
                        warn!(target: LOG_CLIENT_REACTOR, operation_id = %state.operation_id(), "Received an active state that doesn't produce any transitions. Ignoring.");
                        continue;
                    }

                    let transitions_num = transitions.len();
                    currently_running_sms.insert(state.clone());
                    futures.push(Box::pin(async move {
                        let (first_completed_result, _index, _unused_transitions) =
                            select_all(transitions).await;
                        ExecutorLoopEvent::Triggered(first_completed_result)
                    }));

                    info!(target: LOG_CLIENT_REACTOR, operation_id = %state.operation_id(), total = futures.len(), transitions_num, "Started new active state machine.");
                }
                ExecutorLoopEvent::Triggered(TransitionForActiveState {
                    outcome,
                    state,
                    meta,
                    transition_fn,
                }) => {
                    debug!(
                        target: LOG_CLIENT_REACTOR,
                        operation_id = %state.operation_id(),
                        "State machine trigger function complete. Starting transition function.",
                    );
                    let span = tracing::info_span!(
                        "state_machine_transition",
                        operation_id = %state.operation_id()
                    );
                    // Perform the transition as another future, so transitions can happen in
                    // parallel.
                    // Database write conflicts might be happening quite often here,
                    // but transaction functions are supposed to be idempotent anyway,
                    // so it seems like a good stress-test in the worst case.
                    futures.push({
                        let sm_update_tx = self.sm_update_tx.clone();
                        let db = self.db.clone();
                        let notifier = self.notifier.clone();
                        let module_contexts = self.module_contexts.clone();
                        let global_context_gen = global_context_gen.clone();
                        Box::pin(
                            async move {
                                info!(
                                    target: LOG_CLIENT_REACTOR,
                                    operation_id = %state.operation_id(),
                                    "Executing state transition",
                                );
                                debug!(
                                    target: LOG_CLIENT_REACTOR,
                                    operation_id = %state.operation_id(),
                                    ?state,
                                    outcome = ?AbbreviateJson(&outcome),
                                    "Executing state transition (details)",
                                );

                                let module_contexts = &module_contexts;
                                let global_context_gen = &global_context_gen;

                                let outcome = db
                                    .autocommit::<'_, '_, _, _, Infallible>(
                                        |dbtx, _| {
                                            let state = state.clone();
                                            let transition_fn = transition_fn.clone();
                                            let transition_outcome = outcome.clone();
                                            Box::pin(async move {
                                                let new_state = transition_fn(
                                                    &mut ClientSMDatabaseTransaction::new(
                                                        &mut dbtx.to_ref(),
                                                        state.module_instance_id(),
                                                    ),
                                                    transition_outcome,
                                                    state.clone(),
                                                )
                                                .await;
                                                dbtx.remove_entry(&ActiveStateKey::from_state(
                                                    state.clone(),
                                                ))
                                                .await;
                                                dbtx.insert_entry(
                                                    &InactiveStateKey::from_state(state.clone()),
                                                    &meta.into_inactive(),
                                                )
                                                .await;

                                                let context = &module_contexts
                                                    .get(&state.module_instance_id())
                                                    .expect("Unknown module");

                                                let global_context = global_context_gen(
                                                    state.module_instance_id(),
                                                    state.operation_id(),
                                                );
                                                if new_state.is_terminal(context, &global_context) {
                                                    let k = InactiveStateKey::from_state(
                                                        new_state.clone(),
                                                    );
                                                    let v = ActiveStateMeta::default().into_inactive();
                                                    dbtx.insert_entry(&k, &v).await;
                                                    Ok(ActiveOrInactiveState::Inactive {
                                                        dyn_state: new_state,
                                                    })
                                                } else {
                                                    let k = ActiveStateKey::from_state(
                                                        new_state.clone(),
                                                    );
                                                    let v = ActiveStateMeta::default();
                                                    dbtx.insert_entry(&k, &v).await;
                                                    Ok(ActiveOrInactiveState::Active {
                                                        dyn_state: new_state,
                                                        meta: v,
                                                    })
                                                }
                                            })
                                        },
                                        None,
                                    )
                                    .await
                                    .expect("autocommit should keep trying to commit (max_attempt: None) and body doesn't return errors");

                                debug!(
                                    target: LOG_CLIENT_REACTOR,
                                    operation_id = %state.operation_id(),
                                    terminal = !outcome.is_active(),
                                    ?outcome,
                                    "Finished executing state transition",
                                );

                                match &outcome {
                                    ActiveOrInactiveState::Active { dyn_state, meta: _ } => {
                                        sm_update_tx
                                            .send(dyn_state.clone())
                                            .expect("can't fail: we are the receiving end");
                                        notifier.notify(dyn_state.clone());
                                    }
                                    ActiveOrInactiveState::Inactive { dyn_state } => {
                                        notifier.notify(dyn_state.clone());
                                    }
                                }
                                ExecutorLoopEvent::Completed { state, outcome }
                            }
                            .instrument(span),
                        )
                    });
                }
                ExecutorLoopEvent::Completed { state, outcome } => {
                    assert!(
                        currently_running_sms.remove(&state),
                        "State must have been recorded"
                    );
                    info!(
                        target: LOG_CLIENT_REACTOR,
                        operation_id = %state.operation_id(),
                        outcome_active = outcome.is_active(),
                        total = futures.len(),
                        "State transition complete"
                    );
                    trace!(
                        target: LOG_CLIENT_REACTOR,
                        ?outcome,
                        operation_id = %state.operation_id(), total = futures.len(),
                        "State transition complete"
                    );
                }
                ExecutorLoopEvent::Disconnected => {
                    break;
                }
            }
        }

        info!(target: LOG_CLIENT_REACTOR, "Terminated.");
        Ok(())
    }

    async fn get_active_states(&self) -> Vec<(DynState, ActiveStateMeta)> {
        self.db
            .begin_transaction()
            .await
            .find_by_prefix(&ActiveStateKeyPrefix)
            .await
            // ignore states from modules that are not initialized yet
            .filter(|(state, _)| {
                future::ready(
                    self.module_contexts
                        .contains_key(&state.state.module_instance_id()),
                )
            })
            .map(|(state, meta)| (state.state, meta))
            .collect::<Vec<_>>()
            .await
    }

    async fn get_active_state(&self, state: &DynState) -> Option<ActiveStateMeta> {
        // ignore states from modules that are not initialized yet
        if !self
            .module_contexts
            .contains_key(&state.module_instance_id())
        {
            return None;
        }
        self.db
            .begin_transaction()
            .await
            .get_value(&ActiveStateKey::from_state(state.clone()))
            .await
    }

    async fn get_inactive_states(&self) -> Vec<(DynState, InactiveStateMeta)> {
        self.db
            .begin_transaction()
            .await
            .find_by_prefix(&InactiveStateKeyPrefix)
            .await
            // ignore states from modules that are not initialized yet
            .filter(|(state, _)| {
                future::ready(
                    self.module_contexts
                        .contains_key(&state.state.module_instance_id()),
                )
            })
            .map(|(state, meta)| (state.state, meta))
            .collect::<Vec<_>>()
            .await
    }
}

impl ExecutorInner {
    /// See [`Executor::stop_executor`].
    fn stop_executor(&self) -> Option<()> {
        let Some(shutdown_sender) = self
            .shutdown_executor
            .try_lock()
            .expect("Only locked during startup, no collisions should be possible")
            .take()
        else {
            debug!("Executor already stopped, ignoring stop request");
            return None;
        };

        if shutdown_sender.send(()).is_err() {
            warn!("Failed to send shutdown signal to executor, already dead?");
        }

        Some(())
    }
}

impl Debug for ExecutorInner {
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
        self.valid_module_ids.insert(context.module_instance_id());

        if self
            .module_contexts
            .insert(context.module_instance_id(), context)
            .is_some()
        {
            panic!("Tried to add two modules with the same instance id!");
        }
    }

    /// Allow executor to build state machines associated with the module id,
    /// for which the module itself might not be available yet (otherwise it
    /// would be registered with `[Self::with_module_dyn]`).
    pub fn with_valid_module_id(&mut self, module_id: ModuleInstanceId) {
        self.valid_module_ids.insert(module_id);
    }

    /// Build [`Executor`] and spawn background task in `tasks` executing active
    /// state machines. The supplied database `db` must support isolation, so
    /// cannot be an isolated DB instance itself.
    pub async fn build(
        self,
        db: Database,
        notifier: Notifier,
        client_task_group: TaskGroup,
    ) -> Executor {
        let (sm_update_tx, sm_update_rx) = tokio::sync::mpsc::unbounded_channel();

        let inner = Arc::new(ExecutorInner {
            db,
            context: Mutex::new(None),
            module_contexts: self.module_contexts,
            valid_module_ids: self.valid_module_ids,
            notifier,
            shutdown_executor: Default::default(),
            sm_update_tx,
            sm_update_rx: Mutex::new(Some(sm_update_rx)),
            client_task_group,
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
pub struct ActiveStateKey {
    // TODO: remove redundant operation id from state trait
    pub operation_id: OperationId,
    // TODO: state being a key... seems ... risky?
    pub state: DynState,
}

impl ActiveStateKey {
    pub fn from_state(state: DynState) -> ActiveStateKey {
        ActiveStateKey {
            operation_id: state.operation_id(),
            state,
        }
    }
}

impl Encodable for ActiveStateKey {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += self.state.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for ActiveStateKey {
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
pub struct ActiveStateKeyBytes {
    pub operation_id: OperationId,
    pub module_instance_id: ModuleInstanceId,
    pub state: Vec<u8>,
}

impl Encodable for ActiveStateKeyBytes {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += writer.write(self.state.as_slice())?;
        Ok(len)
    }
}

impl Decodable for ActiveStateKeyBytes {
    fn consensus_decode<R: std::io::Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let operation_id = OperationId::consensus_decode(reader, modules)?;
        let module_instance_id = ModuleInstanceId::consensus_decode(reader, modules)?;
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(DecodeError::from_err)?;

        let mut instance_bytes = ModuleInstanceId::consensus_encode_to_vec(&module_instance_id);
        instance_bytes.append(&mut bytes);

        Ok(ActiveStateKeyBytes {
            operation_id,
            module_instance_id,
            state: instance_bytes,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ActiveOperationStateKeyPrefix {
    pub operation_id: OperationId,
}

impl Encodable for ActiveOperationStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.operation_id.consensus_encode(writer)
    }
}

impl ::fedimint_core::db::DatabaseLookup for ActiveOperationStateKeyPrefix {
    type Record = ActiveStateKey;
}

#[derive(Debug)]
pub(crate) struct ActiveModuleOperationStateKeyPrefix {
    pub operation_id: OperationId,
    pub module_instance: ModuleInstanceId,
}

impl Encodable for ActiveModuleOperationStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += self.module_instance.consensus_encode(writer)?;
        Ok(len)
    }
}

impl ::fedimint_core::db::DatabaseLookup for ActiveModuleOperationStateKeyPrefix {
    type Record = ActiveStateKey;
}

#[derive(Debug)]
pub struct ActiveStateKeyPrefix;

impl Encodable for ActiveStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, _writer: &mut W) -> Result<usize, Error> {
        Ok(0)
    }
}

#[derive(Debug, Copy, Clone, Encodable, Decodable)]
pub struct ActiveStateMeta {
    pub created_at: SystemTime,
}

impl ::fedimint_core::db::DatabaseRecord for ActiveStateKey {
    const DB_PREFIX: u8 = ExecutorDbPrefixes::ActiveStates as u8;
    const NOTIFY_ON_MODIFY: bool = true;
    type Key = Self;
    type Value = ActiveStateMeta;
}

impl DatabaseKeyWithNotify for ActiveStateKey {}

impl ::fedimint_core::db::DatabaseLookup for ActiveStateKeyPrefix {
    type Record = ActiveStateKey;
}

#[derive(Debug, Encodable, Decodable)]
pub(crate) struct ActiveStateKeyPrefixBytes;

impl ::fedimint_core::db::DatabaseRecord for ActiveStateKeyBytes {
    const DB_PREFIX: u8 = ExecutorDbPrefixes::ActiveStates as u8;
    const NOTIFY_ON_MODIFY: bool = false;
    type Key = Self;
    type Value = ActiveStateMeta;
}

impl ::fedimint_core::db::DatabaseLookup for ActiveStateKeyPrefixBytes {
    type Record = ActiveStateKeyBytes;
}

impl Default for ActiveStateMeta {
    fn default() -> Self {
        Self {
            created_at: fedimint_core::time::now(),
        }
    }
}

impl ActiveStateMeta {
    fn into_inactive(self) -> InactiveStateMeta {
        InactiveStateMeta {
            created_at: self.created_at,
            exited_at: fedimint_core::time::now(),
        }
    }
}

/// A past or final state of a state machine
#[derive(Debug, Clone)]
pub struct InactiveStateKey {
    // TODO: remove redundant operation id from state trait
    pub operation_id: OperationId,
    pub state: DynState,
}

impl InactiveStateKey {
    pub fn from_state(state: DynState) -> InactiveStateKey {
        InactiveStateKey {
            operation_id: state.operation_id(),
            state,
        }
    }
}

impl Encodable for InactiveStateKey {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += self.state.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for InactiveStateKey {
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
pub struct InactiveStateKeyBytes {
    pub operation_id: OperationId,
    pub module_instance_id: ModuleInstanceId,
    pub state: Vec<u8>,
}

impl Encodable for InactiveStateKeyBytes {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += writer.write(self.state.as_slice())?;
        Ok(len)
    }
}

impl Decodable for InactiveStateKeyBytes {
    fn consensus_decode<R: std::io::Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let operation_id = OperationId::consensus_decode(reader, modules)?;
        let module_instance_id = ModuleInstanceId::consensus_decode(reader, modules)?;
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(DecodeError::from_err)?;

        let mut instance_bytes = ModuleInstanceId::consensus_encode_to_vec(&module_instance_id);
        instance_bytes.append(&mut bytes);

        Ok(InactiveStateKeyBytes {
            operation_id,
            module_instance_id,
            state: instance_bytes,
        })
    }
}

#[derive(Debug)]
pub(crate) struct InactiveOperationStateKeyPrefix {
    pub operation_id: OperationId,
}

impl Encodable for InactiveOperationStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.operation_id.consensus_encode(writer)
    }
}

impl ::fedimint_core::db::DatabaseLookup for InactiveOperationStateKeyPrefix {
    type Record = InactiveStateKey;
}

#[derive(Debug)]
pub(crate) struct InactiveModuleOperationStateKeyPrefix {
    pub operation_id: OperationId,
    pub module_instance: ModuleInstanceId,
}

impl Encodable for InactiveModuleOperationStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += self.module_instance.consensus_encode(writer)?;
        Ok(len)
    }
}

impl ::fedimint_core::db::DatabaseLookup for InactiveModuleOperationStateKeyPrefix {
    type Record = InactiveStateKey;
}

#[derive(Debug, Clone)]
pub struct InactiveStateKeyPrefix;

impl Encodable for InactiveStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, _writer: &mut W) -> Result<usize, Error> {
        Ok(0)
    }
}

#[derive(Debug, Encodable, Decodable)]
pub(crate) struct InactiveStateKeyPrefixBytes;

impl ::fedimint_core::db::DatabaseRecord for InactiveStateKeyBytes {
    const DB_PREFIX: u8 = ExecutorDbPrefixes::InactiveStates as u8;
    const NOTIFY_ON_MODIFY: bool = false;
    type Key = Self;
    type Value = InactiveStateMeta;
}

impl ::fedimint_core::db::DatabaseLookup for InactiveStateKeyPrefixBytes {
    type Record = InactiveStateKeyBytes;
}

#[derive(Debug, Copy, Clone, Decodable, Encodable)]
pub struct InactiveStateMeta {
    pub created_at: SystemTime,
    pub exited_at: SystemTime,
}

impl ::fedimint_core::db::DatabaseRecord for InactiveStateKey {
    const DB_PREFIX: u8 = ExecutorDbPrefixes::InactiveStates as u8;
    const NOTIFY_ON_MODIFY: bool = true;
    type Key = Self;
    type Value = InactiveStateMeta;
}

impl DatabaseKeyWithNotify for InactiveStateKey {}

impl ::fedimint_core::db::DatabaseLookup for InactiveStateKeyPrefix {
    type Record = InactiveStateKey;
}

#[derive(Debug)]
enum ActiveOrInactiveState {
    Active {
        dyn_state: DynState,
        #[allow(dead_code)] // currently not printed anywhere, but useful in the db
        meta: ActiveStateMeta,
    },
    Inactive {
        dyn_state: DynState,
    },
}

impl ActiveOrInactiveState {
    fn is_active(&self) -> bool {
        match self {
            ActiveOrInactiveState::Active { .. } => true,
            ActiveOrInactiveState::Inactive { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::sync::Arc;
    use std::time::Duration;

    use fedimint_core::core::{
        Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId,
    };
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::task::{self, TaskGroup};
    use tokio::sync::broadcast::Sender;
    use tracing::{info, trace};

    use crate::sm::state::{Context, DynContext, DynState};
    use crate::sm::{Executor, Notifier, State, StateTransition};
    use crate::DynGlobalClientContext;

    #[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Hash)]
    enum MockStateMachine {
        Start,
        ReceivedNonNull(u64),
        Final,
    }

    impl State for MockStateMachine {
        type ModuleContext = MockContext;

        fn transitions(
            &self,
            context: &Self::ModuleContext,
            _global_context: &DynGlobalClientContext,
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
        type DynType = DynState;

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

    async fn get_executor() -> (Executor, Sender<u64>, Database) {
        let (broadcast, _) = tokio::sync::broadcast::channel(10);

        let mut decoder_builder = Decoder::builder();
        decoder_builder.with_decodable_type::<MockStateMachine>();
        let decoder = decoder_builder.build();

        let decoders =
            ModuleDecoderRegistry::new(vec![(42, ModuleKind::from_static_str("test"), decoder)]);
        let db = Database::new(MemDatabase::new(), decoders);

        let mut executor_builder = Executor::builder();
        executor_builder.with_module(
            42,
            MockContext {
                broadcast: broadcast.clone(),
            },
        );
        let executor = executor_builder
            .build(db.clone(), Notifier::new(db.clone()), TaskGroup::new())
            .await;
        executor
            .start_executor(Arc::new(|_, _| DynGlobalClientContext::new_fake()))
            .await;

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
