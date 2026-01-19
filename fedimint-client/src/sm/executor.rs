use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::{Debug, Formatter};
use std::io::{Error, Write};
use std::mem;
use std::sync::Arc;

use anyhow::anyhow;
use fedimint_client_module::sm::executor::{
    ActiveStateKey, ContextGen, IExecutor, InactiveStateKey,
};
use fedimint_client_module::sm::{
    ActiveStateMeta, ClientSMDatabaseTransaction, DynContext, DynState, InactiveStateMeta, State,
    StateTransition, StateTransitionFunction,
};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::{
    Database, DatabaseKeyWithNotify, IReadDatabaseTransactionOpsTyped,
    IWriteDatabaseTransactionOpsTyped, WriteDatabaseTransaction,
};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::fmt_utils::AbbreviateJson;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::{BoxFuture, FmtCompactAnyhow as _};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_eventlog::{DBTransactionEventLogExt as _, Event, EventKind, EventPersistence};
use fedimint_logging::LOG_CLIENT_REACTOR;
use futures::future::{self, select_all};
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::select;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{Instrument, debug, error, info, trace, warn};

use crate::sm::notifier::Notifier;
use crate::{AddStateMachinesError, AddStateMachinesResult, DynGlobalClientContext};

/// Prefixes for executor DB entries
pub(crate) enum ExecutorDbPrefixes {
    /// See [`ActiveStateKey`]
    ActiveStates = 0xa1,
    /// See [`InactiveStateKey`]
    InactiveStates = 0xa2,
}

#[derive(Serialize, Deserialize)]
pub struct StateMachineUpdated {
    operation_id: OperationId,
    started: bool,
    terminal: bool,
    module_id: ModuleInstanceId,
}

impl Event for StateMachineUpdated {
    const MODULE: Option<fedimint_core::core::ModuleKind> = None;
    const KIND: EventKind = EventKind::from_static("sm-updated");
    const PERSISTENCE: EventPersistence = EventPersistence::Trimable;
}

/// Executor that drives forward state machines under its management.
///
/// Each state transition is atomic and supposed to be idempotent such that a
/// stop/crash of the executor at any point can be recovered from on restart.
/// The executor is aware of the concept of Fedimint modules and can give state
/// machines a different [execution context](crate::module::sm::Context)
/// depending on the owning module, making it very flexible.
#[derive(Clone, Debug)]
pub struct Executor {
    inner: Arc<ExecutorInner>,
}

struct ExecutorInner {
    db: Database,
    state: std::sync::RwLock<ExecutorState>,
    module_contexts: BTreeMap<ModuleInstanceId, DynContext>,
    valid_module_ids: BTreeSet<ModuleInstanceId>,
    notifier: Notifier,
    /// Any time executor should notice state machine update (e.g. because it
    /// was created), it's must be sent through this channel for it to notice.
    sm_update_tx: mpsc::UnboundedSender<DynState>,
    client_task_group: TaskGroup,
    log_ordering_wakeup_tx: watch::Sender<()>,
}

enum ExecutorState {
    Unstarted {
        sm_update_rx: mpsc::UnboundedReceiver<DynState>,
    },
    Running {
        context_gen: ContextGen,
        shutdown_sender: oneshot::Sender<()>,
    },
    Stopped,
}

impl ExecutorState {
    /// Starts the executor, returning a receiver that will be signalled when
    /// the executor is stopped and a receiver for state machine updates.
    /// Returns `None` if the executor has already been started and/or stopped.
    fn start(
        &mut self,
        context: ContextGen,
    ) -> Option<(oneshot::Receiver<()>, mpsc::UnboundedReceiver<DynState>)> {
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();

        let previous_state = mem::replace(
            self,
            ExecutorState::Running {
                context_gen: context,
                shutdown_sender,
            },
        );

        match previous_state {
            ExecutorState::Unstarted { sm_update_rx } => Some((shutdown_receiver, sm_update_rx)),
            _ => {
                // Replace the previous state, undoing the `mem::replace` above.
                *self = previous_state;

                debug!(target: LOG_CLIENT_REACTOR, "Executor already started, ignoring start request");
                None
            }
        }
    }

    /// Stops the executor, returning `Some(())` if the executor was running and
    /// `None` if it was in any other state.
    fn stop(&mut self) -> Option<()> {
        let previous_state = mem::replace(self, ExecutorState::Stopped);

        match previous_state {
            ExecutorState::Running {
                shutdown_sender, ..
            } => {
                if shutdown_sender.send(()).is_err() {
                    warn!(target: LOG_CLIENT_REACTOR, "Failed to send shutdown signal to executor, already dead?");
                }
                Some(())
            }
            _ => {
                // Replace the previous state, undoing the `mem::replace` above.
                *self = previous_state;

                debug!(target: LOG_CLIENT_REACTOR, "Executor not running, ignoring stop request");
                None
            }
        }
    }

    fn gen_context(&self, state: &DynState) -> Option<DynGlobalClientContext> {
        let ExecutorState::Running { context_gen, .. } = self else {
            return None;
        };
        Some(context_gen(
            state.module_instance_id(),
            state.operation_id(),
        ))
    }
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
        let mut dbtx = self.inner.db.begin_write_transaction().await;

        self.add_state_machines_dbtx(&mut dbtx.to_ref_nc(), states)
            .await?;

        dbtx.commit_tx().await;

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
        dbtx: &mut WriteDatabaseTransaction<'_>,
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
                .get_value(&ActiveStateKeyDb(ActiveStateKey::from_state(state.clone())))
                .await
                .is_some();
            let is_inactive_state = dbtx
                .get_value(&InactiveStateKeyDb(InactiveStateKey::from_state(
                    state.clone(),
                )))
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
                match self
                    .inner
                    .state
                    .read()
                    .expect("locking failed")
                    .gen_context(&state)
                {
                    Some(context) => {
                        if state.is_terminal(module_context, &context) {
                            return Err(AddStateMachinesError::Other(anyhow!(
                                "State is already terminal, adding it to the executor doesn't make sense."
                            )));
                        }
                    }
                    _ => {
                        warn!(target: LOG_CLIENT_REACTOR, "Executor should be running at this point");
                    }
                }
            }

            dbtx.insert_new_entry(
                &ActiveStateKeyDb(ActiveStateKey::from_state(state.clone())),
                &ActiveStateMeta::default(),
            )
            .await;

            let operation_id = state.operation_id();
            self.inner
                .log_event_dbtx(
                    dbtx,
                    StateMachineUpdated {
                        operation_id,
                        started: true,
                        terminal: false,
                        module_id: state.module_instance_id(),
                    },
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
            .wait_key_exists(&InactiveStateKeyDb(InactiveStateKey::from_state(state)))
            .await
    }

    pub async fn await_active_state(&self, state: DynState) -> ActiveStateMeta {
        self.inner
            .db
            .wait_key_exists(&ActiveStateKeyDb(ActiveStateKey::from_state(state)))
            .await
    }

    /// Only meant for debug tooling
    pub async fn get_operation_states(
        &self,
        operation_id: OperationId,
    ) -> (
        Vec<(DynState, ActiveStateMeta)>,
        Vec<(DynState, InactiveStateMeta)>,
    ) {
        let mut dbtx = self.inner.db.begin_read_transaction().await;
        let active_states: Vec<_> = dbtx
            .find_by_prefix(&ActiveOperationStateKeyPrefix { operation_id })
            .await
            .map(|(active_key, active_meta)| (active_key.0.state, active_meta))
            .collect()
            .await;
        let inactive_states: Vec<_> = dbtx
            .find_by_prefix(&InactiveOperationStateKeyPrefix { operation_id })
            .await
            .map(|(active_key, inactive_meta)| (active_key.0.state, inactive_meta))
            .collect()
            .await;

        (active_states, inactive_states)
    }

    /// Starts the background thread that runs the state machines. This cannot
    /// be done when building the executor since some global contexts in turn
    /// may depend on the executor, forming a cyclic dependency.
    ///
    /// ## Panics
    /// If called more than once.
    pub fn start_executor(&self, context_gen: ContextGen) {
        let Some((shutdown_receiver, sm_update_rx)) = self
            .inner
            .state
            .write()
            .expect("locking can't fail")
            .start(context_gen.clone())
        else {
            panic!("start_executor was called previously");
        };

        let task_runner_inner = self.inner.clone();
        let _handle = self.inner.client_task_group.spawn("sm-executor", |task_handle| async move {
            let executor_runner = task_runner_inner.run(context_gen, sm_update_rx);
            let task_group_shutdown_rx = task_handle.make_shutdown_rx();
            select! {
                () = task_group_shutdown_rx => {
                    debug!(
                        target: LOG_CLIENT_REACTOR,
                        "Shutting down state machine executor runner due to task group shutdown signal"
                    );
                },
                shutdown_happened_sender = shutdown_receiver => {
                    match shutdown_happened_sender {
                        Ok(()) => {
                            debug!(
                                target: LOG_CLIENT_REACTOR,
                                "Shutting down state machine executor runner due to explicit shutdown signal"
                            );
                        },
                        Err(_) => {
                            warn!(
                                target: LOG_CLIENT_REACTOR,
                                "Shutting down state machine executor runner because the shutdown signal channel was closed (the executor object was dropped)"
                            );
                        }
                    }
                },
                () = executor_runner => {
                    error!(target: LOG_CLIENT_REACTOR, "State machine executor runner exited unexpectedly!");
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
        debug!(target: LOG_CLIENT_REACTOR, "Starting state machine executor task");
        if let Err(err) = self
            .run_state_machines_executor_inner(global_context_gen, sm_update_rx)
            .await
        {
            warn!(
                target: LOG_CLIENT_REACTOR,
                err = %err.fmt_compact_anyhow(),
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
            warn!(
                target: LOG_CLIENT_REACTOR,
                module_id = module_instance, "A terminal state where only active states are expected. Please report this bug upstream."
            );
            let mut dbtx = self.db.begin_write_transaction().await;
            let k = InactiveStateKey::from_state(state.clone());
            let v = ActiveStateMeta::default().into_inactive();
            dbtx.remove_entry(&ActiveStateKeyDb(ActiveStateKey::from_state(state.clone())))
                .await;
            dbtx.insert_entry(&InactiveStateKeyDb(k), &v).await;
            dbtx.commit_tx().await;
        }

        transitions
    }

    async fn run_state_machines_executor_inner(
        &self,
        global_context_gen: ContextGen,
        mut sm_update_rx: tokio::sync::mpsc::UnboundedReceiver<DynState>,
    ) -> anyhow::Result<()> {
        /// All futures in the executor resolve to this type, so the handling
        /// code can tell them apart.
        enum ExecutorLoopEvent {
            /// Notification about `DynState` arrived and should be handled,
            /// usually added to the list of pending futures.
            New { state: DynState },
            /// One of trigger futures of a state machine finished and
            /// returned transition function to run
            Triggered(TransitionForActiveState),
            /// The state machine did not need to run, so it was canceled
            Invalid { state: DynState },
            /// Transition function and all the accounting around it are done
            Completed {
                state: DynState,
                outcome: ActiveOrInactiveState,
            },
            /// New job receiver disconnected, that can only mean termination
            Disconnected,
        }

        let active_states = self.get_active_states().await;
        trace!(target: LOG_CLIENT_REACTOR, "Starting active states: {:?}", active_states);
        for (state, _meta) in active_states {
            self.sm_update_tx
                .send(state)
                .expect("Must be able to send state machine to own opened channel");
        }

        // Keeps track of things already running, so we can deduplicate, just
        // in case.
        let mut currently_running_sms = HashSet::<DynState>::new();
        // All things happening in parallel go into here
        // NOTE: `FuturesUnordered` is a footgun: when it's not being polled
        // (e.g. we picked an event and are awaiting on something to process it),
        // nothing inside `futures` will be making progress, which in extreme cases
        // could lead to hangs. For this reason we try really hard in the code here,
        // to pick an event from `futures` and spawn a new task, avoiding any `await`,
        // just so we can get back to `futures.next()` ASAP.
        let mut futures: FuturesUnordered<BoxFuture<'_, ExecutorLoopEvent>> =
            FuturesUnordered::new();

        loop {
            let event = tokio::select! {
                new = sm_update_rx.recv() => {
                    match new { Some(new) => {
                        ExecutorLoopEvent::New {
                            state: new,
                        }
                    } _ => {
                        ExecutorLoopEvent::Disconnected
                    }}
                },

                event = futures.next(), if !futures.is_empty() => event.expect("we only .next() if there are pending futures"),
            };

            // main reactor loop: wait for next thing that completed, react (possibly adding
            // more things to `futures`)
            match event {
                ExecutorLoopEvent::New { state } => {
                    if currently_running_sms.contains(&state) {
                        warn!(target: LOG_CLIENT_REACTOR, operation_id = %state.operation_id().fmt_short(), "Received a state machine that is already running. Ignoring");
                        continue;
                    }
                    currently_running_sms.insert(state.clone());
                    let futures_len = futures.len();
                    let global_context_gen = &global_context_gen;
                    trace!(target: LOG_CLIENT_REACTOR, state = ?state, "Started new active state machine, details.");
                    futures.push(Box::pin(async move {
                        let Some(meta) = self.get_active_state(&state).await else {
                            warn!(target: LOG_CLIENT_REACTOR, operation_id = %state.operation_id().fmt_short(), "Couldn't look up received state machine. Ignoring.");
                            return ExecutorLoopEvent::Invalid { state: state.clone() };
                        };

                        let transitions = self
                            .get_transition_for(&state, meta, global_context_gen)
                            .await;
                        if transitions.is_empty() {
                            warn!(target: LOG_CLIENT_REACTOR, operation_id = %state.operation_id().fmt_short(), "Received an active state that doesn't produce any transitions. Ignoring.");
                            return ExecutorLoopEvent::Invalid { state: state.clone() };
                        }
                        let transitions_num = transitions.len();

                        debug!(target: LOG_CLIENT_REACTOR, operation_id = %state.operation_id().fmt_short(), total = futures_len + 1, transitions_num, "New active state machine.");

                        let (first_completed_result, _index, _unused_transitions) =
                            select_all(transitions).await;
                        ExecutorLoopEvent::Triggered(first_completed_result)
                    }));
                }
                ExecutorLoopEvent::Triggered(TransitionForActiveState {
                    outcome,
                    state,
                    meta,
                    transition_fn,
                }) => {
                    debug!(
                        target: LOG_CLIENT_REACTOR,
                        operation_id = %state.operation_id().fmt_short(),
                        "Triggered state transition",
                    );
                    let span = tracing::debug_span!(
                        target: LOG_CLIENT_REACTOR,
                        "sm_transition",
                        operation_id = %state.operation_id().fmt_short()
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
                                debug!(
                                    target: LOG_CLIENT_REACTOR,
                                    "Executing state transition",
                                );
                                trace!(
                                    target: LOG_CLIENT_REACTOR,
                                    ?state,
                                    outcome = ?AbbreviateJson(&outcome),
                                    "Executing state transition (details)",
                                );

                                let module_contexts = &module_contexts;
                                let global_context_gen = &global_context_gen;

                                let outcome = {
                                    let state_module_instance_id = state.module_instance_id();
                                    let mut dbtx = db.begin_write_transaction().await;

                                    let new_state = transition_fn(
                                        &mut ClientSMDatabaseTransaction::new(
                                            &mut dbtx.to_ref_nc(),
                                            state.module_instance_id(),
                                        ),
                                        outcome.clone(),
                                        state.clone(),
                                    )
                                    .await;
                                    dbtx.remove_entry(&ActiveStateKeyDb(
                                        ActiveStateKey::from_state(state.clone()),
                                    ))
                                    .await;
                                    dbtx.insert_entry(
                                        &InactiveStateKeyDb(InactiveStateKey::from_state(
                                            state.clone(),
                                        )),
                                        &meta.into_inactive(),
                                    )
                                    .await;

                                    let context = &module_contexts
                                        .get(&state.module_instance_id())
                                        .expect("Unknown module");

                                    let operation_id = state.operation_id();
                                    let global_context = global_context_gen(
                                        state.module_instance_id(),
                                        operation_id,
                                    );

                                    let is_terminal =
                                        new_state.is_terminal(context, &global_context);

                                    self.log_event_dbtx(
                                        &mut dbtx.to_ref_nc(),
                                        StateMachineUpdated {
                                            started: false,
                                            operation_id,
                                            module_id: state_module_instance_id,
                                            terminal: is_terminal,
                                        },
                                    )
                                    .await;

                                    let result = if is_terminal {
                                        let k = InactiveStateKey::from_state(new_state.clone());
                                        let v = ActiveStateMeta::default().into_inactive();
                                        dbtx.insert_entry(&InactiveStateKeyDb(k), &v).await;
                                        ActiveOrInactiveState::Inactive {
                                            dyn_state: new_state,
                                        }
                                    } else {
                                        let k = ActiveStateKey::from_state(new_state.clone());
                                        let v = ActiveStateMeta::default();
                                        dbtx.insert_entry(&ActiveStateKeyDb(k), &v).await;
                                        ActiveOrInactiveState::Active {
                                            dyn_state: new_state,
                                            meta: v,
                                        }
                                    };

                                    dbtx.commit_tx().await;

                                    result
                                };

                                debug!(
                                    target: LOG_CLIENT_REACTOR,
                                    terminal = !outcome.is_active(),
                                    ?outcome,
                                    "State transition complete",
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
                ExecutorLoopEvent::Invalid { state } => {
                    trace!(
                        target: LOG_CLIENT_REACTOR,
                        operation_id = %state.operation_id().fmt_short(), total = futures.len(),
                        "State invalid"
                    );
                    assert!(
                        currently_running_sms.remove(&state),
                        "State must have been recorded"
                    );
                }

                ExecutorLoopEvent::Completed { state, outcome } => {
                    assert!(
                        currently_running_sms.remove(&state),
                        "State must have been recorded"
                    );
                    debug!(
                        target: LOG_CLIENT_REACTOR,
                        operation_id = %state.operation_id().fmt_short(),
                        outcome_active = outcome.is_active(),
                        total = futures.len(),
                        "State transition complete"
                    );
                    trace!(
                        target: LOG_CLIENT_REACTOR,
                        ?outcome,
                        operation_id = %state.operation_id().fmt_short(), total = futures.len(),
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
            .begin_read_transaction()
            .await
            .find_by_prefix(&ActiveStateKeyPrefix)
            .await
            // ignore states from modules that are not initialized yet
            .filter(|(state, _)| {
                future::ready(
                    self.module_contexts
                        .contains_key(&state.0.state.module_instance_id()),
                )
            })
            .map(|(state, meta)| (state.0.state, meta))
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
            .begin_read_transaction()
            .await
            .get_value(&ActiveStateKeyDb(ActiveStateKey::from_state(state.clone())))
            .await
    }

    async fn get_inactive_states(&self) -> Vec<(DynState, InactiveStateMeta)> {
        self.db
            .begin_read_transaction()
            .await
            .find_by_prefix(&InactiveStateKeyPrefix)
            .await
            // ignore states from modules that are not initialized yet
            .filter(|(state, _)| {
                future::ready(
                    self.module_contexts
                        .contains_key(&state.0.state.module_instance_id()),
                )
            })
            .map(|(state, meta)| (state.0.state, meta))
            .collect::<Vec<_>>()
            .await
    }

    pub async fn log_event_dbtx<E>(&self, dbtx: &mut WriteDatabaseTransaction<'_>, event: E)
    where
        E: Event + Send,
    {
        dbtx.log_event(self.log_ordering_wakeup_tx.clone(), None, event)
            .await;
    }
}

impl ExecutorInner {
    /// See [`Executor::stop_executor`].
    fn stop_executor(&self) -> Option<()> {
        let mut state = self.state.write().expect("Locking can't fail");

        state.stop()
    }
}

impl Debug for ExecutorInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ExecutorInner {{}}")
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
    pub fn build(
        self,
        db: Database,
        notifier: Notifier,
        client_task_group: TaskGroup,
        log_ordering_wakeup_tx: watch::Sender<()>,
    ) -> Executor {
        let (sm_update_tx, sm_update_rx) = tokio::sync::mpsc::unbounded_channel();

        let inner = Arc::new(ExecutorInner {
            db,
            log_ordering_wakeup_tx,
            state: std::sync::RwLock::new(ExecutorState::Unstarted { sm_update_rx }),
            module_contexts: self.module_contexts,
            valid_module_ids: self.valid_module_ids,
            notifier,
            sm_update_tx,
            client_task_group,
        });

        debug!(
            target: LOG_CLIENT_REACTOR,
            instances = ?inner.module_contexts.keys().copied().collect::<Vec<_>>(),
            "Initialized state machine executor with module instances"
        );
        Executor { inner }
    }
}
#[derive(Debug)]
pub struct ActiveOperationStateKeyPrefix {
    pub operation_id: OperationId,
}

impl Encodable for ActiveOperationStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.operation_id.consensus_encode(writer)
    }
}

impl ::fedimint_core::db::DatabaseLookup for ActiveOperationStateKeyPrefix {
    type Record = ActiveStateKeyDb;
}

#[derive(Debug)]
pub(crate) struct ActiveModuleOperationStateKeyPrefix {
    pub operation_id: OperationId,
    pub module_instance: ModuleInstanceId,
}

impl Encodable for ActiveModuleOperationStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.operation_id.consensus_encode(writer)?;
        self.module_instance.consensus_encode(writer)?;
        Ok(())
    }
}

impl ::fedimint_core::db::DatabaseLookup for ActiveModuleOperationStateKeyPrefix {
    type Record = ActiveStateKeyDb;
}

#[derive(Debug)]
pub struct ActiveStateKeyPrefix;

impl Encodable for ActiveStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, _writer: &mut W) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Encodable, Decodable, Debug)]
pub struct ActiveStateKeyDb(pub fedimint_client_module::sm::executor::ActiveStateKey);

impl ::fedimint_core::db::DatabaseRecord for ActiveStateKeyDb {
    const DB_PREFIX: u8 = ExecutorDbPrefixes::ActiveStates as u8;
    const NOTIFY_ON_MODIFY: bool = true;
    type Key = Self;
    type Value = ActiveStateMeta;
}

impl DatabaseKeyWithNotify for ActiveStateKeyDb {}

impl ::fedimint_core::db::DatabaseLookup for ActiveStateKeyPrefix {
    type Record = ActiveStateKeyDb;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ActiveStateKeyPrefixBytes;

impl ::fedimint_core::db::DatabaseRecord for ActiveStateKeyBytes {
    const DB_PREFIX: u8 = ExecutorDbPrefixes::ActiveStates as u8;
    const NOTIFY_ON_MODIFY: bool = false;
    type Key = Self;
    type Value = ActiveStateMeta;
}

impl ::fedimint_core::db::DatabaseLookup for ActiveStateKeyPrefixBytes {
    type Record = ActiveStateKeyBytes;
}

#[derive(Encodable, Decodable, Debug)]
pub struct InactiveStateKeyDb(pub fedimint_client_module::sm::executor::InactiveStateKey);

#[derive(Debug)]
pub struct InactiveStateKeyBytes {
    pub operation_id: OperationId,
    pub module_instance_id: ModuleInstanceId,
    pub state: Vec<u8>,
}

impl Encodable for InactiveStateKeyBytes {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.operation_id.consensus_encode(writer)?;
        writer.write_all(self.state.as_slice())?;
        Ok(())
    }
}

impl Decodable for InactiveStateKeyBytes {
    fn consensus_decode_partial<R: std::io::Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let operation_id = OperationId::consensus_decode_partial(reader, modules)?;
        let module_instance_id = ModuleInstanceId::consensus_decode_partial(reader, modules)?;
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
pub struct InactiveOperationStateKeyPrefix {
    pub operation_id: OperationId,
}

impl Encodable for InactiveOperationStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.operation_id.consensus_encode(writer)
    }
}

impl ::fedimint_core::db::DatabaseLookup for InactiveOperationStateKeyPrefix {
    type Record = InactiveStateKeyDb;
}

#[derive(Debug)]
pub(crate) struct InactiveModuleOperationStateKeyPrefix {
    pub operation_id: OperationId,
    pub module_instance: ModuleInstanceId,
}

impl Encodable for InactiveModuleOperationStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.operation_id.consensus_encode(writer)?;
        self.module_instance.consensus_encode(writer)?;
        Ok(())
    }
}

impl ::fedimint_core::db::DatabaseLookup for InactiveModuleOperationStateKeyPrefix {
    type Record = InactiveStateKeyDb;
}

#[derive(Debug, Clone)]
pub struct InactiveStateKeyPrefix;

impl Encodable for InactiveStateKeyPrefix {
    fn consensus_encode<W: Write>(&self, _writer: &mut W) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug, Encodable, Decodable)]
pub struct InactiveStateKeyPrefixBytes;

impl ::fedimint_core::db::DatabaseRecord for InactiveStateKeyBytes {
    const DB_PREFIX: u8 = ExecutorDbPrefixes::InactiveStates as u8;
    const NOTIFY_ON_MODIFY: bool = false;
    type Key = Self;
    type Value = InactiveStateMeta;
}

impl ::fedimint_core::db::DatabaseLookup for InactiveStateKeyPrefixBytes {
    type Record = InactiveStateKeyBytes;
}

#[derive(Debug)]
pub struct ActiveStateKeyBytes {
    pub operation_id: OperationId,
    pub module_instance_id: ModuleInstanceId,
    pub state: Vec<u8>,
}

impl Encodable for ActiveStateKeyBytes {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.operation_id.consensus_encode(writer)?;
        writer.write_all(self.state.as_slice())?;
        Ok(())
    }
}

impl Decodable for ActiveStateKeyBytes {
    fn consensus_decode_partial<R: std::io::Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let operation_id = OperationId::consensus_decode_partial(reader, modules)?;
        let module_instance_id = ModuleInstanceId::consensus_decode_partial(reader, modules)?;
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
impl ::fedimint_core::db::DatabaseRecord for InactiveStateKeyDb {
    const DB_PREFIX: u8 = ExecutorDbPrefixes::InactiveStates as u8;
    const NOTIFY_ON_MODIFY: bool = true;
    type Key = Self;
    type Value = InactiveStateMeta;
}

impl DatabaseKeyWithNotify for InactiveStateKeyDb {}

impl ::fedimint_core::db::DatabaseLookup for InactiveStateKeyPrefix {
    type Record = InactiveStateKeyDb;
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

#[apply(async_trait_maybe_send!)]
impl IExecutor for Executor {
    async fn get_active_states(&self) -> Vec<(DynState, ActiveStateMeta)> {
        Self::get_active_states(self).await
    }

    async fn add_state_machines_dbtx(
        &self,
        dbtx: &mut WriteDatabaseTransaction<'_>,
        states: Vec<DynState>,
    ) -> AddStateMachinesResult {
        Self::add_state_machines_dbtx(self, dbtx, states).await
    }
}

#[cfg(test)]
mod tests;
