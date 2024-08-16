use std::marker::PhantomData;
use std::sync::Arc;

use fedimint_core::core::{ModuleInstanceId, OperationId};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::util::broadcaststream::BroadcastStream;
use fedimint_core::util::BoxStream;
use futures::StreamExt;
use tracing::{debug, error, trace};

use crate::sm::executor::{
    ActiveModuleOperationStateKeyPrefix, ActiveStateKey, InactiveModuleOperationStateKeyPrefix,
    InactiveStateKey,
};
use crate::sm::{ActiveStateMeta, DynState, InactiveStateMeta, State};

/// State transition notifier owned by the modularized client used to inform
/// modules of state transitions.
///
/// To not lose any state transitions that happen before a module subscribes to
/// the operation the notifier loads all belonging past state transitions from
/// the DB. State transitions may be reported multiple times and out of order.
#[derive(Clone)]
pub struct Notifier {
    /// Broadcast channel used to send state transitions to all subscribers
    broadcast: tokio::sync::broadcast::Sender<DynState>,
    /// Database used to load all states that happened before subscribing
    db: Database,
}

impl Notifier {
    pub fn new(db: Database) -> Self {
        let (sender, _receiver) = tokio::sync::broadcast::channel(10_000);
        Self {
            broadcast: sender,
            db,
        }
    }

    /// Notify all subscribers of a state transition
    pub fn notify(&self, state: DynState) {
        let queue_len = self.broadcast.len();
        trace!(?state, %queue_len, "Sending notification about state transition");
        // FIXME: use more robust notification mechanism
        if let Err(e) = self.broadcast.send(state) {
            debug!(
                ?e,
                %queue_len,
                receivers=self.broadcast.receiver_count(),
                "Could not send state transition notification, no active receivers"
            );
        }
    }

    /// Create a new notifier for a specific module instance that can only
    /// subscribe to the instance's state transitions
    pub fn module_notifier<S>(&self, module_instance: ModuleInstanceId) -> ModuleNotifier<S> {
        ModuleNotifier {
            broadcast: self.broadcast.clone(),
            module_instance,
            db: self.db.clone(),
            _pd: PhantomData,
        }
    }

    /// Create a [`NotifierSender`] handle that lets the owner trigger
    /// notifications without having to hold a full `Notifier`.
    pub fn sender(&self) -> NotifierSender {
        NotifierSender {
            sender: self.broadcast.clone(),
        }
    }
}

/// Notifier send handle that can be shared to places where we don't need an
/// entire [`Notifier`] but still need to trigger notifications. The main use
/// case is triggering notifications when a DB transaction was committed
/// successfully.
pub struct NotifierSender {
    sender: tokio::sync::broadcast::Sender<DynState>,
}

impl NotifierSender {
    /// Notify all subscribers of a state transition
    pub fn notify(&self, state: DynState) {
        let _res = self.sender.send(state);
    }
}

/// State transition notifier for a specific module instance that can only
/// subscribe to transitions belonging to that module
#[derive(Debug, Clone)]
pub struct ModuleNotifier<S> {
    broadcast: tokio::sync::broadcast::Sender<DynState>,
    module_instance: ModuleInstanceId,
    /// Database used to load all states that happened before subscribing, see
    /// [`Notifier`]
    db: Database,
    /// `S` limits the type of state that can be subscribed to the one
    /// associated with the module instance
    _pd: PhantomData<S>,
}

impl<S> ModuleNotifier<S>
where
    S: State,
{
    // TODO: remove duplicates and order old transitions
    /// Subscribe to state transitions belonging to an operation and module
    /// (module context contained in struct).
    ///
    /// The returned stream will contain all past state transitions that
    /// happened before the subscription and are read from the database, after
    /// these the stream will contain all future state transitions. The states
    /// loaded from the database are not returned in a specific order. There may
    /// also be duplications.
    pub async fn subscribe(&self, operation_id: OperationId) -> BoxStream<'static, S> {
        let to_typed_state = |state: DynState| {
            state
                .as_any()
                .downcast_ref::<S>()
                .expect("Tried to subscribe to wrong state type")
                .clone()
        };

        // It's important to start the subscription first and then query the database to
        // not lose any transitions in the meantime.
        let new_transitions = self.subscribe_all_operations();

        let db_states = {
            let mut dbtx = self.db.begin_transaction_nc().await;
            let active_states = dbtx
                .find_by_prefix(&ActiveModuleOperationStateKeyPrefix {
                    operation_id,
                    module_instance: self.module_instance,
                })
                .await
                .map(|(key, val): (ActiveStateKey, ActiveStateMeta)| {
                    (to_typed_state(key.state), val.created_at)
                })
                .collect::<Vec<(S, _)>>()
                .await;

            let inactive_states = dbtx
                .find_by_prefix(&InactiveModuleOperationStateKeyPrefix {
                    operation_id,
                    module_instance: self.module_instance,
                })
                .await
                .map(|(key, val): (InactiveStateKey, InactiveStateMeta)| {
                    (to_typed_state(key.state), val.created_at)
                })
                .collect::<Vec<(S, _)>>()
                .await;

            // FIXME: don't rely on SystemTime for ordering and introduce a state transition
            // index instead (dpc was right again xD)
            let mut all_states_timed = active_states
                .into_iter()
                .chain(inactive_states)
                .collect::<Vec<(S, _)>>();
            all_states_timed.sort_by(|(_, t1), (_, t2)| t1.cmp(t2));
            debug!(
                operation_id = %operation_id.fmt_short(),
                num = all_states_timed.len(),
                "Returning state transitions from DB for notifier subscription",
            );
            all_states_timed
                .into_iter()
                .map(|(s, _)| s)
                .collect::<Vec<S>>()
        };

        let new_transitions = new_transitions.filter_map({
            let db_states: Arc<_> = Arc::new(db_states.clone());

            move |state: S| {
                let db_states = db_states.clone();
                async move {
                    if state.operation_id() == operation_id {
                        trace!(operation_id = %operation_id.fmt_short(), ?state, "Received state transition notification");
                        // Deduplicate events that might have both come from the DB and streamed,
                        // due to subscribing to notifier before querying the DB.
                        //
                        // Note: linear search should be good enough in practice for many reasons.
                        // Eg. states tend to have all the states in the DB, or all streamed "live",
                        // so the overlap here should be minimal.
                        // And we'll rewrite the whole thing anyway and use only db as a reference.
                        if db_states.iter().any(|db_s| db_s == &state) {
                            debug!(operation_id = %operation_id.fmt_short(), ?state, "Ignoring duplicated event");
                            return None;
                        }
                        Some(state)
                    } else {
                        None
                    }
                }
            }
        });
        Box::pin(futures::stream::iter(db_states).chain(new_transitions))
    }

    /// Subscribe to all state transitions belonging to the module instance.
    pub fn subscribe_all_operations(&self) -> BoxStream<'static, S> {
        let module_instance_id = self.module_instance;
        Box::pin(
            BroadcastStream::new(self.broadcast.subscribe())
                .take_while(|res| {
                    let cont = if let Err(err) = res {
                        error!(?err, "ModuleNotifier stream stopped on error");
                        false
                    } else {
                        true
                    };
                    std::future::ready(cont)
                })
                .filter_map(move |res| async move {
                    let s = res.expect("We filtered out errors above");
                    if s.module_instance_id() == module_instance_id {
                        Some(
                            s.as_any()
                                .downcast_ref::<S>()
                                .expect("Tried to subscribe to wrong state type")
                                .clone(),
                        )
                    } else {
                        None
                    }
                }),
        )
    }
}
