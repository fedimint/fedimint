use std::marker::PhantomData;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::Database;
use fedimint_core::util::broadcaststream::BroadcastStream;
use fedimint_core::util::BoxStream;
use futures::StreamExt;
use tracing::error;

use crate::sm::executor::{
    ActiveModuleOperationStateKeyPrefix, ActiveStateKey, InactiveModuleOperationStateKeyPrefix,
    InactiveStateKey,
};
use crate::sm::{ActiveState, DynState, GlobalContext, InactiveState, OperationId, State};

/// State transition notifier owned by the modularized client used to inform
/// modules of state transitions.
///
/// To not lose any state transitions that happen before a module subscribes to
/// the operation the notifier loads all belonging past state transitions from
/// the DB. State transitions may be reported multiple times and out of order.
#[derive(Clone)]
pub struct Notifier<GC> {
    /// Broadcast channel used to send state transitions to all subscribers
    broadcast: tokio::sync::broadcast::Sender<DynState<GC>>,
    /// Database used to load all states that happened before subscribing
    db: Database,
}

impl<GC> Notifier<GC> {
    pub fn new(db: Database) -> Self {
        let (sender, _receiver) = tokio::sync::broadcast::channel(100);
        Self {
            broadcast: sender,
            db,
        }
    }

    /// Notify all subscribers of a state transition
    pub fn notify(&self, state: DynState<GC>) {
        let _res = self.broadcast.send(state);
    }

    /// Create a new notifier for a specific module instance that can only
    /// subscribe to the instance's state transitions
    pub fn module_notifier<S>(&self, module_instance: ModuleInstanceId) -> ModuleNotifier<GC, S> {
        ModuleNotifier {
            broadcast: self.broadcast.clone(),
            module_instance,
            db: self.db.clone(),
            _pd: Default::default(),
        }
    }
}

/// State transition notifier for a specific module instance that can only
/// subscribe to transitions belonging to that module
#[derive(Debug, Clone)]
pub struct ModuleNotifier<GC, S> {
    broadcast: tokio::sync::broadcast::Sender<DynState<GC>>,
    module_instance: ModuleInstanceId,
    /// Database used to load all states that happened before subscribing, see
    /// [`Notifier`]
    db: Database,
    /// `S` limits the type of state that can be subscribed to to the one
    /// associated with the module instance
    _pd: PhantomData<S>,
}

impl<GC, S> ModuleNotifier<GC, S>
where
    GC: GlobalContext,
    S: State<GlobalContext = GC>,
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
        let to_typed_state = |state: DynState<GC>| {
            state
                .as_any()
                .downcast_ref::<S>()
                .expect("Tried to subscribe to wrong state type")
                .clone()
        };

        // It's important to start the subscription first and then query the database to
        // not lose any transitions in the meantime.
        let new_transitions =
            self.subscribe_all_operations()
                .await
                .filter_map(move |state: S| async move {
                    if state.operation_id() == operation_id {
                        Some(state)
                    } else {
                        None
                    }
                });

        let db_states = {
            let mut dbtx = self.db.begin_transaction().await;
            let active_states = dbtx
                .find_by_prefix(&ActiveModuleOperationStateKeyPrefix {
                    operation_id,
                    module_instance: self.module_instance,
                    _pd: Default::default(),
                })
                .await
                .map(|(key, val): (ActiveStateKey<GC>, ActiveState)| {
                    (to_typed_state(key.state), val.created_at)
                })
                .collect::<Vec<(S, _)>>()
                .await;

            let inactive_states = dbtx
                .find_by_prefix(&InactiveModuleOperationStateKeyPrefix {
                    operation_id,
                    module_instance: self.module_instance,
                    _pd: Default::default(),
                })
                .await
                .map(|(key, val): (InactiveStateKey<GC>, InactiveState)| {
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
            all_states_timed
                .into_iter()
                .map(|(s, _)| s)
                .collect::<Vec<S>>()
        };

        Box::pin(futures::stream::iter(db_states).chain(new_transitions))
    }

    /// Subscribe to all state transitions belonging to the module instance.
    pub async fn subscribe_all_operations(&self) -> BoxStream<'static, S> {
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
