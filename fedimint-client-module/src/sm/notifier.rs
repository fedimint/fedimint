use std::marker::PhantomData;

use fedimint_core::core::{ModuleInstanceId, OperationId};
use fedimint_core::util::broadcaststream::BroadcastStream;
use fedimint_core::util::BoxStream;
use fedimint_logging::LOG_CLIENT;
use futures::StreamExt as _;
use tokio::sync::mpsc;
use tracing::{debug, error, trace};

use super::{DynState, State};
use crate::module::FinalClientIface;
use crate::sm::executor::{ActiveStateKey, InactiveStateKey};
use crate::sm::{ActiveStateMeta, InactiveStateMeta};

/// State transition notifier for a specific module instance that can only
/// subscribe to transitions belonging to that module
#[derive(Debug, Clone)]
pub struct ModuleNotifier<S> {
    broadcast: tokio::sync::broadcast::Sender<DynState>,
    module_instance: ModuleInstanceId,
    client: FinalClientIface,
    /// `S` limits the type of state that can be subscribed to the one
    /// associated with the module instance
    _pd: PhantomData<S>,
}

impl<S> ModuleNotifier<S>
where
    S: State,
{
    pub fn new(
        broadcast: tokio::sync::broadcast::Sender<DynState>,
        module_instance: ModuleInstanceId,
        client: FinalClientIface,
    ) -> Self {
        Self {
            broadcast,
            module_instance,
            client,
            _pd: PhantomData,
        }
    }

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
        let (tx, rx) = mpsc::unbounded_channel();
        let this = self.clone();

        tokio::spawn(async move {
            loop {
                // Subscribe first, then query DB to not miss any transitions that
                // happen between the two operations.
                let new_transitions = this.subscribe_all_operations();

                let client_strong = this.client.get();
                let db_states: Vec<S> = {
                    let to_typed_state = |state: DynState| {
                        state
                            .as_any()
                            .downcast_ref::<S>()
                            .expect("Tried to subscribe to wrong state type")
                            .clone()
                    };

                    let mut dbtx = client_strong.db().begin_transaction_nc().await;
                    let active_states = client_strong
                        .read_operation_active_states(
                            operation_id,
                            this.module_instance,
                            &mut dbtx,
                        )
                        .await
                        .map(|(key, val): (ActiveStateKey, ActiveStateMeta)| {
                            (to_typed_state(key.state), val.created_at)
                        })
                        .collect::<Vec<(S, _)>>()
                        .await;

                    let inactive_states = this
                        .client
                        .get()
                        .read_operation_inactive_states(
                            operation_id,
                            this.module_instance,
                            &mut dbtx,
                        )
                        .await
                        .map(|(key, val): (InactiveStateKey, InactiveStateMeta)| {
                            (to_typed_state(key.state), val.created_at)
                        })
                        .collect::<Vec<(S, _)>>()
                        .await;

                    // FIXME: don't rely on SystemTime for ordering and introduce a state
                    // transition index instead (dpc was right again xD)
                    let num_active = active_states.len();
                    let num_inactive = inactive_states.len();
                    let mut all_states_timed = active_states
                        .into_iter()
                        .chain(inactive_states)
                        .collect::<Vec<(S, _)>>();
                    all_states_timed.sort_by_key(|(_, t1)| *t1);
                    debug!(
                        operation_id = %operation_id.fmt_short(),
                        module_instance = %this.module_instance,
                        active = num_active,
                        inactive = num_inactive,
                        "Returning state transitions from DB for notifier subscription",
                    );
                    all_states_timed
                        .into_iter()
                        .map(|(s, _)| s)
                        .collect::<Vec<S>>()
                };

                let mut stream =
                    futures::stream::iter(db_states.clone()).chain(new_transitions);

                while let Some(state) = stream.next().await {
                    if state.operation_id() == operation_id {
                        // Deduplicate events that might have both come from the DB and
                        // streamed, due to subscribing before querying the DB.
                        if db_states.iter().any(|db_s| db_s == &state) {
                            debug!(
                                operation_id = %operation_id.fmt_short(),
                                ?state,
                                "Ignoring duplicated event"
                            );
                            continue;
                        }
                        if tx.send(state).is_err() {
                            return;
                        }
                    }
                }

                // Live stream ended (e.g. Lagged or Closed). If the broadcast
                // sender has been dropped the client is shutting down, so we stop.
                if this.broadcast.is_closed() {
                    return;
                }
                debug!(
                    operation_id = %operation_id.fmt_short(),
                    "Notifier stream ended, re-syncing from database"
                );
            }
        });

        Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(rx))
    }

    /// Subscribe to all state transitions belonging to the module instance.
    pub fn subscribe_all_operations(&self) -> BoxStream<'static, S> {
        let module_instance_id = self.module_instance;
        Box::pin(
            BroadcastStream::new(self.broadcast.subscribe())
                .take_while(|res| {
                    let cont = if let Err(err) = res {
                        error!(target: LOG_CLIENT, ?err, "ModuleNotifier stream stopped on error");
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
