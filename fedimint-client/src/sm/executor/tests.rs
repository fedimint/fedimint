use std::fmt::Debug;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use fedimint_client_module::error::AddStateMachinesError;
use fedimint_client_module::sm::executor::ActiveStateKey;
use fedimint_client_module::sm::{
    ActiveStateMeta, Context, DynContext, DynState, State, StateTransition,
};
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::runtime;
use fedimint_core::task::TaskGroup;
use fedimint_logging::LOG_CLIENT_REACTOR;
use tokio::sync::broadcast::Sender;
use tokio::sync::watch;
use tracing::{info, trace};

use super::{ActiveStateKeyDb, Executor};
use crate::DynGlobalClientContext;
use crate::sm::notifier::Notifier;

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
                        |_dbtx, (), _state| Box::pin(async { MockStateMachine::Final }),
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
                    |_dbtx, (), _state| Box::pin(async { MockStateMachine::Final }),
                )]
            }
            MockStateMachine::Final => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        MOCK_OPERATION
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

impl Context for MockContext {
    const KIND: Option<ModuleKind> = None;
}

/// The operation every [`MockStateMachine`] belongs to.
const MOCK_OPERATION: OperationId = OperationId([0u8; 32]);

fn get_executor() -> (Executor, Sender<u64>, Database) {
    let (executor, broadcast, db) = build_executor();

    start_executor(&executor);

    (executor, broadcast, db)
}

/// An executor that is not running yet, for tests that need to arrange the
/// database it will find when it starts.
fn build_executor() -> (Executor, Sender<u64>, Database) {
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
    let (log_ordering_wakeup_tx, _log_ordering_wakeup_rx) = watch::channel(());
    let executor = executor_builder.build(
        db.clone(),
        Notifier::new(),
        TaskGroup::new(),
        log_ordering_wakeup_tx,
    );

    (executor, broadcast, db)
}

fn start_executor(executor: &Executor) {
    executor.start_executor(
        Arc::new(|_, _| DynGlobalClientContext::new_fake()),
        tracing::Span::none(),
    );

    info!(
        target: LOG_CLIENT_REACTOR,
        "Initialized test executor"
    );
}

/// Waits until `count` triggers of the mock state machine are listening on
/// its broadcast, which is how a test knows the executor has started the
/// state it is about to send a value to.
async fn await_trigger_receivers(sender: &Sender<u64>, count: usize) {
    while sender.receiver_count() != count {
        runtime::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_executor() {
    const MOCK_INSTANCE_1: ModuleInstanceId = 42;
    const MOCK_INSTANCE_2: ModuleInstanceId = 21;

    let (executor, sender, _db) = get_executor();
    executor
        .add_state_machines(vec![DynState::from_typed(
            MOCK_INSTANCE_1,
            MockStateMachine::Start,
        )])
        .await
        .unwrap();

    let err = executor
        .add_state_machines(vec![DynState::from_typed(
            MOCK_INSTANCE_1,
            MockStateMachine::Start,
        )])
        .await
        .expect_err("Running the same state machine a second time should fail");
    assert!(
        matches!(err, AddStateMachinesError::StateAlreadyExists),
        "{err:?}"
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
    runtime::sleep(Duration::from_secs(1)).await;
    sender.send(0).unwrap();
    runtime::sleep(Duration::from_secs(2)).await;

    assert!(
        executor
            .contains_inactive_state(MOCK_INSTANCE_1, MockStateMachine::Final)
            .await,
        "State was written to DB and waits for broadcast"
    );
}

#[tokio::test]
async fn adding_a_state_of_an_unknown_module_is_typed() {
    const UNREGISTERED_INSTANCE: ModuleInstanceId = 21;

    let (executor, _sender, _db) = get_executor();

    let err = executor
        .add_state_machines(vec![DynState::from_typed(
            UNREGISTERED_INSTANCE,
            MockStateMachine::Start,
        )])
        .await
        .expect_err("The executor does not know this module instance");

    assert!(
        matches!(
            err,
            AddStateMachinesError::UnknownModule {
                module_instance_id: UNREGISTERED_INSTANCE
            }
        ),
        "{err:?}"
    );
}

/// A panic while the executor state write lock is held, e.g. from a panicking
/// tracing subscriber, poisons the lock. `stop_executor` runs from destructors,
/// which must never panic, so it has to tolerate the poison instead of
/// panicking on it.
#[tokio::test]
async fn stop_executor_tolerates_poisoned_state_lock() {
    let (executor, _sender, _db) = get_executor();

    let executor_clone = executor.clone();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = executor_clone
            .inner
            .state
            .write()
            .expect("Not poisoned yet");
        panic!("Poison the executor state lock");
    }))
    .expect_err("Must have panicked to poison the lock");

    assert!(executor.inner.state.is_poisoned());
    executor.stop_executor();
}

/// Waiting for an operation to have no active states returns at once when it
/// has none, keeps waiting while a state machine moves between non-terminal
/// states, and returns once the last one has reached its terminal state.
#[tokio::test]
async fn awaiting_no_active_states_returns_once_the_last_state_machine_is_terminal() {
    const MOCK_INSTANCE: ModuleInstanceId = 42;
    const NOT_YET: Duration = Duration::from_millis(200);
    const SOON: Duration = Duration::from_secs(10);

    let (executor, sender, _db) = get_executor();

    runtime::timeout(SOON, executor.await_no_active_states(MOCK_OPERATION))
        .await
        .expect("An operation that never started a state machine has none running");

    executor
        .add_state_machines(vec![DynState::from_typed(
            MOCK_INSTANCE,
            MockStateMachine::Start,
        )])
        .await
        .expect("The state machine is new");

    assert!(executor.has_active_states(MOCK_OPERATION).await);

    let mut finished = pin!(executor.await_no_active_states(MOCK_OPERATION));

    assert!(
        runtime::timeout(NOT_YET, &mut finished).await.is_err(),
        "The state machine has not moved yet"
    );

    // `Start` -> `ReceivedNonNull(7)`: the operation moves, but is not over.
    await_trigger_receivers(&sender, 2).await;
    sender.send(7).expect("The triggers are listening");
    executor
        .await_active_state(DynState::from_typed(
            MOCK_INSTANCE,
            MockStateMachine::ReceivedNonNull(7),
        ))
        .await;

    assert!(
        runtime::timeout(NOT_YET, &mut finished).await.is_err(),
        "The state machine moved to another non-terminal state"
    );

    // `ReceivedNonNull(7)` -> `Final`.
    await_trigger_receivers(&sender, 1).await;
    sender.send(7).expect("The trigger is listening");

    runtime::timeout(SOON, &mut finished)
        .await
        .expect("The only state machine of the operation reached its terminal state");

    assert!(!executor.has_active_states(MOCK_OPERATION).await);
    assert!(
        executor
            .contains_inactive_state(MOCK_INSTANCE, MockStateMachine::Final)
            .await
    );
}

/// A terminal state can be found among the active ones, for example one a
/// recovery added before its module was there to say it is terminal. The
/// executor makes it inactive when it comes across it, and those waiting for
/// the operation to have no active states have to hear about that too.
#[tokio::test]
async fn awaiting_no_active_states_notices_a_terminal_state_being_inactivated() {
    const MOCK_INSTANCE: ModuleInstanceId = 42;
    const NOT_YET: Duration = Duration::from_millis(200);
    const SOON: Duration = Duration::from_secs(10);

    let (executor, _sender, db) = build_executor();

    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(
        &ActiveStateKeyDb(ActiveStateKey::from_state(DynState::from_typed(
            MOCK_INSTANCE,
            MockStateMachine::Final,
        ))),
        &ActiveStateMeta::default(),
    )
    .await;
    dbtx.commit_tx().await;

    let mut finished = pin!(executor.await_no_active_states(MOCK_OPERATION));

    assert!(
        runtime::timeout(NOT_YET, &mut finished).await.is_err(),
        "Nothing runs the state before the executor starts"
    );

    start_executor(&executor);

    runtime::timeout(SOON, &mut finished)
        .await
        .expect("The executor made the terminal state inactive");

    assert!(!executor.has_active_states(MOCK_OPERATION).await);
}
