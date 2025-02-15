use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::runtime;
use fedimint_core::task::TaskGroup;
use fedimint_logging::LOG_CLIENT_REACTOR;
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

impl Context for MockContext {
    const KIND: Option<ModuleKind> = None;
}

fn get_executor() -> (Executor, Sender<u64>, Database) {
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
    let executor = executor_builder.build(db.clone(), Notifier::new(db.clone()), TaskGroup::new());
    executor.start_executor(Arc::new(|_, _| DynGlobalClientContext::new_fake()));

    info!(
        target: LOG_CLIENT_REACTOR,
        "Initialized test executor"
    );
    (executor, broadcast, db)
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
