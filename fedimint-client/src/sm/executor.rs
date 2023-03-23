use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::{Error, Read, Write};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::bail;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{AutocommitError, Database};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use futures::future::select_all;
use futures::stream::StreamExt;
use tokio::select;
use tracing::{debug, error, info, warn};

use crate::sm::state::{DynContext, DynState};
use crate::sm::{GlobalContext, State, StateTransition};

/// After how many retries a DB transaction is aborted with an error
const MAX_DB_RETRIES: Option<usize> = Some(100);

/// Wait time till checking the DB for new state machines when there are no
/// active ones
const EXECUTOR_POLL_INTERVAL: Duration = Duration::from_secs(1);

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
pub struct Executor<GC> {
    inner: Arc<ExecutorInner<GC>>,
}

struct ExecutorInner<GC> {
    db: Database,
    context: GC,
    module_contexts: BTreeMap<ModuleInstanceId, DynContext>,
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

    /// Adds a number of state machines to the executor atomically. They will be
    /// driven to completion automatically in the background.
    pub async fn add_state_machines(&self, states: Vec<DynState<GC>>) -> anyhow::Result<()> {
        self.inner.db
            .autocommit(
                |dbtx| {
                    let states = states.clone();
                    Box::pin(async move {
                        for state in states {
                            if !self.inner.module_contexts.contains_key(&state.module_instance_id()) {
                                bail!("Unknown module");
                            }

                            let is_active_state = dbtx
                                .get_value(&ActiveStateKey::<GC>(state.clone()))
                                .await
                                .is_some();
                            let is_inactive_state = dbtx
                                .get_value(&InactiveStateKey::<GC>(state.clone()))
                                .await
                                .is_some();

                            if is_active_state || is_inactive_state {
                                bail!("State already exists in database!")
                            }

                            if state.is_terminal(self.inner.module_contexts.get(&state.module_instance_id()).expect("No such module"), &self.inner.context) {
                                bail!("State is already terminal, adding it to the executor doesn't make sense.")
                            }

                            dbtx.insert_entry(&ActiveStateKey(state), &ActiveState::new()).await;
                        }

                        Ok(())
                    })
                },
                MAX_DB_RETRIES,
            )
            .await
            .map_err(|e| match e {
                AutocommitError::CommitFailed { last_error , retries } => {
                    last_error.context(format!("Failed to commit after {retries} retries"))
                }
                AutocommitError::ClosureError { error, .. } => {error}
            })?;

        Ok(())
    }

    /// **Mostly used for testing**
    ///
    /// Check if state exists in the database as part of an actively running
    /// state machine.
    pub async fn contains_active_state<S: State<GC>>(
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
    pub async fn contains_inactive_state<S: State<GC>>(
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
}

impl<GC> ExecutorInner<GC>
where
    GC: GlobalContext,
{
    async fn run(&self) {
        info!("Starting state machine executor task");
        loop {
            if let Err(err) = self.execute_next_state_transition().await {
                warn!(
                    %err,
                    "An unexpected error occurred during a state transition"
                );
            }
        }
    }

    async fn execute_next_state_transition(&self) -> anyhow::Result<()> {
        let active_states = self.get_active_states().await;

        if active_states.is_empty() {
            // FIXME: what to do in this case? Probably best to subscribe to DB eventually
            debug!("No state transitions available, waiting before re-trying");
            tokio::time::sleep(EXECUTOR_POLL_INTERVAL).await;
            return Ok(());
        }

        let transitions = active_states
            .iter()
            .flat_map(|(state, meta)| {
                let module_instance = state.module_instance_id();
                let context = &self
                    .module_contexts
                    .get(&module_instance)
                    .expect("Unknown module");
                state
                    .transitions(context, &self.context)
                    .into_iter()
                    .map(move |transition| {
                        Box::pin(async move {
                            let StateTransition {
                                trigger,
                                transition,
                            } = transition;
                            (trigger.await, state.clone(), transition, meta)
                        })
                    })
            })
            .collect::<Vec<_>>();

        let num_states = active_states.len();
        let num_transitions = transitions.len();
        debug!(
            num_states,
            num_transitions, "Awaiting any state transition to become ready"
        );

        let ((transition_outcome, state, transition_fn, meta), _, _) =
            select_all(transitions).await;

        self.db
            .autocommit(
                |dbtx| {
                    let state = state.clone();
                    let transition_fn = transition_fn.clone();
                    let transition_outcome = transition_outcome.clone();
                    Box::pin(async move {
                        let new_state = transition_fn(
                            &mut dbtx.with_module_prefix(state.module_instance_id()),
                            transition_outcome,
                            state.clone(),
                        )
                        .await;
                        dbtx.remove_entry(&ActiveStateKey(state.clone())).await;
                        dbtx.insert_entry(&InactiveStateKey(state.clone()), &meta.into_inactive())
                            .await;

                        let context = &self
                            .module_contexts
                            .get(&state.module_instance_id())
                            .expect("Unknown module");
                        let global_context = &self.context;

                        if new_state.is_terminal(context, global_context) {
                            // TODO: log state machine id or something
                            debug!("State machine reached terminal state");
                            dbtx.insert_entry(
                                &InactiveStateKey(new_state),
                                &ActiveState::new().into_inactive(),
                            )
                            .await;
                        } else {
                            dbtx.insert_entry(&ActiveStateKey(new_state), &ActiveState::new())
                                .await;
                        }

                        Ok(())
                    })
                },
                Some(100),
            )
            .await
            .map_err(|e| match e {
                AutocommitError::CommitFailed {
                    last_error,
                    retries,
                } => last_error.context(format!("Failed to commit after {retries} retries")),
                AutocommitError::ClosureError { error, .. } => error,
            })?;

        Ok(())
    }

    async fn get_active_states(&self) -> Vec<(DynState<GC>, ActiveState)> {
        self.db
            .begin_transaction()
            .await
            .find_by_prefix(&ActiveStateKeyPrefix::<GC>::new())
            .await
            .map(|(state, meta)| (state.0, meta))
            .collect::<Vec<_>>()
            .await
    }

    async fn get_inactive_states(&self) -> Vec<(DynState<GC>, InactiveState)> {
        self.db
            .begin_transaction()
            .await
            .find_by_prefix(&InactiveStateKeyPrefix::new())
            .await
            .map(|(state, meta)| (state.0, meta))
            .collect::<Vec<_>>()
            .await
    }
}

impl ExecutorBuilder {
    /// Allow executor being built to run state machines associated with the
    /// supplied module
    pub fn with_module<C>(&mut self, instance_id: ModuleInstanceId, context: C)
    where
        C: IntoDynInstance<DynType = DynContext>,
    {
        if self
            .module_contexts
            .insert(instance_id, context.into_dyn(instance_id))
            .is_some()
        {
            panic!("Tried to add two modules with the same instance id!");
        }
    }

    /// Build [`Executor`] and spawn background task in `tasks` executing active
    /// state machines. The supplied database `db` must support isolation, so
    /// cannot be an isolated DB instance itself.
    pub async fn build<GC>(self, tasks: &mut TaskGroup, db: Database, context: GC) -> Executor<GC>
    where
        GC: GlobalContext,
    {
        let inner = Arc::new(ExecutorInner {
            db,
            context,
            module_contexts: self.module_contexts,
        });

        let task_runner_inner = inner.clone();
        let _handle = tasks
            .spawn("state_machine_executor", move |handle| async move {
                let shutdown_future = handle.make_shutdown_rx().await;
                let executor_runner = task_runner_inner.run();
                select! {
                    _ = shutdown_future => {
                        info!("Shutting down state machine executor runner");
                    },
                    _ = executor_runner => {
                        error!("State machine executor runner exited unexpectedly!");
                    },
                };
            })
            .await;

        debug!(
            instances = ?inner.module_contexts.keys().copied().collect::<Vec<_>>(),
            "Initialized state machine executor with module instances"
        );
        Executor { inner }
    }
}

/// A state that is able to make progress eventually
#[derive(Debug)]
struct ActiveStateKey<GC>(DynState<GC>);

impl<GC> Encodable for ActiveStateKey<GC> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.0.consensus_encode(writer)
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
        Ok(ActiveStateKey(DynState::consensus_decode(reader, modules)?))
    }
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
struct ActiveState {
    created_at: SystemTime,
}

impl<GC> ::fedimint_core::db::DatabaseRecord for ActiveStateKey<GC>
where
    GC: GlobalContext,
{
    const DB_PREFIX: u8 = ExecutorDbPrefixes::ActiveStates as u8;
    type Key = Self;
    type Value = ActiveState;
}
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
struct InactiveStateKey<GC>(DynState<GC>);

impl<GC> Encodable for InactiveStateKey<GC>
where
    GC: GlobalContext,
{
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.0.consensus_encode(writer)
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
        Ok(InactiveStateKey(DynState::consensus_decode(
            reader, modules,
        )?))
    }
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
struct InactiveState {
    created_at: SystemTime,
    exited_at: SystemTime,
}

impl<GC> ::fedimint_core::db::DatabaseRecord for InactiveStateKey<GC>
where
    GC: GlobalContext,
{
    const DB_PREFIX: u8 = ExecutorDbPrefixes::InactiveStates as u8;
    type Key = Self;
    type Value = InactiveState;
}

impl<GC> ::fedimint_core::db::DatabaseLookup for InactiveStateKeyPrefix<GC>
where
    GC: GlobalContext,
{
    type Record = InactiveStateKey<GC>;
}

#[cfg(test)]
mod tests {
    use std::fmt::{Debug, Display, Formatter};
    use std::time::Duration;

    use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::ModuleCommon;
    use fedimint_core::plugin_types_trait_impl_common;
    use fedimint_core::task::TaskGroup;
    use impl_tools::autoimpl;
    use serde::{Deserialize, Serialize};
    use tokio::sync::broadcast::Sender;
    use tracing::{info, trace};

    use crate::module::ClientModule;
    use crate::sm::state::{Context, DynContext, DynState};
    use crate::sm::{Executor, OperationId, State, StateTransition};

    #[derive(Debug)]
    struct MockClientModule(tokio::sync::broadcast::Sender<u64>);

    struct MockCommon;

    #[autoimpl(Deref, DerefMut using self.0)]
    #[derive(
        Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
    )]
    struct MockInput(());

    impl Display for MockInput {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            std::fmt::Debug::fmt(self, f)
        }
    }

    #[autoimpl(Deref, DerefMut using self.0)]
    #[derive(
        Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
    )]
    struct MockOutput(());

    impl Display for MockOutput {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            std::fmt::Debug::fmt(self, f)
        }
    }

    #[autoimpl(Deref, DerefMut using self.0)]
    #[derive(
        Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
    )]
    struct MockOutputOutcome(());

    impl Display for MockOutputOutcome {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            std::fmt::Debug::fmt(self, f)
        }
    }

    #[autoimpl(Deref, DerefMut using self.0)]
    #[derive(
        Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
    )]
    struct MockConsensusItem(());

    impl Display for MockConsensusItem {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            std::fmt::Debug::fmt(self, f)
        }
    }

    plugin_types_trait_impl_common!(MockInput, MockOutput, MockOutputOutcome, MockConsensusItem);

    impl ModuleCommon for MockCommon {
        type Input = MockInput;
        type Output = MockOutput;
        type OutputOutcome = MockOutputOutcome;
        type ConsensusItem = MockConsensusItem;
    }

    #[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
    enum MockStateMachine {
        Start,
        ReceivedNonNull(u64),
        Final,
    }

    impl State<()> for MockStateMachine {
        type ModuleContext = MockContext;

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
            [0u8; 32]
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

    impl ClientModule for MockClientModule {
        type Common = MockCommon;
        type ModuleStateMachineContext = MockContext;
        type GlobalStateMachineContext = ();
        type States = MockStateMachine;

        fn context(&self) -> Self::ModuleStateMachineContext {
            MockContext {
                broadcast: self.0.clone(),
            }
        }
    }

    async fn get_executor(tg: &mut TaskGroup) -> (Executor<()>, Sender<u64>, Database) {
        let (broadcast, _) = tokio::sync::broadcast::channel(10);
        let module = MockClientModule(broadcast.clone());

        let decoders = ModuleDecoderRegistry::new(vec![(42, MockClientModule::decoder())]);
        let db = Database::new(MemDatabase::new(), decoders);

        let mut executor_builder = Executor::<()>::builder();
        executor_builder.with_module(42, module.context());
        let executor = executor_builder.build(tg, db.clone(), ()).await;

        info!("Initialized test executor");
        (executor, broadcast, db)
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_executor() {
        const MOCK_INSTANCE_1: ModuleInstanceId = 42;
        const MOCK_INSTANCE_2: ModuleInstanceId = 21;

        let mut task_group = TaskGroup::new();
        let (executor, sender, _db) = get_executor(&mut task_group).await;
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
        tokio::time::sleep(Duration::from_secs(1)).await;
        sender.send(0).unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(
            executor
                .contains_inactive_state(MOCK_INSTANCE_1, MockStateMachine::Final)
                .await,
            "State was written to DB and waits for broadcast"
        );
    }
}
