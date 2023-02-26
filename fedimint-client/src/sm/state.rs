use std::any::Any;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, DynEncodable, Encodable};
use fedimint_core::{
    dyn_newtype_define_with_instance_id, dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id,
    module_dyn_newtype_impl_encode_decode, newtype_impl_eq_passthrough_with_instance_id,
};
use futures::future::BoxFuture;

use crate::sm::{GlobalContext, OperationId};

/// Implementors act as state machines that can be executed
pub trait State:
    Debug + Clone + Eq + PartialEq + Encodable + Decodable + Send + Sync + 'static
{
    /// Additional resources made available in the state transitions
    type ModuleContext: Context;

    /// All possible transitions from the current state to other states. See
    /// [`StateTransition`] for details.
    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &GlobalContext,
    ) -> Vec<StateTransition<Self>>;

    /// Operation this state machine belongs to. See [`OperationId`] for
    /// details.
    fn operation_id(&self) -> OperationId;
}

/// Object-safe version of [`State`]
pub trait IState: Debug + DynEncodable + Send + Sync {
    fn as_any(&self) -> &(dyn Any + Send + Sync);

    /// All possible transitions from the state
    fn transitions(
        &self,
        context: &DynContext,
        global_context: &GlobalContext,
    ) -> Vec<StateTransition<DynState>>;

    /// Operation this state machine belongs to. See [`OperationId`] for
    /// details.
    fn operation_id(&self) -> OperationId;

    /// Clone state
    fn clone(&self, module_instance_id: ModuleInstanceId) -> DynState;

    fn erased_eq_no_instance_id(&self, other: &DynState) -> bool;
}

/// Something that can be a [`DynContext`] for a state machine
///
/// General purpose code should use [`DynContext`] instead
pub trait IContext: Debug {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
}

dyn_newtype_define_with_instance_id! {
    /// A shared context for a module client state machine
    #[derive(Clone)]
    pub DynContext(Arc<IContext>)
}

/// Additional data made available to state machines of a module (e.g. API
/// clients)
pub trait Context: std::fmt::Debug + Send + Sync + 'static {}

/// Type-erased version of [`Context`]
impl<T> IContext for T
where
    T: Context + 'static + Send + Sync,
{
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

type TriggerFuture = Pin<Box<dyn Future<Output = serde_json::Value> + Send + 'static>>;
// TODO: remove Arc, maybe make it a fn pointer?
type StateTransitionFunction<S> = Arc<
    dyn for<'a> Fn(&'a mut DatabaseTransaction<'_>, serde_json::Value, S) -> BoxFuture<'a, S>
        + Send
        + Sync,
>;

/// Represents one or multiple possible state transitions triggered in a common
/// way
pub struct StateTransition<S> {
    /// Future that will block until a state transition is possible.
    ///
    /// **The trigger future must be idempotent since it might be re-run if the
    /// client is restarted.**
    ///
    /// To wait for a possible state transition it can query external APIs,
    /// subscribe to events emitted by other state machines, etc.
    /// Optionally, it can also return some data that will be given to the
    /// state transition function, see the `transition` docs for details.
    pub trigger: TriggerFuture,
    /// State transition function that, using the output of the `trigger`,
    /// performs the appropriate state transition.
    ///
    /// **This function shall not block on network IO or similar things as all
    /// actual state transitions are run serially.**
    ///
    /// Since the this function can return different output states depending on
    /// the `Value` returned by the `trigger` future it can be used to model
    /// multiple possible state transition at once. E.g. instead of having
    /// two state transitions querying the same API endpoint and each waiting
    /// for a specific value to be returned to trigger their respective state
    /// transition we can have one `trigger` future querying the API and
    /// depending on the return value run different state transitions,
    /// saving network requests.
    pub transition: StateTransitionFunction<S>,
}

impl<S> StateTransition<S> {
    /// Creates a new `StateTransition` where the `trigger` future returns a
    /// value of type `V` that is then given to the `transition` function.
    pub fn new<V, Trigger, TransitionFn>(
        trigger: Trigger,
        transition: TransitionFn,
    ) -> StateTransition<S>
    where
        S: Send + Sync + Clone + 'static,
        V: serde::Serialize + serde::de::DeserializeOwned + Send,
        Trigger: Future<Output = V> + Send + 'static,
        TransitionFn: for<'a> Fn(&'a mut DatabaseTransaction<'_>, V, S) -> BoxFuture<'a, S>
            + Send
            + Sync
            + Copy
            + 'static,
    {
        StateTransition {
            trigger: Box::pin(async move {
                let val = trigger.await;
                serde_json::to_value(val).expect("Value could not be serialized")
            }),
            transition: Arc::new(move |dbtx, val, state| {
                Box::pin(async move {
                    let typed_val: V = serde_json::from_value(val)
                        .expect("Deserialize trigger return value failed");
                    transition(dbtx, typed_val, state.clone()).await
                })
            }),
        }
    }
}

impl<T> IState for T
where
    T: State,
{
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn transitions(
        &self,
        context: &DynContext,
        global_context: &GlobalContext,
    ) -> Vec<StateTransition<DynState>> {
        <T as State>::transitions(
            self,
            context.as_any().downcast_ref().expect("Wrong module"),
            global_context,
        )
        .into_iter()
        .map(|st| StateTransition {
            trigger: st.trigger,
            transition: Arc::new(
                move |dbtx: &mut DatabaseTransaction, val, state: DynState| {
                    let transition = st.transition.clone();
                    Box::pin(async move {
                        let new_state = transition(
                            &mut dbtx.with_module_prefix(state.module_instance_id()),
                            val,
                            state
                                .as_any()
                                .downcast_ref::<T>()
                                .expect("Wrong module")
                                .clone(),
                        )
                        .await;
                        DynState::from_typed(state.module_instance_id(), new_state)
                    })
                },
            ),
        })
        .collect()
    }

    fn operation_id(&self) -> OperationId {
        <T as State>::operation_id(self)
    }

    fn clone(&self, module_instance_id: ModuleInstanceId) -> DynState {
        DynState::from_typed(module_instance_id, <T as Clone>::clone(self))
    }

    fn erased_eq_no_instance_id(&self, other: &DynState) -> bool {
        let other: &T = other
            .as_any()
            .downcast_ref()
            .expect("Type is ensured in previous step");

        self == other
    }
}

dyn_newtype_define_with_instance_id! {
    /// A type-erased state of a state machine belonging to a module instance, see [`State`]
    pub DynState(Box<IState>)
}

dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(DynState);

newtype_impl_eq_passthrough_with_instance_id!(DynState);

module_dyn_newtype_impl_encode_decode!(DynState);

impl DynState {
    /// `true` if this state allows no further transitions
    pub fn is_terminal(&self, context: &DynContext, global_context: &GlobalContext) -> bool {
        self.transitions(context, global_context).is_empty()
    }
}
