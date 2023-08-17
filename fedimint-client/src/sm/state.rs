use std::any::Any;
use std::fmt::Debug;
use std::future::Future;
use std::io::{Error, Read, Write};
use std::pin::Pin;
use std::sync::Arc;

use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, DecodeError, DynEncodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::BoxFuture;
use fedimint_core::{maybe_add_send, maybe_add_send_sync, module_plugin_dyn_newtype_define};

use crate::sm::{ClientSMDatabaseTransaction, GlobalContext, OperationId};

/// Implementors act as state machines that can be executed
pub trait State:
    Debug + Clone + Eq + PartialEq + Encodable + Decodable + MaybeSend + MaybeSync + 'static
{
    /// Additional resources made available in this module's state transitions
    type ModuleContext: Context;

    /// Additional resources made available for all state transitions
    type GlobalContext: GlobalContext;

    /// All possible transitions from the current state to other states. See
    /// [`StateTransition`] for details.
    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>>;

    // TODO: move out of this interface into wrapper struct (see OperationState)
    /// Operation this state machine belongs to. See [`OperationId`] for
    /// details.
    fn operation_id(&self) -> OperationId;
}

/// Object-safe version of [`State`]
pub trait IState<GC>: Debug + DynEncodable + MaybeSend + MaybeSync {
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any));

    /// All possible transitions from the state
    fn transitions(
        &self,
        context: &DynContext,
        global_context: &GC,
    ) -> Vec<StateTransition<DynState<GC>>>;

    /// Operation this state machine belongs to. See [`OperationId`] for
    /// details.
    fn operation_id(&self) -> OperationId;

    /// Clone state
    fn clone(&self, module_instance_id: ModuleInstanceId) -> DynState<GC>;

    fn erased_eq_no_instance_id(&self, other: &DynState<GC>) -> bool;
}

/// Something that can be a [`DynContext`] for a state machine
///
/// General purpose code should use [`DynContext`] instead
pub trait IContext: Debug {
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any));
}

module_plugin_dyn_newtype_define! {
    /// A shared context for a module client state machine
    #[derive(Clone)]
    pub DynContext(Arc<IContext>)
}

/// Additional data made available to state machines of a module (e.g. API
/// clients)
pub trait Context: std::fmt::Debug + MaybeSend + MaybeSync + 'static {}

impl Context for () {}

/// Type-erased version of [`Context`]
impl<T> IContext for T
where
    T: Context + 'static + MaybeSend + MaybeSync,
{
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any)) {
        self
    }
}

type TriggerFuture = Pin<Box<maybe_add_send!(dyn Future<Output = serde_json::Value> + 'static)>>;

// TODO: remove Arc, maybe make it a fn pointer?
pub(super) type StateTransitionFunction<S> = Arc<
    maybe_add_send_sync!(
        dyn for<'a> Fn(
            &'a mut ClientSMDatabaseTransaction<'_, '_>,
            serde_json::Value,
            S,
        ) -> BoxFuture<'a, S>
    ),
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
        S: MaybeSend + MaybeSync + Clone + 'static,
        V: serde::Serialize + serde::de::DeserializeOwned + Send,
        Trigger: Future<Output = V> + MaybeSend + 'static,
        TransitionFn: for<'a> Fn(&'a mut ClientSMDatabaseTransaction<'_, '_>, V, S) -> BoxFuture<'a, S>
            + MaybeSend
            + MaybeSync
            + Clone
            + 'static,
    {
        StateTransition {
            trigger: Box::pin(async move {
                let val = trigger.await;
                serde_json::to_value(val).expect("Value could not be serialized")
            }),
            transition: Arc::new(move |dbtx, val, state| {
                let transition = transition.clone();
                Box::pin(async move {
                    let typed_val: V = serde_json::from_value(val)
                        .expect("Deserialize trigger return value failed");
                    transition(dbtx, typed_val, state.clone()).await
                })
            }),
        }
    }
}

impl<GC, T> IState<GC> for T
where
    GC: GlobalContext,
    T: State<GlobalContext = GC>,
{
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any)) {
        self
    }

    fn transitions(
        &self,
        context: &DynContext,
        global_context: &GC,
    ) -> Vec<StateTransition<DynState<GC>>> {
        <T as State>::transitions(
            self,
            context.as_any().downcast_ref().expect("Wrong module"),
            global_context,
        )
        .into_iter()
        .map(|st| StateTransition {
            trigger: st.trigger,
            transition: Arc::new(
                move |dbtx: &mut ClientSMDatabaseTransaction<'_, '_>, val, state: DynState<GC>| {
                    let transition = st.transition.clone();
                    Box::pin(async move {
                        let new_state = transition(
                            dbtx,
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

    fn clone(&self, module_instance_id: ModuleInstanceId) -> DynState<GC> {
        DynState::from_typed(module_instance_id, <T as Clone>::clone(self))
    }

    fn erased_eq_no_instance_id(&self, other: &DynState<GC>) -> bool {
        let other: &T = other
            .as_any()
            .downcast_ref()
            .expect("Type is ensured in previous step");

        self == other
    }
}

/// A type-erased state of a state machine belonging to a module instance, see
/// [`State`]
pub struct DynState<GC>(
    Box<maybe_add_send_sync!(dyn IState<GC> + 'static)>,
    ModuleInstanceId,
);

impl<GC> std::ops::Deref for DynState<GC> {
    type Target = maybe_add_send_sync!(dyn IState<GC> + 'static);

    fn deref(&self) -> &<Self as std::ops::Deref>::Target {
        &*self.0
    }
}

impl<GC> DynState<GC> {
    pub fn module_instance_id(&self) -> ModuleInstanceId {
        self.1
    }

    pub fn from_typed<I>(module_instance_id: ModuleInstanceId, typed: I) -> Self
    where
        I: IState<GC> + 'static,
    {
        Self(Box::new(typed), module_instance_id)
    }

    pub fn from_parts(
        module_instance_id: ::fedimint_core::core::ModuleInstanceId,
        dynbox: Box<maybe_add_send_sync!(dyn IState<GC> + 'static)>,
    ) -> Self {
        Self(dynbox, module_instance_id)
    }
}

impl<GC> std::fmt::Debug for DynState<GC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl<GC> std::ops::DerefMut for DynState<GC> {
    fn deref_mut(&mut self) -> &mut <Self as std::ops::Deref>::Target {
        &mut *self.0
    }
}

impl<GC> Clone for DynState<GC> {
    fn clone(&self) -> Self {
        self.0.clone(self.1)
    }
}

impl<GC> PartialEq for DynState<GC> {
    fn eq(&self, other: &Self) -> bool {
        if self.1 != other.1 {
            return false;
        }
        self.erased_eq_no_instance_id(other)
    }
}
impl<GC> Eq for DynState<GC> {}

impl<GC> Encodable for DynState<GC> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.1.consensus_encode(writer)?;
        self.0.consensus_encode_dyn(writer)
    }
}
impl<GC> Decodable for DynState<GC>
where
    GC: GlobalContext,
{
    fn consensus_decode<R: std::io::Read>(
        reader: &mut R,
        modules: &::fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let key = fedimint_core::core::ModuleInstanceId::consensus_decode(reader, modules)?;
        modules.get_expect(key).decode(reader, key, modules)
    }
}

impl<GC> DynState<GC> {
    /// `true` if this state allows no further transitions
    pub fn is_terminal(&self, context: &DynContext, global_context: &GC) -> bool {
        self.transitions(context, global_context).is_empty()
    }
}

#[derive(Debug)]
pub struct OperationState<S> {
    pub operation_id: OperationId,
    pub state: S,
}

/// Wrapper for states that don't want to carry around their operation id. `S`
/// is allowed to panic when `operation_id` is called.
impl<S> State for OperationState<S>
where
    S: State,
{
    type ModuleContext = S::ModuleContext;
    type GlobalContext = S::GlobalContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<StateTransition<Self>> {
        let transitions: Vec<StateTransition<OperationState<S>>> = self
            .state
            .transitions(context, global_context)
            .into_iter()
            .map(
                |StateTransition {
                     trigger,
                     transition,
                 }| {
                    let op_transition: StateTransitionFunction<Self> =
                        Arc::new(move |dbtx, value, op_state| {
                            let transition = transition.clone();
                            Box::pin(async move {
                                let state = transition(dbtx, value, op_state.state).await;
                                OperationState {
                                    operation_id: op_state.operation_id,
                                    state,
                                }
                            })
                        });

                    StateTransition {
                        trigger,
                        transition: op_transition,
                    }
                },
            )
            .collect();
        transitions
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

// TODO: can we get rid of `GC`? Maybe make it an associated type of `State`
// instead?
impl<S> IntoDynInstance for OperationState<S>
where
    S: State,
{
    type DynType = DynState<S::GlobalContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl<S> Encodable for OperationState<S>
where
    S: State,
{
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.operation_id.consensus_encode(writer)?;
        len += self.state.consensus_encode(writer)?;
        Ok(len)
    }
}

impl<S> Decodable for OperationState<S>
where
    S: State,
{
    fn consensus_decode<R: Read>(
        read: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let operation_id = OperationId::consensus_decode(read, modules)?;
        let state = S::consensus_decode(read, modules)?;

        Ok(OperationState {
            operation_id,
            state,
        })
    }
}

// TODO: derive after getting rid of `GC` type arg
impl<S> PartialEq for OperationState<S>
where
    S: State,
{
    fn eq(&self, other: &Self) -> bool {
        self.operation_id.eq(&other.operation_id) && self.state.eq(&other.state)
    }
}

impl<S> Eq for OperationState<S> where S: State {}

impl<S> Clone for OperationState<S>
where
    S: State,
{
    fn clone(&self) -> Self {
        OperationState {
            operation_id: self.operation_id,
            state: self.state.clone(),
        }
    }
}
