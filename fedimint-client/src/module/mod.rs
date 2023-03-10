use std::fmt::Debug;
use std::sync::Arc;

use fedimint_core::core::{Decoder, DynInput, DynOutput, KeyPair, ModuleInstanceId};
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::module::{ModuleCommon, TransactionItemAmount};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, maybe_add_send_sync, Amount, TransactionId,
};

use crate::sm::{Context, DynContext, DynState, State};
use crate::GlobalClientContext;

pub mod gen;

/// Fedimint module client
pub trait ClientModule: Debug + MaybeSend + MaybeSync + 'static {
    /// Common module types shared between client and server
    type Common: ModuleCommon;

    /// Data and API clients available to state machine transitions of this
    /// module
    type ModuleStateMachineContext: Context;

    /// All possible states this client can submit to the executor
    type States: State<GlobalClientContext, ModuleContext = Self::ModuleStateMachineContext>;

    fn decoder() -> Decoder {
        let mut decoder_builder = Self::Common::decoder_builder();
        decoder_builder.with_decodable_type::<Self::States>();
        decoder_builder.build()
    }

    fn context(&self) -> Self::ModuleStateMachineContext;

    /// Returns the amount represented by the input and the fee its processing
    /// requires
    fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> TransactionItemAmount;

    /// Returns the amount represented by the output and the fee its processing
    /// requires
    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount;
}

/// Type-erased version of [`ClientModule`]
pub trait IClientModule: Debug {
    fn decoder(&self) -> Decoder;

    fn context(&self, instance: ModuleInstanceId) -> DynContext;

    fn input_amount(&self, input: &DynInput) -> TransactionItemAmount;

    fn output_amount(&self, output: &DynOutput) -> TransactionItemAmount;
}

impl<T> IClientModule for T
where
    T: ClientModule,
{
    fn decoder(&self) -> Decoder {
        T::decoder()
    }

    fn context(&self, instance: ModuleInstanceId) -> DynContext {
        DynContext::from_typed(instance, <T as ClientModule>::context(self))
    }

    fn input_amount(&self, input: &DynInput) -> TransactionItemAmount {
        <T as ClientModule>::input_amount(
            self,
            input
                .as_any()
                .downcast_ref()
                .expect("Dispatched to correct module"),
        )
    }

    fn output_amount(&self, output: &DynOutput) -> TransactionItemAmount {
        <T as ClientModule>::output_amount(
            self,
            output
                .as_any()
                .downcast_ref()
                .expect("Dispatched to correct module"),
        )
    }
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynClientModule(Arc<IClientModule>)
);

impl AsRef<maybe_add_send_sync!(dyn IClientModule + 'static)> for DynClientModule {
    fn as_ref(&self) -> &maybe_add_send_sync!(dyn IClientModule + 'static) {
        self.0.as_ref()
    }
}

pub type StateGenerator<S> = Box<dyn Fn(TransactionId, u64) -> Vec<S>>;

/// A client module that can be used as funding source and to generate arbitrary
/// change outputs for unbalanced transactions.
#[apply(async_trait_maybe_send!)]
pub trait PrimaryClientModule: ClientModule {
    // TODO: unclear if we should return a vec of inputs
    /// Creates an input of **at least** a given `min_amount` from the holdings
    /// managed by the module.
    ///
    /// If successful it returns:
    /// * A set of private keys belonging to the input for signing the
    ///   transaction
    /// * The input of **at least** `min_amount`, the actual amount might be
    ///   larger, the caller has to handle this case and possibly generate
    ///   change using `create_change_output`.
    /// * A closure that generates states belonging to the input. This closure
    ///   takes the transaction id of the transaction in which the input was
    ///   used and the input index as input since these cannot be known at time
    ///   of calling `create_funding_input` and have to be injected later.
    ///
    /// The function returns an error if the client's funds are not sufficient
    /// to create the requested input.
    async fn create_sufficient_input(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        min_amount: Amount,
    ) -> anyhow::Result<(
        Vec<KeyPair>,
        <Self::Common as ModuleCommon>::Input,
        StateGenerator<Self::States>,
    )>;

    /// Creates an output of **exactly** `amount` that will pay into the
    /// holdings managed by the module.
    ///
    /// It returns:
    /// * The output of **exactly** `amount`.
    /// * A closure that generates states belonging to the output. This closure
    ///   takes the transaction id of the transaction in which the output was
    ///   used and the output index as input since these cannot be known at time
    ///   of calling `create_change_output` and have to be injected later.
    async fn create_exact_output(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        amount: Amount,
    ) -> (
        <Self::Common as ModuleCommon>::Output,
        StateGenerator<Self::States>,
    );
}

/// Type-erased version of [`PrimaryClientModule`]
#[apply(async_trait_maybe_send!)]
pub trait IPrimaryClientModule: IClientModule {
    async fn create_sufficient_input(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        min_amount: Amount,
    ) -> anyhow::Result<(
        Vec<KeyPair>,
        DynInput,
        StateGenerator<DynState<GlobalClientContext>>,
    )>;

    async fn create_exact_output(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        amount: Amount,
    ) -> (DynOutput, StateGenerator<DynState<GlobalClientContext>>);

    fn as_client(&self) -> &(maybe_add_send_sync!(dyn IClientModule + 'static));
}

#[apply(async_trait_maybe_send!)]
impl<T> IPrimaryClientModule for T
where
    T: PrimaryClientModule,
{
    async fn create_sufficient_input(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        min_amount: Amount,
    ) -> anyhow::Result<(
        Vec<KeyPair>,
        DynInput,
        StateGenerator<DynState<GlobalClientContext>>,
    )> {
        let (keys, input, state_gen) = T::create_sufficient_input(self, dbtx, min_amount).await?;
        let dyn_input = DynInput::from_typed(module_instance, input);
        let dyn_states = state_gen_to_dyn(state_gen, module_instance);

        Ok((keys, dyn_input, dyn_states))
    }

    async fn create_exact_output(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        amount: Amount,
    ) -> (DynOutput, StateGenerator<DynState<GlobalClientContext>>) {
        let (output, state_gen) = T::create_exact_output(self, dbtx, amount).await;
        let dyn_output = DynOutput::from_typed(module_instance, output);
        let dyn_states = state_gen_to_dyn(state_gen, module_instance);

        (dyn_output, dyn_states)
    }

    fn as_client(&self) -> &(maybe_add_send_sync!(dyn IClientModule + 'static)) {
        self
    }
}

fn state_gen_to_dyn<S>(
    state_gen: StateGenerator<S>,
    module_instance: ModuleInstanceId,
) -> StateGenerator<DynState<GlobalClientContext>>
where
    S: State<GlobalClientContext>,
{
    Box::new(move |txid, index| {
        let states = state_gen(txid, index);
        states
            .into_iter()
            .map(|state| DynState::from_typed(module_instance, state))
            .collect()
    })
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynPrimaryClientModule(Arc<IPrimaryClientModule>)
);

impl AsRef<maybe_add_send_sync!(dyn IClientModule + 'static)> for DynPrimaryClientModule {
    fn as_ref(&self) -> &maybe_add_send_sync!(dyn IClientModule + 'static) {
        self.0.as_client()
    }
}
