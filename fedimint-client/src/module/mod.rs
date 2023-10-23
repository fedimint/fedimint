use std::any::Any;
use std::ffi;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::bail;
use fedimint_core::api::DynGlobalApi;
use fedimint_core::core::{
    Decoder, DynInput, DynOutput, IntoDynInstance, ModuleInstanceId, OperationId,
};
use fedimint_core::db::{DatabaseTransaction, ModuleDatabaseTransaction};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{ModuleCommon, TransactionItemAmount};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::BoxStream;
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, maybe_add_send_sync, Amount, OutPoint,
    TransactionId,
};

use crate::sm::{Context, DynContext, DynState, Executor, State};
use crate::transaction::{ClientInput, ClientOutput};
use crate::{Client, DynGlobalClientContext};

pub mod init;

pub type ClientModuleRegistry = ModuleRegistry<DynClientModule>;

/// Fedimint module client
#[apply(async_trait_maybe_send!)]
pub trait ClientModule: Debug + MaybeSend + MaybeSync + 'static {
    /// Common module types shared between client and server
    type Common: ModuleCommon;

    /// Data and API clients available to state machine transitions of this
    /// module
    type ModuleStateMachineContext: Context;

    /// All possible states this client can submit to the executor
    type States: State<
            GlobalContext = DynGlobalClientContext,
            ModuleContext = Self::ModuleStateMachineContext,
        > + IntoDynInstance<DynType = DynState<DynGlobalClientContext>>;

    fn decoder() -> Decoder {
        let mut decoder_builder = Self::Common::decoder_builder();
        decoder_builder.with_decodable_type::<Self::States>();
        decoder_builder.build()
    }

    fn context(&self) -> Self::ModuleStateMachineContext;

    async fn handle_cli_command(
        &self,
        _client: &Client,
        _args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        Err(anyhow::format_err!(
            "This module does not implement cli commands"
        ))
    }

    /// Returns the amount represented by the input and the fee its processing
    /// requires
    fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> TransactionItemAmount;

    /// Returns the amount represented by the output and the fee its processing
    /// requires
    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount;

    fn supports_backup(&self) -> bool {
        false
    }

    async fn backup(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _executor: Executor<DynGlobalClientContext>,
        _api: DynGlobalApi,
        _module_instance_id: ModuleInstanceId,
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("Backup not supported");
    }

    async fn restore(
        &self,
        // _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _dbtx: &mut DatabaseTransaction<'_>,
        _module_instance_id: ModuleInstanceId,
        _executor: Executor<DynGlobalClientContext>,
        _api: DynGlobalApi,
        _snapshot: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("Backup not supported");
    }

    async fn wipe(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _module_instance_id: ModuleInstanceId,
        _executor: Executor<DynGlobalClientContext>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("Wiping not supported");
    }

    /// Does this module support being a primary module
    ///
    /// If it does it must implement:
    ///
    /// * [`Self::create_sufficient_input`]
    /// * [`Self::create_exact_output`]
    /// * [`Self::await_primary_module_output`]
    /// * [`Self::get_balance`]
    /// * [`Self::subscribe_balance_changes`]
    fn supports_being_primary(&self) -> bool {
        false
    }

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
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _operation_id: OperationId,
        _min_amount: Amount,
    ) -> anyhow::Result<Vec<ClientInput<<Self::Common as ModuleCommon>::Input, Self::States>>> {
        unimplemented!()
    }

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
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _operation_id: OperationId,
        _amount: Amount,
    ) -> Vec<ClientOutput<<Self::Common as ModuleCommon>::Output, Self::States>> {
        unimplemented!()
    }

    /// Waits for the funds from an output created by
    /// [`Self::create_exact_output`] to become available. This function
    /// returning typically implies a change in the output of
    /// [`Self::get_balance`].
    async fn await_primary_module_output(
        &self,
        _operation_id: OperationId,
        _out_point: OutPoint,
    ) -> anyhow::Result<Amount> {
        unimplemented!()
    }

    /// Returns the balance held by this module and available for funding
    /// transactions.
    async fn get_balance(&self, _dbtx: &mut ModuleDatabaseTransaction<'_>) -> Amount {
        unimplemented!()
    }

    /// Returns a stream that will output the updated module balance each time
    /// it changes.
    async fn subscribe_balance_changes(&self) -> BoxStream<'static, ()> {
        unimplemented!()
    }

    /// Leave the federation
    ///
    /// While technically there's nothing stopping the client from just
    /// abandoning Federation at any point by deleting all the related
    /// local data, it is useful to make sure it's safe beforehand.
    ///
    /// This call indicates the desire of the caller client code
    /// to orderly and safely leave the Federation by this module instance.
    /// The goal of the implementations is to fulfil that wish,
    /// giving prompt and informative feedback if it's not yet possible.
    ///
    /// The client module implementation should handle the request
    /// and return as fast as possible avoiding blocking for longer than
    /// necessary. This would usually involve some combination of:
    ///
    /// * recording the state of being in process of leaving the Federation to
    ///   prevent initiating new conditions that could delay its completion;
    /// * performing any fast to complete cleanup/exit logic;
    /// * initiating any time-consuming logic (e.g. canceling outstanding
    ///   contracts), as background jobs, tasks machines, etc.
    /// * checking for any conditions indicating it might not be safe to leave
    ///   at the moment.
    ///
    /// This function should return `Ok` only if from the perspective
    /// of this module instance, it is safe to delete client data and
    /// stop using it, with no further actions (like background jobs) required
    /// to complete.
    ///
    /// This function should return an error if it's not currently possible
    /// to safely (e.g. without loosing funds) leave the Federation.
    /// It should avoid running indefinitely trying to complete any cleanup
    /// actions necessary to reach a clean state, preferring spawning new
    /// state machines and returning an informative error about cleanup
    /// still in progress.
    ///
    /// If any internal task needs to complete, any user action is required,
    /// or even external condition needs to be met this function
    /// should return a `Err`.
    ///
    /// Notably modules should not disable interaction that might be necessary
    /// for the user (possibly through other modules) to leave the Federation.
    /// In particular a Mint module should retain ability to create new notes,
    /// and LN module should retain ability to send funds out.
    ///
    /// Calling code must NOT assume that a module that once returned `Ok`,
    /// will not return `Err` at later point. E.g. a Mint module might have
    /// no outstanding balance at first, but other modules winding down
    /// might "cash-out" to Ecash.
    ///
    /// Before leaving the Federation and deleting any state the calling code
    /// must collect a full round of `Ok` from all the modules.
    ///
    /// Calling code should allow the user to override and ignore any
    /// outstanding errors, after sufficient amount of warnings. Ideally,
    /// this should be done on per-module basis, to avoid mistakes.
    async fn leave(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _module_instance_id: ModuleInstanceId,
        _executor: Executor<DynGlobalClientContext>,
        _api: DynGlobalApi,
    ) -> anyhow::Result<()> {
        bail!("Unable to determine if safe to leave the federation: Not implemented")
    }
}

/// Type-erased version of [`ClientModule`]
#[apply(async_trait_maybe_send!)]
pub trait IClientModule: Debug {
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn std::any::Any));

    fn decoder(&self) -> Decoder;

    fn context(&self, instance: ModuleInstanceId) -> DynContext;

    async fn handle_cli_command(
        &self,
        client: &Client,
        args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value>;

    fn input_amount(&self, input: &DynInput) -> TransactionItemAmount;

    fn output_amount(&self, output: &DynOutput) -> TransactionItemAmount;

    fn supports_backup(&self) -> bool;

    async fn backup(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        executor: Executor<DynGlobalClientContext>,
        api: DynGlobalApi,
        module_instance_id: ModuleInstanceId,
    ) -> anyhow::Result<Vec<u8>>;

    async fn restore(
        &self,
        // dbtx: &mut ModuleDatabaseTransaction<'_>,
        dbtx: &mut DatabaseTransaction<'_>,
        module_instance_id: ModuleInstanceId,
        executor: Executor<DynGlobalClientContext>,
        api: DynGlobalApi,
        snapshot: Option<&[u8]>,
    ) -> anyhow::Result<()>;

    async fn wipe(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        module_instance_id: ModuleInstanceId,
        executor: Executor<DynGlobalClientContext>,
    ) -> anyhow::Result<()>;

    fn supports_being_primary(&self) -> bool;

    async fn create_sufficient_input(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        min_amount: Amount,
    ) -> anyhow::Result<Vec<ClientInput>>;

    async fn create_exact_output(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        amount: Amount,
    ) -> Vec<ClientOutput>;

    async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<Amount>;

    async fn get_balance(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Amount;

    async fn subscribe_balance_changes(&self) -> BoxStream<'static, ()>;
}

#[apply(async_trait_maybe_send!)]
impl<T> IClientModule for T
where
    T: ClientModule,
{
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn Any)) {
        self
    }

    fn decoder(&self) -> Decoder {
        T::decoder()
    }

    fn context(&self, instance: ModuleInstanceId) -> DynContext {
        DynContext::from_typed(instance, <T as ClientModule>::context(self))
    }

    async fn handle_cli_command(
        &self,
        client: &Client,
        args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        <T as ClientModule>::handle_cli_command(self, client, args).await
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

    fn supports_backup(&self) -> bool {
        <T as ClientModule>::supports_backup(self)
    }

    async fn backup(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        executor: Executor<DynGlobalClientContext>,
        api: DynGlobalApi,
        module_instance_id: ModuleInstanceId,
    ) -> anyhow::Result<Vec<u8>> {
        <T as ClientModule>::backup(self, dbtx, executor, api, module_instance_id).await
    }

    async fn restore(
        &self,
        // dbtx: &mut ModuleDatabaseTransaction<'_>,
        dbtx: &mut DatabaseTransaction<'_>,
        module_instance_id: ModuleInstanceId,
        executor: Executor<DynGlobalClientContext>,
        api: DynGlobalApi,
        snapshot: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        <T as ClientModule>::restore(self, dbtx, module_instance_id, executor, api, snapshot).await
    }

    async fn wipe(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        module_instance_id: ModuleInstanceId,
        executor: Executor<DynGlobalClientContext>,
    ) -> anyhow::Result<()> {
        <T as ClientModule>::wipe(self, dbtx, module_instance_id, executor).await
    }

    fn supports_being_primary(&self) -> bool {
        <T as ClientModule>::supports_being_primary(self)
    }

    async fn create_sufficient_input(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        min_amount: Amount,
    ) -> anyhow::Result<Vec<ClientInput>> {
        Ok(<T as ClientModule>::create_sufficient_input(
            self,
            &mut dbtx.with_module_prefix(module_instance),
            operation_id,
            min_amount,
        )
        .await?
        .into_iter()
        .map(|input| input.into_dyn(module_instance))
        .collect())
    }

    async fn create_exact_output(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        amount: Amount,
    ) -> Vec<ClientOutput> {
        <T as ClientModule>::create_exact_output(
            self,
            &mut dbtx.with_module_prefix(module_instance),
            operation_id,
            amount,
        )
        .await
        .into_iter()
        .map(|output| output.into_dyn(module_instance))
        .collect()
    }

    async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<Amount> {
        <T as ClientModule>::await_primary_module_output(self, operation_id, out_point).await
    }

    async fn get_balance(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Amount {
        <T as ClientModule>::get_balance(self, &mut dbtx.with_module_prefix(module_instance)).await
    }

    async fn subscribe_balance_changes(&self) -> BoxStream<'static, ()> {
        <T as ClientModule>::subscribe_balance_changes(self).await
    }
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub DynClientModule(Arc<IClientModule>)
);

impl AsRef<maybe_add_send_sync!(dyn IClientModule + 'static)> for DynClientModule {
    fn as_ref(&self) -> &maybe_add_send_sync!(dyn IClientModule + 'static) {
        self.inner.as_ref()
    }
}

pub type StateGenerator<S> =
    Arc<maybe_add_send_sync!(dyn Fn(TransactionId, u64) -> Vec<S> + 'static)>;
