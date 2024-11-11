use core::fmt;
use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;
use std::{ffi, marker, ops};

use anyhow::{anyhow, bail};
use bitcoin::secp256k1::PublicKey;
use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{
    Decoder, DynInput, DynOutput, IInput, IntoDynInstance, ModuleInstanceId, ModuleKind,
    OperationId,
};
use fedimint_core::db::{Database, DatabaseTransaction, GlobalDBTxAccessToken};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleInit};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::BoxStream;
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, maybe_add_send_sync, Amount, OutPoint,
    TransactionId,
};
use futures::Stream;
use serde::de::DeserializeOwned;
use serde::Serialize;

use self::init::ClientModuleInit;
use crate::db::event_log::Event;
use crate::module::recovery::{DynModuleBackup, ModuleBackup};
use crate::oplog::{OperationLogEntry, UpdateStreamOrOutcome};
use crate::sm::{self, ActiveStateMeta, Context, DynContext, DynState, State};
use crate::transaction::{ClientInputBundle, ClientOutputBundle, TransactionBuilder};
use crate::{
    oplog, AddStateMachinesResult, Client, ClientStrong, ClientWeak,
    InstancelessDynClientInputBundle, TransactionUpdates,
};

pub mod init;
pub mod recovery;

pub type ClientModuleRegistry = ModuleRegistry<DynClientModule>;

/// A final, fully initialized [`crate::Client`]
///
/// Client modules need to be able to access a `Client` they are a part
/// of. To break the circular dependency, the final `Client` is passed
/// after `Client` was built via a shared state.
#[derive(Clone, Default)]
pub struct FinalClient(Arc<std::sync::OnceLock<ClientWeak>>);

impl FinalClient {
    /// Get a temporary [`ClientStrong`]
    ///
    /// Care must be taken to not let the user take ownership of this value,
    /// and not store it elsewhere permanently either, as it could prevent
    /// the cleanup of the Client.
    pub(crate) fn get(&self) -> ClientStrong {
        self.0
            .get()
            .expect("client must be already set")
            .upgrade()
            .expect("client module context must not be use past client shutdown")
    }

    pub(crate) fn set(&self, client: ClientWeak) {
        self.0.set(client).expect("FinalLazyClient already set");
    }
}

/// A Client context for a [`ClientModule`] `M`
///
/// Client modules can interact with the whole
/// client through this struct.
pub struct ClientContext<M> {
    client: FinalClient,
    module_instance_id: ModuleInstanceId,
    global_dbtx_access_token: GlobalDBTxAccessToken,
    module_db: Database,
    _marker: marker::PhantomData<M>,
}

impl<M> Clone for ClientContext<M> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            module_db: self.module_db.clone(),
            module_instance_id: self.module_instance_id,
            _marker: marker::PhantomData,
            global_dbtx_access_token: self.global_dbtx_access_token,
        }
    }
}

/// A reference back to itself that the module cacn get from the
/// [`ClientContext`]
pub struct ClientContextSelfRef<'s, M> {
    // we are OK storing `ClientStrong` here, because of the `'s` preventing `Self` from being
    // stored permanently somewhere
    client: ClientStrong,
    module_instance_id: ModuleInstanceId,
    _marker: marker::PhantomData<&'s M>,
}

impl<M> ops::Deref for ClientContextSelfRef<'_, M>
where
    M: ClientModule,
{
    type Target = M;

    fn deref(&self) -> &Self::Target {
        self.client
            .get_module(self.module_instance_id)
            .as_any()
            .downcast_ref::<M>()
            .unwrap_or_else(|| panic!("Module is not of type {}", std::any::type_name::<M>()))
    }
}

impl<M> fmt::Debug for ClientContext<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientContext")
    }
}

impl<M> ClientContext<M>
where
    M: ClientModule,
{
    /// Get a reference back to client module from the [`Self`]
    ///
    /// It's often necessary for a client module to "move self"
    /// by-value, especially due to async lifetimes issues.
    /// Clients usually work with `&mut self`, which can't really
    /// work in such context.
    ///
    /// Fortunately [`ClientContext`] is `Clone` and `Send, and
    /// can be used to recover the reference to the module at later
    /// time.
    #[allow(clippy::needless_lifetimes)] // just for explicitiness
    pub fn self_ref<'s>(&'s self) -> ClientContextSelfRef<'s, M> {
        ClientContextSelfRef {
            client: self.client.get(),
            module_instance_id: self.module_instance_id,
            _marker: marker::PhantomData,
        }
    }

    /// Get a reference to a global Api handle
    pub fn global_api(&self) -> DynGlobalApi {
        self.client.get().api_clone()
    }
    pub fn decoders(&self) -> ModuleDecoderRegistry {
        self.client.get().decoders().clone()
    }

    pub fn input_from_dyn<'i>(
        &self,
        input: &'i DynInput,
    ) -> Option<&'i <M::Common as ModuleCommon>::Input> {
        (input.module_instance_id() == self.module_instance_id).then(|| {
            input
                .as_any()
                .downcast_ref::<<M::Common as ModuleCommon>::Input>()
                .expect("instance_id just checked")
        })
    }

    pub fn output_from_dyn<'o>(
        &self,
        output: &'o DynOutput,
    ) -> Option<&'o <M::Common as ModuleCommon>::Output> {
        (output.module_instance_id() == self.module_instance_id).then(|| {
            output
                .as_any()
                .downcast_ref::<<M::Common as ModuleCommon>::Output>()
                .expect("instance_id just checked")
        })
    }

    pub fn map_dyn<'s, 'i, 'o, I>(
        &'s self,
        typed: impl IntoIterator<Item = I> + 'i,
    ) -> impl Iterator<Item = <I as IntoDynInstance>::DynType> + 'o
    where
        I: IntoDynInstance,
        'i: 'o,
        's: 'o,
    {
        typed.into_iter().map(|i| self.make_dyn(i))
    }

    /// Turn a typed output into a dyn version
    pub fn make_dyn_output(&self, output: <M::Common as ModuleCommon>::Output) -> DynOutput {
        self.make_dyn(output)
    }

    /// Turn a typed input into a dyn version
    pub fn make_dyn_input(&self, input: <M::Common as ModuleCommon>::Input) -> DynInput {
        self.make_dyn(input)
    }

    /// Turn a `typed` into a dyn version
    pub fn make_dyn<I>(&self, typed: I) -> <I as IntoDynInstance>::DynType
    where
        I: IntoDynInstance,
    {
        typed.into_dyn(self.module_instance_id)
    }

    /// Turn a typed [`ClientOutputBundle`] into a dyn version
    pub fn make_client_outputs<O, S>(&self, output: ClientOutputBundle<O, S>) -> ClientOutputBundle
    where
        O: IntoDynInstance<DynType = DynOutput> + 'static,
        S: IntoDynInstance<DynType = DynState> + 'static,
    {
        self.make_dyn(output)
    }

    /// Turn a typed [`ClientInputBundle`] into a dyn version
    pub fn make_client_inputs<I, S>(&self, inputs: ClientInputBundle<I, S>) -> ClientInputBundle
    where
        I: IntoDynInstance<DynType = DynInput> + 'static,
        S: IntoDynInstance<DynType = DynState> + 'static,
    {
        self.make_dyn(inputs)
    }

    pub fn make_dyn_state<S>(&self, sm: S) -> DynState
    where
        S: sm::IState + 'static,
    {
        DynState::from_typed(self.module_instance_id, sm)
    }

    /// See [`crate::Client::finalize_and_submit_transaction`]
    pub async fn finalize_and_submit_transaction<F, Meta>(
        &self,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta: F,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)>
    where
        F: Fn(TransactionId, Vec<OutPoint>) -> Meta + Clone + MaybeSend + MaybeSync,
        Meta: serde::Serialize + MaybeSend,
    {
        self.client
            .get()
            .finalize_and_submit_transaction(
                operation_id,
                operation_type,
                operation_meta,
                tx_builder,
            )
            .await
    }

    /// See [`crate::Client::transaction_updates`]
    pub async fn transaction_updates(&self, operation_id: OperationId) -> TransactionUpdates {
        self.client.get().transaction_updates(operation_id).await
    }

    /// See [`crate::Client::await_primary_module_outputs`]
    pub async fn await_primary_module_outputs(
        &self,
        operation_id: OperationId,
        outputs: Vec<OutPoint>,
    ) -> anyhow::Result<Amount> {
        self.client
            .get()
            .await_primary_module_outputs(operation_id, outputs)
            .await
    }

    // TODO: unify with `Self::get_operation`
    pub async fn get_operation(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<oplog::OperationLogEntry> {
        let operation = self
            .client
            .get()
            .operation_log()
            .get_operation(operation_id)
            .await
            .ok_or(anyhow::anyhow!("Operation not found"))?;

        if operation.operation_module_kind() != M::kind().as_str() {
            bail!("Operation is not a lightning operation");
        }

        Ok(operation)
    }

    /// Get global db.
    ///
    /// Only intended for internal use (private).
    fn global_db(&self) -> fedimint_core::db::Database {
        let db = self.client.get().db().clone();

        db.ensure_global()
            .expect("global_db must always return a global db");

        db
    }

    pub fn module_db(&self) -> &Database {
        self.module_db
            .ensure_isolated()
            .expect("module_db must always return isolated db");
        &self.module_db
    }

    pub async fn has_active_states(&self, op_id: OperationId) -> bool {
        self.client.get().has_active_states(op_id).await
    }

    pub async fn operation_exists(&self, op_id: OperationId) -> bool {
        self.client.get().operation_exists(op_id).await
    }

    pub async fn get_own_active_states(&self) -> Vec<(M::States, ActiveStateMeta)> {
        self.client
            .get()
            .executor
            .get_active_states()
            .await
            .into_iter()
            .filter(|s| s.0.module_instance_id() == self.module_instance_id)
            .map(|s| {
                (
                    s.0.as_any()
                        .downcast_ref::<M::States>()
                        .expect("incorrect output type passed to module plugin")
                        .clone(),
                    s.1,
                )
            })
            .collect()
    }

    pub async fn get_config(&self) -> ClientConfig {
        self.client.get().config().await
    }

    /// Returns an invite code for the federation that points to an arbitrary
    /// guardian server for fetching the config
    pub async fn get_invite_code(&self) -> InviteCode {
        let cfg = self.get_config().await.global;
        self.client
            .get()
            .invite_code(
                *cfg.api_endpoints
                    .keys()
                    .next()
                    .expect("A federation always has at least one guardian"),
            )
            .await
            .expect("The guardian we requested an invite code for exists")
    }

    pub fn get_internal_payment_markers(&self) -> anyhow::Result<(PublicKey, u64)> {
        self.client.get().get_internal_payment_markers()
    }

    /// This method starts n state machines with given operation id without a
    /// corresponding transaction
    pub async fn manual_operation_start(
        &self,
        operation_id: OperationId,
        op_type: &str,
        operation_meta: impl serde::Serialize + Debug,
        sms: Vec<DynState>,
    ) -> anyhow::Result<()> {
        let db = self.module_db();
        let mut dbtx = db.begin_transaction().await;
        {
            let dbtx = &mut dbtx.global_dbtx(self.global_dbtx_access_token);

            self.manual_operation_start_inner(
                &mut dbtx.to_ref_nc(),
                operation_id,
                op_type,
                operation_meta,
                sms,
            )
            .await?;
        }

        dbtx.commit_tx_result().await.map_err(|_| {
            anyhow!(
                "Operation with id {} already exists",
                operation_id.fmt_short()
            )
        })?;

        Ok(())
    }

    pub async fn manual_operation_start_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        op_type: &str,
        operation_meta: impl serde::Serialize + Debug,
        sms: Vec<DynState>,
    ) -> anyhow::Result<()> {
        self.manual_operation_start_inner(
            &mut dbtx.global_dbtx(self.global_dbtx_access_token),
            operation_id,
            op_type,
            operation_meta,
            sms,
        )
        .await
    }

    /// See [`Self::manual_operation_start`], just inside a database
    /// transaction.
    async fn manual_operation_start_inner(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        op_type: &str,
        operation_meta: impl serde::Serialize + Debug,
        sms: Vec<DynState>,
    ) -> anyhow::Result<()> {
        dbtx.ensure_global()
            .expect("Must deal with global dbtx here");

        if Client::operation_exists_dbtx(&mut dbtx.to_ref_nc(), operation_id).await {
            bail!(
                "Operation with id {} already exists",
                operation_id.fmt_short()
            );
        }

        self.client
            .get()
            .operation_log
            .add_operation_log_entry(&mut dbtx.to_ref_nc(), operation_id, op_type, operation_meta)
            .await;

        self.client
            .get()
            .executor
            .add_state_machines_dbtx(&mut dbtx.to_ref_nc(), sms)
            .await
            .expect("State machine is valid");

        Ok(())
    }

    pub fn outcome_or_updates<U, S>(
        &self,
        operation: &OperationLogEntry,
        operation_id: OperationId,
        stream_gen: impl FnOnce() -> S,
    ) -> UpdateStreamOrOutcome<U>
    where
        U: Clone + Serialize + DeserializeOwned + Debug + MaybeSend + MaybeSync + 'static,
        S: Stream<Item = U> + MaybeSend + 'static,
    {
        operation.outcome_or_updates(&self.global_db(), operation_id, stream_gen)
    }

    pub async fn claim_inputs<I, S>(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        inputs: ClientInputBundle<I, S>,
        operation_id: OperationId,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)>
    where
        I: IInput + MaybeSend + MaybeSync + 'static,
        S: sm::IState + MaybeSend + MaybeSync + 'static,
    {
        self.claim_inputs_dyn(dbtx, inputs.into_instanceless(), operation_id)
            .await
    }

    async fn claim_inputs_dyn(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        inputs: InstancelessDynClientInputBundle,
        operation_id: OperationId,
    ) -> anyhow::Result<(TransactionId, Vec<OutPoint>)> {
        let tx_builder =
            TransactionBuilder::new().with_inputs(inputs.into_dyn(self.module_instance_id));

        self.client
            .get()
            .finalize_and_submit_transaction_inner(
                &mut dbtx.global_dbtx(self.global_dbtx_access_token),
                operation_id,
                tx_builder,
            )
            .await
    }

    pub async fn add_state_machines_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        states: Vec<DynState>,
    ) -> AddStateMachinesResult {
        self.client
            .get()
            .executor
            .add_state_machines_dbtx(&mut dbtx.global_dbtx(self.global_dbtx_access_token), states)
            .await
    }

    pub async fn add_operation_log_entry_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta: impl serde::Serialize,
    ) {
        self.client
            .get()
            .operation_log()
            .add_operation_log_entry(
                &mut dbtx.global_dbtx(self.global_dbtx_access_token),
                operation_id,
                operation_type,
                operation_meta,
            )
            .await;
    }

    pub async fn log_event<E, Cap>(&self, dbtx: &mut DatabaseTransaction<'_, Cap>, event: E)
    where
        E: Event + Send,
        Cap: Send,
    {
        self.client
            .get()
            .log_event_dbtx(
                &mut dbtx.global_dbtx(self.global_dbtx_access_token),
                Some(self.module_instance_id),
                event,
            )
            .await;
    }
}

/// Fedimint module client
#[apply(async_trait_maybe_send!)]
pub trait ClientModule: Debug + MaybeSend + MaybeSync + 'static {
    type Init: ClientModuleInit;

    /// Common module types shared between client and server
    type Common: ModuleCommon;

    /// Data stored in regular backups so that restoring doesn't have to start
    /// from epoch 0
    type Backup: ModuleBackup;

    /// Data and API clients available to state machine transitions of this
    /// module
    type ModuleStateMachineContext: Context;

    /// All possible states this client can submit to the executor
    type States: State<ModuleContext = Self::ModuleStateMachineContext>
        + IntoDynInstance<DynType = DynState>;

    fn decoder() -> Decoder {
        let mut decoder_builder = Self::Common::decoder_builder();
        decoder_builder.with_decodable_type::<Self::States>();
        decoder_builder.with_decodable_type::<Self::Backup>();
        decoder_builder.build()
    }

    fn kind() -> ModuleKind {
        <<<Self as ClientModule>::Init as ModuleInit>::Common as CommonModuleInit>::KIND
    }

    fn context(&self) -> Self::ModuleStateMachineContext;

    /// Initialize client.
    ///
    /// Called by the core client code on start, after [`ClientContext`] is
    /// fully initialized, so unlike during [`ClientModuleInit::init`],
    /// access to global client is allowed.
    async fn start(&self) {}

    async fn handle_cli_command(
        &self,
        _args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        Err(anyhow::format_err!(
            "This module does not implement cli commands"
        ))
    }

    async fn handle_rpc(
        &self,
        _method: String,
        _request: serde_json::Value,
    ) -> BoxStream<'_, anyhow::Result<serde_json::Value>> {
        Box::pin(futures::stream::once(std::future::ready(Err(
            anyhow::format_err!("This module does not implement rpc"),
        ))))
    }

    /// Returns the fee the processing of this input requires.
    ///
    /// If the semantics of a given input aren't known this function returns
    /// `None`, this only happens if a future version of Fedimint introduces a
    /// new input variant. For clients this should only be the case when
    /// processing transactions created by other users, so the result of
    /// this function can be `unwrap`ped whenever dealing with inputs
    /// generated by ourselves.
    fn input_fee(
        &self,
        amount: Amount,
        input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amount>;

    /// Returns the fee the processing of this output requires.
    ///
    /// If the semantics of a given output aren't known this function returns
    /// `None`, this only happens if a future version of Fedimint introduces a
    /// new output variant. For clients this should only be the case when
    /// processing transactions created by other users, so the result of
    /// this function can be `unwrap`ped whenever dealing with inputs
    /// generated by ourselves.
    fn output_fee(
        &self,
        amount: Amount,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amount>;

    fn supports_backup(&self) -> bool {
        false
    }

    async fn backup(&self) -> anyhow::Result<Self::Backup> {
        anyhow::bail!("Backup not supported");
    }

    /// Does this module support being a primary module
    ///
    /// If it does it must implement:
    ///
    /// * [`Self::create_final_inputs_and_outputs`]
    /// * [`Self::await_primary_module_output`]
    /// * [`Self::get_balance`]
    /// * [`Self::subscribe_balance_changes`]
    fn supports_being_primary(&self) -> bool {
        false
    }

    /// Creates all inputs and outputs necessary to balance the transaction.
    /// The function returns an error if and only if the client's funds are not
    /// sufficient to create the inputs necessary to fully fund the transaction.
    ///
    /// A returned input also contains:
    /// * A set of private keys belonging to the input for signing the
    ///   transaction
    /// * A closure that generates states belonging to the input. This closure
    ///   takes the transaction id of the transaction in which the input was
    ///   used and the input index as input since these cannot be known at time
    ///   of calling `create_funding_input` and have to be injected later.
    ///
    /// A returned output also contains:
    /// * A closure that generates states belonging to the output. This closure
    ///   takes the transaction id of the transaction in which the output was
    ///   used and the output index as input since these cannot be known at time
    ///   of calling `create_change_output` and have to be injected later.

    async fn create_final_inputs_and_outputs(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _operation_id: OperationId,
        _input_amount: Amount,
        _output_amount: Amount,
    ) -> anyhow::Result<(
        ClientInputBundle<<Self::Common as ModuleCommon>::Input, Self::States>,
        ClientOutputBundle<<Self::Common as ModuleCommon>::Output, Self::States>,
    )> {
        unimplemented!()
    }

    /// Waits for the funds from an output created by
    /// [`Self::create_final_inputs_and_outputs`] to become available. This
    /// function returning typically implies a change in the output of
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
    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>) -> Amount {
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
    async fn leave(&self, _dbtx: &mut DatabaseTransaction<'_>) -> anyhow::Result<()> {
        bail!("Unable to determine if safe to leave the federation: Not implemented")
    }
}

/// Type-erased version of [`ClientModule`]
#[apply(async_trait_maybe_send!)]
pub trait IClientModule: Debug {
    fn as_any(&self) -> &(maybe_add_send_sync!(dyn std::any::Any));

    fn decoder(&self) -> Decoder;

    fn context(&self, instance: ModuleInstanceId) -> DynContext;

    async fn start(&self);

    async fn handle_cli_command(&self, args: &[ffi::OsString])
        -> anyhow::Result<serde_json::Value>;

    async fn handle_rpc(
        &self,
        method: String,
        request: serde_json::Value,
    ) -> BoxStream<'_, anyhow::Result<serde_json::Value>>;

    fn input_fee(&self, amount: Amount, input: &DynInput) -> Option<Amount>;

    fn output_fee(&self, amount: Amount, output: &DynOutput) -> Option<Amount>;

    fn supports_backup(&self) -> bool;

    async fn backup(&self, module_instance_id: ModuleInstanceId)
        -> anyhow::Result<DynModuleBackup>;

    fn supports_being_primary(&self) -> bool;

    async fn create_final_inputs_and_outputs(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        input_amount: Amount,
        output_amount: Amount,
    ) -> anyhow::Result<(ClientInputBundle, ClientOutputBundle)>;

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

    async fn start(&self) {
        <T as ClientModule>::start(self).await;
    }

    async fn handle_cli_command(
        &self,
        args: &[ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        <T as ClientModule>::handle_cli_command(self, args).await
    }

    async fn handle_rpc(
        &self,
        method: String,
        request: serde_json::Value,
    ) -> BoxStream<'_, anyhow::Result<serde_json::Value>> {
        <T as ClientModule>::handle_rpc(self, method, request).await
    }

    fn input_fee(&self, amount: Amount, input: &DynInput) -> Option<Amount> {
        <T as ClientModule>::input_fee(
            self,
            amount,
            input
                .as_any()
                .downcast_ref()
                .expect("Dispatched to correct module"),
        )
    }

    fn output_fee(&self, amount: Amount, output: &DynOutput) -> Option<Amount> {
        <T as ClientModule>::output_fee(
            self,
            amount,
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
        module_instance_id: ModuleInstanceId,
    ) -> anyhow::Result<DynModuleBackup> {
        Ok(DynModuleBackup::from_typed(
            module_instance_id,
            <T as ClientModule>::backup(self).await?,
        ))
    }

    fn supports_being_primary(&self) -> bool {
        <T as ClientModule>::supports_being_primary(self)
    }

    async fn create_final_inputs_and_outputs(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        input_amount: Amount,
        output_amount: Amount,
    ) -> anyhow::Result<(ClientInputBundle, ClientOutputBundle)> {
        let (inputs, outputs) = <T as ClientModule>::create_final_inputs_and_outputs(
            self,
            &mut dbtx.to_ref_with_prefix_module_id(module_instance).0,
            operation_id,
            input_amount,
            output_amount,
        )
        .await?;

        let inputs = inputs.into_dyn(module_instance);

        let outputs = outputs.into_dyn(module_instance);

        Ok((inputs, outputs))
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
        <T as ClientModule>::get_balance(
            self,
            &mut dbtx.to_ref_with_prefix_module_id(module_instance).0,
        )
        .await
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

/// A contiguous range of input/output indexes
#[derive(Copy, Clone, Encodable, Decodable, PartialEq, Eq, Hash, Debug)]
pub struct IdxRange {
    start: u64,
    end_inclusive: u64,
}

impl IdxRange {
    pub fn new_single(start: u64) -> Self {
        Self {
            start,
            end_inclusive: start,
        }
    }

    pub fn start(self) -> u64 {
        self.start
    }

    pub fn count(self) -> usize {
        self.into_iter().count()
    }
}

impl IntoIterator for IdxRange {
    type Item = u64;

    type IntoIter = ops::RangeInclusive<u64>;

    fn into_iter(self) -> Self::IntoIter {
        ops::RangeInclusive::new(self.start, self.end_inclusive)
    }
}

impl From<ops::RangeInclusive<u64>> for IdxRange {
    fn from(value: ops::RangeInclusive<u64>) -> Self {
        Self {
            start: *value.start(),
            end_inclusive: *value.end(),
        }
    }
}

#[derive(Copy, Clone, Encodable, Decodable, PartialEq, Eq, Hash, Debug)]
pub struct OutPointRange {
    txid: TransactionId,
    idx_range: IdxRange,
}

impl OutPointRange {
    pub fn new(txid: TransactionId, idx_range: IdxRange) -> Self {
        Self { txid, idx_range }
    }

    pub fn new_single(txid: TransactionId, idx: u64) -> Self {
        Self {
            txid,
            idx_range: IdxRange::new_single(idx),
        }
    }

    pub fn start_idx(self) -> u64 {
        self.idx_range.start()
    }

    pub fn out_idx_iter(self) -> impl Iterator<Item = u64> {
        self.idx_range.into_iter()
    }

    pub fn count(self) -> usize {
        self.idx_range.count()
    }
}

impl IntoIterator for OutPointRange {
    type Item = OutPoint;

    type IntoIter = OutPointRangeIter;

    fn into_iter(self) -> Self::IntoIter {
        OutPointRangeIter {
            txid: self.txid,
            inner: self.idx_range.into_iter(),
        }
    }
}

pub struct OutPointRangeIter {
    txid: TransactionId,

    inner: ops::RangeInclusive<u64>,
}

impl OutPointRange {
    pub fn txid(&self) -> TransactionId {
        self.txid
    }
}

impl Iterator for OutPointRangeIter {
    type Item = OutPoint;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|idx| OutPoint {
            txid: self.txid,
            out_idx: idx,
        })
    }
}

pub type StateGenerator<S> = Arc<maybe_add_send_sync!(dyn Fn(OutPointRange) -> Vec<S> + 'static)>;
