use core::fmt;
use std::any::Any;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::{ffi, marker, ops};

use anyhow::{anyhow, bail};
use bitcoin::secp256k1::PublicKey;
use fedimint_api_client::api::{DynGlobalApi, DynModuleApi};
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{
    Decoder, DynInput, DynOutput, IInput, IntoDynInstance, ModuleInstanceId, ModuleKind,
    OperationId,
};
use fedimint_core::db::{Database, DatabaseTransaction, GlobalDBTxAccessToken, NonCommittable};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::module::{AmountUnit, Amounts, CommonModuleInit, ModuleCommon, ModuleInit};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::BoxStream;
use fedimint_core::{
    Amount, OutPoint, PeerId, apply, async_trait_maybe_send, dyn_newtype_define, maybe_add_send,
    maybe_add_send_sync,
};
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use fedimint_logging::LOG_CLIENT;
use futures::Stream;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::warn;

use self::init::ClientModuleInit;
use crate::module::recovery::{DynModuleBackup, ModuleBackup};
use crate::oplog::{IOperationLog, OperationLogEntry, UpdateStreamOrOutcome};
use crate::sm::executor::{ActiveStateKey, IExecutor, InactiveStateKey};
use crate::sm::{self, ActiveStateMeta, Context, DynContext, DynState, InactiveStateMeta, State};
use crate::transaction::{ClientInputBundle, ClientOutputBundle, TransactionBuilder};
use crate::{AddStateMachinesResult, InstancelessDynClientInputBundle, TransactionUpdates, oplog};

pub mod init;
pub mod recovery;

pub type ClientModuleRegistry = ModuleRegistry<DynClientModule>;

/// A fedimint-client interface exposed to client modules
///
/// To break the dependency of the client modules on the whole fedimint client
/// and in particular the `fedimint-client` crate, the module gets access to an
/// interface, that is implemented by the `Client`.
///
/// This allows lose coupling, less recompilation and better control and
/// understanding of what functionality of the Client the modules get access to.
#[apply(async_trait_maybe_send!)]
pub trait ClientContextIface: MaybeSend + MaybeSync {
    fn get_module(&self, instance: ModuleInstanceId) -> &maybe_add_send_sync!(dyn IClientModule);
    fn api_clone(&self) -> DynGlobalApi;
    fn decoders(&self) -> &ModuleDecoderRegistry;
    async fn finalize_and_submit_transaction(
        &self,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta_gen: Box<maybe_add_send_sync!(dyn Fn(OutPointRange) -> serde_json::Value)>,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<OutPointRange>;

    // TODO: unify
    async fn finalize_and_submit_transaction_inner(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<OutPointRange>;

    async fn transaction_updates(&self, operation_id: OperationId) -> TransactionUpdates;

    async fn await_primary_module_outputs(
        &self,
        operation_id: OperationId,
        // TODO: make `impl Iterator<Item = ...>`
        outputs: Vec<OutPoint>,
    ) -> anyhow::Result<()>;

    fn operation_log(&self) -> &dyn IOperationLog;

    async fn has_active_states(&self, operation_id: OperationId) -> bool;

    async fn operation_exists(&self, operation_id: OperationId) -> bool;

    async fn config(&self) -> ClientConfig;

    fn db(&self) -> &Database;

    fn executor(&self) -> &(maybe_add_send_sync!(dyn IExecutor + 'static));

    async fn invite_code(&self, peer: PeerId) -> Option<InviteCode>;

    fn get_internal_payment_markers(&self) -> anyhow::Result<(PublicKey, u64)>;

    #[allow(clippy::too_many_arguments)]
    async fn log_event_json(
        &self,
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
        module_kind: Option<ModuleKind>,
        module_id: ModuleInstanceId,
        kind: EventKind,
        payload: serde_json::Value,
        persist: EventPersistence,
    );

    async fn read_operation_active_states<'dbtx>(
        &self,
        operation_id: OperationId,
        module_id: ModuleInstanceId,
        dbtx: &'dbtx mut DatabaseTransaction<'_>,
    ) -> Pin<Box<maybe_add_send!(dyn Stream<Item = (ActiveStateKey, ActiveStateMeta)> + 'dbtx)>>;

    async fn read_operation_inactive_states<'dbtx>(
        &self,
        operation_id: OperationId,
        module_id: ModuleInstanceId,
        dbtx: &'dbtx mut DatabaseTransaction<'_>,
    ) -> Pin<Box<maybe_add_send!(dyn Stream<Item = (InactiveStateKey, InactiveStateMeta)> + 'dbtx)>>;
}

/// A final, fully initialized client
///
/// Client modules need to be able to access a `Client` they are a part
/// of. To break the circular dependency, the final `Client` is passed
/// after `Client` was built via a shared state.
#[derive(Clone, Default)]
pub struct FinalClientIface(Arc<std::sync::OnceLock<Weak<dyn ClientContextIface>>>);

impl FinalClientIface {
    /// Get a temporary strong reference to [`ClientContextIface`]
    ///
    /// Care must be taken to not let the user take ownership of this value,
    /// and not store it elsewhere permanently either, as it could prevent
    /// the cleanup of the Client.
    pub(crate) fn get(&self) -> Arc<dyn ClientContextIface> {
        self.0
            .get()
            .expect("client must be already set")
            .upgrade()
            .expect("client module context must not be use past client shutdown")
    }

    pub fn set(&self, client: Weak<dyn ClientContextIface>) {
        self.0.set(client).expect("FinalLazyClient already set");
    }
}

impl fmt::Debug for FinalClientIface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FinalClientIface")
    }
}
/// A Client context for a [`ClientModule`] `M`
///
/// Client modules can interact with the whole
/// client through this struct.
pub struct ClientContext<M> {
    client: FinalClientIface,
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
    client: Arc<dyn ClientContextIface>,
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
    pub fn new(
        client: FinalClientIface,
        module_instance_id: ModuleInstanceId,
        global_dbtx_access_token: GlobalDBTxAccessToken,
        module_db: Database,
    ) -> Self {
        Self {
            client,
            module_instance_id,
            global_dbtx_access_token,
            module_db,
            _marker: marker::PhantomData,
        }
    }

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
    pub fn self_ref(&self) -> ClientContextSelfRef<'_, M> {
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

    /// Get a reference to a module Api handle
    pub fn module_api(&self) -> DynModuleApi {
        self.global_api().with_module(self.module_instance_id)
    }

    /// A set of all decoders of all modules of the client
    pub fn decoders(&self) -> ModuleDecoderRegistry {
        Clone::clone(self.client.get().decoders())
    }

    pub fn input_from_dyn<'i>(
        &self,
        input: &'i DynInput,
    ) -> Option<&'i <M::Common as ModuleCommon>::Input> {
        (input.module_instance_id() == self.module_instance_id).then(|| {
            input
                .as_any()
                .downcast_ref::<<M::Common as ModuleCommon>::Input>()
                .unwrap_or_else(|| {
                    panic!("instance_id {} just checked", input.module_instance_id())
                })
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
                .unwrap_or_else(|| {
                    panic!("instance_id {} just checked", output.module_instance_id())
                })
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

    pub async fn finalize_and_submit_transaction<F, Meta>(
        &self,
        operation_id: OperationId,
        operation_type: &str,
        operation_meta_gen: F,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<OutPointRange>
    where
        F: Fn(OutPointRange) -> Meta + Clone + MaybeSend + MaybeSync + 'static,
        Meta: serde::Serialize + MaybeSend,
    {
        self.client
            .get()
            .finalize_and_submit_transaction(
                operation_id,
                operation_type,
                Box::new(move |out_point_range| {
                    serde_json::to_value(operation_meta_gen(out_point_range)).expect("Can't fail")
                }),
                tx_builder,
            )
            .await
    }

    pub async fn transaction_updates(&self, operation_id: OperationId) -> TransactionUpdates {
        self.client.get().transaction_updates(operation_id).await
    }

    pub async fn await_primary_module_outputs(
        &self,
        operation_id: OperationId,
        // TODO: make `impl Iterator<Item = ...>`
        outputs: Vec<OutPoint>,
    ) -> anyhow::Result<()> {
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
        let db = Clone::clone(self.client.get().db());

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
            .executor()
            .get_active_states()
            .await
            .into_iter()
            .filter(|s| s.0.module_instance_id() == self.module_instance_id)
            .map(|s| {
                (
                    Clone::clone(
                        s.0.as_any()
                            .downcast_ref::<M::States>()
                            .expect("incorrect output type passed to module plugin"),
                    ),
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

        if self
            .client
            .get()
            .operation_log()
            .get_operation_dbtx(&mut dbtx.to_ref_nc(), operation_id)
            .await
            .is_some()
        {
            bail!(
                "Operation with id {} already exists",
                operation_id.fmt_short()
            );
        }

        self.client
            .get()
            .operation_log()
            .add_operation_log_entry_dbtx(
                &mut dbtx.to_ref_nc(),
                operation_id,
                op_type,
                serde_json::to_value(operation_meta).expect("Can't fail"),
            )
            .await;

        self.client
            .get()
            .executor()
            .add_state_machines_dbtx(&mut dbtx.to_ref_nc(), sms)
            .await
            .expect("State machine is valid");

        Ok(())
    }

    pub fn outcome_or_updates<U, S>(
        &self,
        operation: OperationLogEntry,
        operation_id: OperationId,
        stream_gen: impl FnOnce() -> S + 'static,
    ) -> UpdateStreamOrOutcome<U>
    where
        U: Clone + Serialize + DeserializeOwned + Debug + MaybeSend + MaybeSync + 'static,
        S: Stream<Item = U> + MaybeSend + 'static,
    {
        use futures::StreamExt;
        match self.client.get().operation_log().outcome_or_updates(
            &self.global_db(),
            operation_id,
            operation,
            Box::new(move || {
                let stream_gen = stream_gen();
                Box::pin(
                    stream_gen.map(move |item| serde_json::to_value(item).expect("Can't fail")),
                )
            }),
        ) {
            UpdateStreamOrOutcome::UpdateStream(stream) => UpdateStreamOrOutcome::UpdateStream(
                Box::pin(stream.map(|u| serde_json::from_value(u).expect("Can't fail"))),
            ),
            UpdateStreamOrOutcome::Outcome(o) => {
                UpdateStreamOrOutcome::Outcome(serde_json::from_value(o).expect("Can't fail"))
            }
        }
    }

    pub async fn claim_inputs<I, S>(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        inputs: ClientInputBundle<I, S>,
        operation_id: OperationId,
    ) -> anyhow::Result<OutPointRange>
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
    ) -> anyhow::Result<OutPointRange> {
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
            .executor()
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
            .add_operation_log_entry_dbtx(
                &mut dbtx.global_dbtx(self.global_dbtx_access_token),
                operation_id,
                operation_type,
                serde_json::to_value(operation_meta).expect("Can't fail"),
            )
            .await;
    }

    pub async fn log_event<E, Cap>(&self, dbtx: &mut DatabaseTransaction<'_, Cap>, event: E)
    where
        E: Event + Send,
        Cap: Send,
    {
        if <E as Event>::MODULE != Some(<M as ClientModule>::kind()) {
            warn!(
                target: LOG_CLIENT,
                module_kind = %<M as ClientModule>::kind(),
                event_module = ?<E as Event>::MODULE,
                "Client module logging events of different module than its own. This might become an error in the future."
            );
        }
        self.client
            .get()
            .log_event_json(
                &mut dbtx.global_dbtx(self.global_dbtx_access_token).to_ref_nc(),
                <E as Event>::MODULE,
                self.module_instance_id,
                <E as Event>::KIND,
                serde_json::to_value(event).expect("Can't fail"),
                <E as Event>::PERSISTENCE,
            )
            .await;
    }
}

/// Priority module priority (lower number is higher priority)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrimaryModulePriority(u64);

impl PrimaryModulePriority {
    pub const HIGH: Self = Self(100);
    pub const LOW: Self = Self(10000);

    pub fn custom(prio: u64) -> Self {
        Self(prio)
    }
}
/// Which amount units this module supports being primary for
pub enum PrimaryModuleSupport {
    /// Potentially any unit
    Any { priority: PrimaryModulePriority },
    /// Some units supported by the module
    Selected {
        priority: PrimaryModulePriority,
        units: BTreeSet<AmountUnit>,
    },
    /// None
    None,
}

impl PrimaryModuleSupport {
    pub fn selected<const N: usize>(
        priority: PrimaryModulePriority,
        units: [AmountUnit; N],
    ) -> Self {
        Self::Selected {
            priority,
            units: BTreeSet::from(units),
        }
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
        amount: &Amounts,
        input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts>;

    /// Returns the amount of an input previously generated by the module.
    ///
    /// None is only returned if the client can't determine the amount of an
    /// input, which normally should only be the case if a future version of
    /// Fedimint introduces a new input variant, which isn't a problem since
    /// clients only deal with transactions they generated. When the feature was
    /// introduced old LNv2 transactions would also return `None` though.
    ///
    /// # Panics
    /// May panic if the input was not generated by the client itself since some
    /// modules may rely on cached metadata.
    async fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> Option<Amounts>;

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
        amount: &Amounts,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts>;

    /// Returns the amount of the output.
    ///
    /// None is only returned if a future version of Fedimint introduces a
    /// new output variant. For clients this should only be the case when
    /// processing transactions created by other users, so the result of
    /// this function can be `unwrap`ped whenever dealing with inputs
    /// generated by ourselves.
    ///
    /// # Panics
    /// May panic if the output was not generated by the client itself since
    /// some modules may rely on cached metadata.
    async fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts>;

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
    fn supports_being_primary(&self) -> PrimaryModuleSupport {
        PrimaryModuleSupport::None
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
        _unit: AmountUnit,
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
    ) -> anyhow::Result<()> {
        unimplemented!()
    }

    /// Returns the balance held by this module and available for funding
    /// transactions.
    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>, _unit: AmountUnit) -> Amount {
        unimplemented!()
    }

    /// Returns the balance held by this module and available for funding
    /// transactions.
    async fn get_balances(&self, _dbtx: &mut DatabaseTransaction<'_>) -> Amounts {
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
    /// to safely (e.g. without losing funds) leave the Federation.
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

    fn input_fee(&self, amount: &Amounts, input: &DynInput) -> Option<Amounts>;

    async fn input_amount(&self, input: &DynInput) -> Option<Amounts>;

    fn output_fee(&self, amount: &Amounts, output: &DynOutput) -> Option<Amounts>;

    async fn output_amount(&self, output: &DynOutput) -> Option<Amounts>;

    fn supports_backup(&self) -> bool;

    async fn backup(&self, module_instance_id: ModuleInstanceId)
    -> anyhow::Result<DynModuleBackup>;

    fn supports_being_primary(&self) -> PrimaryModuleSupport;

    async fn create_final_inputs_and_outputs(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        unit: AmountUnit,
        input_amount: Amount,
        output_amount: Amount,
    ) -> anyhow::Result<(ClientInputBundle, ClientOutputBundle)>;

    async fn await_primary_module_output(
        &self,
        operation_id: OperationId,
        out_point: OutPoint,
    ) -> anyhow::Result<()>;

    async fn get_balance(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        unit: AmountUnit,
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

    fn input_fee(&self, amount: &Amounts, input: &DynInput) -> Option<Amounts> {
        <T as ClientModule>::input_fee(
            self,
            amount,
            input
                .as_any()
                .downcast_ref()
                .expect("Dispatched to correct module"),
        )
    }

    async fn input_amount(&self, input: &DynInput) -> Option<Amounts> {
        <T as ClientModule>::input_amount(
            self,
            input
                .as_any()
                .downcast_ref()
                .expect("Dispatched to correct module"),
        )
        .await
    }

    fn output_fee(&self, amount: &Amounts, output: &DynOutput) -> Option<Amounts> {
        <T as ClientModule>::output_fee(
            self,
            amount,
            output
                .as_any()
                .downcast_ref()
                .expect("Dispatched to correct module"),
        )
    }

    async fn output_amount(&self, output: &DynOutput) -> Option<Amounts> {
        <T as ClientModule>::output_amount(
            self,
            output
                .as_any()
                .downcast_ref()
                .expect("Dispatched to correct module"),
        )
        .await
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

    fn supports_being_primary(&self) -> PrimaryModuleSupport {
        <T as ClientModule>::supports_being_primary(self)
    }

    async fn create_final_inputs_and_outputs(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        unit: AmountUnit,
        input_amount: Amount,
        output_amount: Amount,
    ) -> anyhow::Result<(ClientInputBundle, ClientOutputBundle)> {
        let (inputs, outputs) = <T as ClientModule>::create_final_inputs_and_outputs(
            self,
            &mut dbtx.to_ref_with_prefix_module_id(module_instance).0,
            operation_id,
            unit,
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
    ) -> anyhow::Result<()> {
        <T as ClientModule>::await_primary_module_output(self, operation_id, out_point).await
    }

    async fn get_balance(
        &self,
        module_instance: ModuleInstanceId,
        dbtx: &mut DatabaseTransaction<'_>,
        unit: AmountUnit,
    ) -> Amount {
        <T as ClientModule>::get_balance(
            self,
            &mut dbtx.to_ref_with_prefix_module_id(module_instance).0,
            unit,
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

// Re-export types from fedimint_core
pub use fedimint_core::{IdxRange, OutPointRange, OutPointRangeIter};

pub type StateGenerator<S> = Arc<maybe_add_send_sync!(dyn Fn(OutPointRange) -> Vec<S> + 'static)>;
