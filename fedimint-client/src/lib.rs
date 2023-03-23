//! Client library for fedimintd

use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use anyhow::anyhow;
use fedimint_core::api::{DynFederationApi, IFederationApi, WsFederationApi};
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::{Database, DatabaseTransaction, IDatabase};
use fedimint_core::task::{MaybeSend, MaybeSync, TaskGroup};
use fedimint_core::time::now;
use fedimint_core::transaction::Transaction;
use fedimint_core::{
    apply, async_trait_maybe_send, dyn_newtype_define, maybe_add_send_sync, Amount, TransactionId,
};
use rand::thread_rng;
use secp256k1_zkp::Secp256k1;

use crate::module::gen::{ClientModuleGen, ClientModuleGenRegistry};
use crate::module::{ClientModuleRegistry, DynPrimaryClientModule, IClientModule};
use crate::sm::{
    ActiveState, DynState, Executor, GlobalContext, InactiveState, OperationId, OperationState,
};
use crate::transaction::{
    tx_submission_sm_decoder, ClientInput, ClientOutput, TransactionBuilder,
    TransactionBuilderBalance, TxSubmissionContext, TxSubmissionStates,
    TRANSACTION_SUBMISSION_MODULE_INSTANCE,
};

/// Module client interface definitions
pub mod module;
/// Client state machine interfaces and executor implementation
pub mod sm;
/// Structs and interfaces to construct Fedimint transactions
pub mod transaction;

#[apply(async_trait_maybe_send!)]
pub trait IGlobalClientContext: Debug + MaybeSend + MaybeSync + 'static {
    /// Returns a reference to the client's federation API client. The provided
    /// interface [`IFederationApi`] typically does not provide the necessary
    /// functionality, for this extension traits like
    /// [`fedimint_core::api::GlobalFederationApi`] have to be used.
    fn api(&self) -> &(dyn IFederationApi + 'static);

    /// Add funding and/or change to the transaction builder as needed, finalize
    /// the transaction and submit it to the federation once `dbtx` is
    /// committed.
    async fn finalize_and_submit_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<TransactionId>;

    /// Wait for any active state to appear in the database
    async fn await_active_state(&self, state: DynState<DynGlobalClientContext>) -> ActiveState;

    /// Wait for any inactive state to appear in the database
    async fn await_inactive_state(&self, state: DynState<DynGlobalClientContext>) -> InactiveState;
}

dyn_newtype_define! {
    /// Global state and functionality provided to all state machines running in the
    /// client
    #[derive(Clone)]
    pub DynGlobalClientContext(Arc<IGlobalClientContext>)
}

impl DynGlobalClientContext {
    /// Waits till consensus has been achieved on the transaction and it was
    /// accepted by consensus.
    pub async fn await_tx_accepted(
        &self,
        operation_id: OperationId,
        txid: TransactionId,
    ) -> InactiveState {
        let state = OperationState {
            operation_id,
            state: TxSubmissionStates::Accepted { txid },
        };
        self.await_inactive_state(state.into_dyn(TRANSACTION_SUBMISSION_MODULE_INSTANCE))
            .await
    }

    /// Waits till the transaction is either rejected on submission or after
    /// consensus has been achieved on it.
    pub async fn await_tx_rejected(
        &self,
        operation_id: OperationId,
        txid: TransactionId,
    ) -> InactiveState {
        let state = OperationState {
            operation_id,
            state: TxSubmissionStates::Rejected { txid },
        };
        self.await_inactive_state(state.into_dyn(TRANSACTION_SUBMISSION_MODULE_INSTANCE))
            .await
    }
}

impl<T> From<Arc<T>> for DynGlobalClientContext
where
    T: IGlobalClientContext,
{
    fn from(inner: Arc<T>) -> Self {
        DynGlobalClientContext(inner)
    }
}

impl GlobalContext for DynGlobalClientContext {}

// TODO: impl `Debug` for `Client` and derive here
impl Debug for ClientInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientInner")
    }
}

#[apply(async_trait_maybe_send!)]
impl IGlobalClientContext for ClientInner {
    fn api(&self) -> &(dyn IFederationApi + 'static) {
        self.api.as_ref()
    }

    async fn finalize_and_submit_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<TransactionId> {
        ClientInner::finalize_and_submit_transaction(self, dbtx, operation_id, tx_builder).await
    }

    async fn await_active_state(&self, state: DynState<DynGlobalClientContext>) -> ActiveState {
        ClientInner::await_active_state(self, state).await
    }

    async fn await_inactive_state(&self, state: DynState<DynGlobalClientContext>) -> InactiveState {
        ClientInner::await_inactive_state(self, state).await
    }
}

pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn context(&self) -> DynGlobalClientContext {
        DynGlobalClientContext::from(self.inner.clone())
    }

    /// Add funding and/or change to the transaction builder as needed, finalize
    /// the transaction and submit it to the federation.
    pub async fn finalize_and_submit_transaction(
        &self,
        operation_id: OperationId,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<TransactionId> {
        let mut dbtx = self.inner.db.begin_transaction().await;
        self.inner
            .finalize_and_submit_transaction(&mut dbtx, operation_id, tx_builder)
            .await
    }
}

struct ClientInner {
    db: Database,
    primary_module: DynPrimaryClientModule,
    primary_module_instance: ModuleInstanceId,
    modules: ClientModuleRegistry,
    executor: Executor<DynGlobalClientContext>,
    api: DynFederationApi,
    secp_ctx: Secp256k1<secp256k1_zkp::All>,
}

impl ClientInner {
    /// Returns a reference to the module, panics if not found
    fn get_module(&self, instance: ModuleInstanceId) -> &maybe_add_send_sync!(dyn IClientModule) {
        if instance == self.primary_module_instance {
            self.primary_module.as_ref()
        } else {
            self.modules
                .get(instance)
                .expect("Module not found")
                .as_ref()
        }
    }

    /// Determines if a transaction is underfunded, overfunded or balanced
    fn transaction_builder_balance(
        &self,
        builder: &TransactionBuilder,
    ) -> TransactionBuilderBalance {
        // FIXME: prevent overflows, currently not suitable for untrusted input
        let mut in_amount = Amount::ZERO;
        let mut out_amount = Amount::ZERO;
        let mut fee_amount = Amount::ZERO;

        for input in &builder.inputs {
            let module = self.get_module(input.input.module_instance_id());
            let item_amount = module.input_amount(&input.input);
            in_amount += item_amount.amount;
            fee_amount += item_amount.fee;
        }

        for output in &builder.outputs {
            let module = self.get_module(output.output.module_instance_id());
            let item_amount = module.output_amount(&output.output);
            out_amount += item_amount.amount;
            fee_amount += item_amount.fee;
        }

        let total_out_amount = out_amount + fee_amount;

        match total_out_amount.cmp(&in_amount) {
            Ordering::Equal => TransactionBuilderBalance::Balanced,
            Ordering::Less => TransactionBuilderBalance::Overfunded(in_amount - total_out_amount),
            Ordering::Greater => {
                TransactionBuilderBalance::Underfunded(total_out_amount - in_amount)
            }
        }
    }

    /// Adds funding to a transaction or removes overfunding via change.
    async fn finalize_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        mut partial_transaction: TransactionBuilder,
    ) -> anyhow::Result<(Transaction, Vec<DynState<DynGlobalClientContext>>)> {
        if let TransactionBuilderBalance::Underfunded(missing_amount) =
            self.transaction_builder_balance(&partial_transaction)
        {
            let (keys, input, state_machines) = self
                .primary_module
                .create_sufficient_input(self.primary_module_instance, dbtx, missing_amount)
                .await?;

            partial_transaction.inputs.push(ClientInput {
                input,
                keys,
                state_machines,
            });
        }

        if let TransactionBuilderBalance::Overfunded(excess_amount) =
            self.transaction_builder_balance(&partial_transaction)
        {
            let (output, state_machines) = self
                .primary_module
                .create_exact_output(self.primary_module_instance, dbtx, excess_amount)
                .await;
            partial_transaction.outputs.push(ClientOutput {
                output,
                state_machines,
            });
        }

        assert!(
            matches!(
                self.transaction_builder_balance(&partial_transaction),
                TransactionBuilderBalance::Balanced
            ),
            "Transaction is balanced after the previous two operations"
        );

        Ok(partial_transaction.build(&self.secp_ctx, thread_rng()))
    }

    async fn finalize_and_submit_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<TransactionId> {
        let (transaction, mut states) = self.finalize_transaction(dbtx, tx_builder).await?;
        let txid = transaction.tx_hash();

        let tx_submission_sm = DynState::from_typed(
            TRANSACTION_SUBMISSION_MODULE_INSTANCE,
            OperationState {
                operation_id,
                state: TxSubmissionStates::Created {
                    txid,
                    tx: transaction,
                    next_submission: now(),
                },
            },
        );
        states.push(tx_submission_sm);

        self.executor.add_state_machines_dbtx(dbtx, states).await?;

        Ok(txid)
    }
}

#[derive(Default)]
pub struct ClientBuilder {
    module_gens: ClientModuleGenRegistry,
    primary_module_instance: Option<ModuleInstanceId>,
    config: Option<ClientConfig>,
}

impl ClientBuilder {
    /// Make module generator available when reading the config
    pub fn with_module<M: ClientModuleGen>(&mut self, module_gen: M) {
        self.module_gens.attach(module_gen);
    }

    /// Uses this config to initialize modules
    ///
    /// ## Panics
    /// If there was a config added previously
    pub fn with_config(&mut self, config: ClientConfig) {
        let was_replaced = self.config.replace(config).is_some();
        assert!(
            !was_replaced,
            "Only one config can be given to the builder."
        )
    }

    /// Uses this module with the given instance id as the primary module. See
    /// [`module::PrimaryClientModule`] for more information.
    ///
    /// ## Panics
    /// If there was a primary module specified previously
    pub fn with_primary_module(&mut self, primary_module_instance: ModuleInstanceId) {
        let was_replaced = self
            .primary_module_instance
            .replace(primary_module_instance)
            .is_some();
        assert!(
            !was_replaced,
            "Only one primary module can be given to the builder."
        )
    }

    // TODO: impl config from file
    // TODO: impl config from federation

    pub async fn build<D: IDatabase>(self, db: D, tg: &mut TaskGroup) -> anyhow::Result<Client> {
        let config = self.config.ok_or(anyhow!("No config was provided"))?;
        let primary_module_instance = self
            .primary_module_instance
            .ok_or(anyhow!("No primary module instance id was provided"))?;

        let mut decoders =
            self.module_gens.decoders(config.modules.iter().map(
                |(module_instance, module_config)| (*module_instance, module_config.kind()),
            ))?;
        decoders.register_module(
            TRANSACTION_SUBMISSION_MODULE_INSTANCE,
            tx_submission_sm_decoder(),
        );

        let db = Database::new(db, decoders);

        let api = DynFederationApi::from(WsFederationApi::from_config(&config));

        let (modules, primary_module) = {
            let mut modules = ClientModuleRegistry::default();
            let mut primary_module = None;
            for (module_instance, module_config) in config.modules {
                if module_instance == primary_module_instance {
                    let module = self
                        .module_gens
                        .get(module_config.kind())
                        .ok_or(anyhow!("Unknown module kind in config"))?
                        .init_primary(module_config, db.clone())
                        .await?;
                    let replaced = primary_module.replace(module).is_some();
                    assert!(replaced, "Each module instance can only occur once in config, so no replacement can take place here.")
                } else {
                    let module = self
                        .module_gens
                        .get(module_config.kind())
                        .ok_or(anyhow!("Unknown module kind in config"))?
                        .init(module_config, db.clone())
                        .await?;
                    modules.register_module(module_instance, module);
                }
            }
            (
                modules,
                primary_module.ok_or(anyhow!("Primary module not found in config"))?,
            )
        };

        let executor = {
            let mut executor_builder = Executor::<DynGlobalClientContext>::builder();
            executor_builder
                .with_module(TRANSACTION_SUBMISSION_MODULE_INSTANCE, TxSubmissionContext);
            executor_builder.with_module_dyn(primary_module.context(primary_module_instance));

            for (module_instance_id, module) in modules.iter_modules() {
                executor_builder.with_module_dyn(module.context(module_instance_id));
            }

            executor_builder.build(db.clone()).await
        };

        let client_inner = Arc::new(ClientInner {
            db,
            primary_module,
            primary_module_instance,
            modules,
            executor,
            api,
            secp_ctx: Secp256k1::new(),
        });

        let global_client_context = DynGlobalClientContext::from(client_inner.clone());

        client_inner
            .executor
            .start_executor(tg, global_client_context)
            .await;

        Ok(Client {
            inner: client_inner,
        })
    }
}
