//! Client library for fedimintd

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use fedimint_core::api::{DynFederationApi, IFederationApi};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction};
use fedimint_core::time::now;
use fedimint_core::transaction::Transaction;
use fedimint_core::{maybe_add_send_sync, Amount, TransactionId};
use rand::thread_rng;
use secp256k1_zkp::Secp256k1;

use crate::module::{DynClientModule, DynPrimaryClientModule, IClientModule};
use crate::sm::{DynState, Executor, GlobalContext, OperationId, OperationState};
use crate::transaction::{
    ClientInput, ClientOutput, TransactionBuilder, TransactionBuilderBalance, TxSubmissionStates,
    TRANSACTION_SUBMISSION_MODULE_INSTANCE,
};

/// Module client interface definitions
pub mod module;
/// Client state machine interfaces and executor implementation
pub mod sm;
/// Structs and interfaces to construct Fedimint transactions
pub mod transaction;

/// Global state and functionality provided to all state machines running in the
/// client
#[derive(Clone)]
pub struct GlobalClientContext {
    inner: Arc<ClientInner>,
}

impl GlobalContext for GlobalClientContext {}

// TODO: impl `Debug` for `Client` and derive here
impl Debug for GlobalClientContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GlobalClientContext")
    }
}

impl GlobalClientContext {
    /// Returns a reference to the client's federation API client. The provided
    /// interface [`IFederationApi`] typically does not provide the necessary
    /// functionality, for this extension traits like
    /// [`fedimint_core::api::GlobalFederationApi`] have to be used.
    pub fn api(&self) -> &(dyn IFederationApi + 'static) {
        self.inner.api.as_ref()
    }

    /// Add funding and/or change to the transaction builder as needed, finalize
    /// the transaction and submit it to the federation once `dbtx` is
    /// committed.
    pub async fn finalize_and_submit_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        operation_id: OperationId,
        tx_builder: TransactionBuilder,
    ) -> anyhow::Result<TransactionId> {
        self.inner
            .finalize_and_submit_transaction(dbtx, operation_id, tx_builder)
            .await
    }
}

pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn context(&self) -> GlobalClientContext {
        GlobalClientContext {
            inner: self.inner.clone(),
        }
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
    modules: BTreeMap<ModuleInstanceId, DynClientModule>,
    executor: Executor<GlobalClientContext>,
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
                .get(&instance)
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
    ) -> anyhow::Result<(Transaction, Vec<DynState<GlobalClientContext>>)> {
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

        self.executor.add_state_mchines_dbtx(dbtx, states).await?;

        Ok(txid)
    }
}
