//! Client library for fedimintd

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::transaction::Transaction;
use fedimint_core::{maybe_add_send_sync, Amount};
use rand::thread_rng;
use secp256k1_zkp::Secp256k1;

use crate::module::{DynClientModule, DynPrimaryClientModule, IClientModule};
use crate::sm::{DynState, Executor};
use crate::transaction::{
    ClientInput, ClientOutput, TransactionBuilder, TransactionBuilderBalance,
};

/// Module client interface definitions
pub mod module;
/// Client state machine interfaces and executor implementation
pub mod sm;
/// Structs and interfaces to construct Fedimint transactions
pub mod transaction;

pub type GlobalClientContext = ();

pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub async fn finalize_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        partial_transaction: TransactionBuilder,
    ) -> anyhow::Result<(Transaction, Vec<DynState<GlobalClientContext>>)> {
        self.inner
            .finalize_transaction(dbtx, partial_transaction)
            .await
    }
}

struct ClientInner {
    primary_module: DynPrimaryClientModule,
    primary_module_instance: ModuleInstanceId,
    modules: BTreeMap<ModuleInstanceId, DynClientModule>,
    _executor: Executor<GlobalClientContext>,
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
}
