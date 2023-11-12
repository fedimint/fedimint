#![allow(clippy::let_unit_value)]

pub mod debug;
pub mod server;

use fedimint_core::db::DatabaseTransaction;
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::TransactionItemAmount;
use fedimint_core::transaction::{Transaction, TransactionError};
use fedimint_core::{Amount, OutPoint};

pub async fn process_transaction_with_dbtx(
    modules: ServerModuleRegistry,
    dbtx: &mut DatabaseTransaction<'_>,
    transaction: Transaction,
) -> Result<(), TransactionError> {
    let txid = transaction.tx_hash();
    let mut funding_verifier = FundingVerifier::default();
    let mut public_keys = Vec::new();

    for input in transaction.inputs.iter() {
        let meta = modules
            .get_expect(input.module_instance_id())
            .process_input(
                &mut dbtx.dbtx_ref_with_prefix_module_id(input.module_instance_id()),
                input,
                input.module_instance_id(),
            )
            .await
            .map_err(TransactionError::Input)?;

        funding_verifier.add_input(meta.amount);
        public_keys.push(meta.pub_keys);
    }

    transaction.validate_signature(public_keys.into_iter().flatten())?;

    for (output, out_idx) in transaction.outputs.iter().zip(0u64..) {
        let amount = modules
            .get_expect(output.module_instance_id())
            .process_output(
                &mut dbtx.dbtx_ref_with_prefix_module_id(output.module_instance_id()),
                output,
                OutPoint { txid, out_idx },
                output.module_instance_id(),
            )
            .await
            .map_err(TransactionError::Output)?;

        funding_verifier.add_output(amount);
    }

    funding_verifier.verify_funding()?;

    Ok(())
}

pub struct FundingVerifier {
    input_amount: Amount,
    output_amount: Amount,
    fee_amount: Amount,
}

impl FundingVerifier {
    pub fn add_input(&mut self, input_amount: TransactionItemAmount) {
        self.input_amount += input_amount.amount;
        self.fee_amount += input_amount.fee;
    }

    pub fn add_output(&mut self, output_amount: TransactionItemAmount) {
        self.output_amount += output_amount.amount;
        self.fee_amount += output_amount.fee;
    }

    pub fn verify_funding(self) -> Result<(), TransactionError> {
        if self.input_amount == (self.output_amount + self.fee_amount) {
            Ok(())
        } else {
            Err(TransactionError::UnbalancedTransaction {
                inputs: self.input_amount,
                outputs: self.output_amount,
                fee: self.fee_amount,
            })
        }
    }
}

impl Default for FundingVerifier {
    fn default() -> Self {
        FundingVerifier {
            input_amount: Amount::ZERO,
            output_amount: Amount::ZERO,
            fee_amount: Amount::ZERO,
        }
    }
}
