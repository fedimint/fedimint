#![allow(clippy::let_unit_value)]

pub(crate) mod debug_fmt;
pub mod server;

use fedimint_core::db::DatabaseTransaction;
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::TransactionItemAmount;
use fedimint_core::transaction::{Transaction, TransactionError};
use fedimint_core::{Amount, OutPoint, TransactionId};

use crate::metrics::{CONSENSUS_TX_PROCESSED_INPUTS, CONSENSUS_TX_PROCESSED_OUTPUTS};

pub async fn process_transaction_with_dbtx(
    modules: ServerModuleRegistry,
    dbtx: &mut DatabaseTransaction<'_>,
    transaction: Transaction,
) -> Result<(), TransactionError> {
    let txid = transaction.tx_hash();
    let mut funding_verifier = FundingVerifier::default();
    let mut public_keys = Vec::new();
    let in_count = transaction.inputs.len();
    let out_count = transaction.outputs.len();

    dbtx.on_commit(move || {
        CONSENSUS_TX_PROCESSED_INPUTS.observe(in_count as f64);
        CONSENSUS_TX_PROCESSED_OUTPUTS.observe(out_count as f64);
    });
    for (input, input_idx) in transaction.inputs.iter().zip(0u64..) {
        let meta = modules
            .get_expect(input.module_instance_id())
            .process_input(
                &mut dbtx.to_ref_with_prefix_module_id(input.module_instance_id()),
                input,
                input.module_instance_id(),
            )
            .await
            .map_err(|error| TransactionError::Input {
                error,
                input_idx,
                txid,
            })?;

        funding_verifier.add_input(meta.amount);
        public_keys.push(meta.pub_key);
    }

    transaction.validate_signatures(public_keys)?;

    for (output, output_idx) in transaction.outputs.iter().zip(0u64..) {
        let amount = modules
            .get_expect(output.module_instance_id())
            .process_output(
                &mut dbtx.to_ref_with_prefix_module_id(output.module_instance_id()),
                output,
                OutPoint {
                    txid,
                    out_idx: output_idx,
                },
                output.module_instance_id(),
            )
            .await
            .map_err(|error| TransactionError::Output {
                txid,
                output_idx,
                error,
            })?;

        funding_verifier.add_output(amount);
    }

    funding_verifier.verify_funding(txid)?;

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

    pub fn verify_funding(self, txid: TransactionId) -> Result<(), TransactionError> {
        if self.input_amount == (self.output_amount + self.fee_amount) {
            Ok(())
        } else {
            Err(TransactionError::UnbalancedTransaction {
                inputs: self.input_amount,
                outputs: self.output_amount,
                fee: self.fee_amount,
                txid,
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
