use fedimint_core::db::DatabaseTransaction;
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::TransactionItemAmount;
use fedimint_core::transaction::{Transaction, TransactionError};
use fedimint_core::{Amount, OutPoint};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::metrics::{CONSENSUS_TX_PROCESSED_INPUTS, CONSENSUS_TX_PROCESSED_OUTPUTS};

pub async fn process_transaction_with_dbtx(
    modules: ServerModuleRegistry,
    dbtx: &mut DatabaseTransaction<'_>,
    transaction: &Transaction,
) -> Result<(), TransactionError> {
    let in_count = transaction.inputs.len();
    let out_count = transaction.outputs.len();

    dbtx.on_commit(move || {
        CONSENSUS_TX_PROCESSED_INPUTS.observe(in_count as f64);
        CONSENSUS_TX_PROCESSED_OUTPUTS.observe(out_count as f64);
    });

    // We can not return the error here as errors are not returned in a specified
    // order and the client still expects consensus on the error. Since the
    // error is not extensible at the moment we need to incorrectly return the
    // InvalidWitnessLength variant.
    transaction
        .inputs
        .clone()
        .into_par_iter()
        .try_for_each(|input| {
            modules
                .get_expect(input.module_instance_id())
                .verify_input(&input)
        })
        .map_err(|_| TransactionError::InvalidWitnessLength)?;

    let mut funding_verifier = FundingVerifier::default();
    let mut public_keys = Vec::new();

    for input in &transaction.inputs {
        let meta = modules
            .get_expect(input.module_instance_id())
            .process_input(
                &mut dbtx
                    .to_ref_with_prefix_module_id(input.module_instance_id())
                    .0,
                input,
            )
            .await
            .map_err(TransactionError::Input)?;

        funding_verifier.add_input(meta.amount);
        public_keys.push(meta.pub_key);
    }

    transaction.validate_signatures(&public_keys)?;

    let txid = transaction.tx_hash();

    for (output, out_idx) in transaction.outputs.iter().zip(0u64..) {
        let amount = modules
            .get_expect(output.module_instance_id())
            .process_output(
                &mut dbtx
                    .to_ref_with_prefix_module_id(output.module_instance_id())
                    .0,
                output,
                OutPoint { txid, out_idx },
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
