use fedimint_core::db::WriteDatabaseTransaction;
use fedimint_core::module::{Amounts, CoreConsensusVersion, TransactionItemAmounts};
use fedimint_core::transaction::{TRANSACTION_OVERFLOW_ERROR, Transaction, TransactionError};
use fedimint_core::{InPoint, OutPoint};
use fedimint_server_core::ServerModuleRegistry;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::metrics::{CONSENSUS_TX_PROCESSED_INPUTS, CONSENSUS_TX_PROCESSED_OUTPUTS};

#[derive(Debug, PartialEq, Eq)]
pub enum TxProcessingMode {
    Submission,
    Consensus,
}

pub async fn process_transaction_with_dbtx<Cap>(
    modules: ServerModuleRegistry,
    dbtx: &mut WriteDatabaseTransaction<'_, Cap>,
    transaction: &Transaction,
    version: CoreConsensusVersion,
    mode: TxProcessingMode,
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

    let txid = transaction.tx_hash();

    for (input, in_idx) in transaction.inputs.iter().zip(0u64..) {
        // somewhat unfortunately, we need to do the extra checks berofe `process_x`
        // does the changes in the dbtx
        if mode == TxProcessingMode::Submission {
            modules
                .get_expect(input.module_instance_id())
                .verify_input_submission(
                    &mut dbtx
                        .to_ref_with_prefix_module_id(input.module_instance_id())
                        .0
                        .to_ref_nc(),
                    input,
                )
                .await
                .map_err(TransactionError::Input)?;
        }
        let meta = modules
            .get_expect(input.module_instance_id())
            .process_input(
                &mut dbtx
                    .to_ref_with_prefix_module_id(input.module_instance_id())
                    .0
                    .to_ref_nc(),
                input,
                InPoint { txid, in_idx },
            )
            .await
            .map_err(TransactionError::Input)?;

        funding_verifier.add_input(meta.amount)?;
        public_keys.push(meta.pub_key);
    }

    transaction.validate_signatures(&public_keys)?;

    for (output, out_idx) in transaction.outputs.iter().zip(0u64..) {
        // somewhat unfortunately, we need to do the extra checks berofe `process_x`
        // does the changes in the dbtx
        if mode == TxProcessingMode::Submission {
            modules
                .get_expect(output.module_instance_id())
                .verify_output_submission(
                    &mut dbtx
                        .to_ref_with_prefix_module_id(output.module_instance_id())
                        .0
                        .to_ref_nc(),
                    output,
                    OutPoint { txid, out_idx },
                )
                .await
                .map_err(TransactionError::Output)?;
        }

        let amount = modules
            .get_expect(output.module_instance_id())
            .process_output(
                &mut dbtx
                    .to_ref_with_prefix_module_id(output.module_instance_id())
                    .0
                    .to_ref_nc(),
                output,
                OutPoint { txid, out_idx },
            )
            .await
            .map_err(TransactionError::Output)?;

        funding_verifier.add_output(amount)?;
    }

    funding_verifier.verify_funding(version)?;

    Ok(())
}

#[derive(Clone, Debug)]
pub struct FundingVerifier {
    inputs: Amounts,
    outputs: Amounts,
    fees: Amounts,
}

impl FundingVerifier {
    pub fn add_input(
        &mut self,
        input: TransactionItemAmounts,
    ) -> Result<&mut Self, TransactionError> {
        self.inputs
            .checked_add_mut(&input.amounts)
            .ok_or(TRANSACTION_OVERFLOW_ERROR)?;
        self.fees
            .checked_add_mut(&input.fees)
            .ok_or(TRANSACTION_OVERFLOW_ERROR)?;

        Ok(self)
    }

    pub fn add_output(
        &mut self,
        output_amounts: TransactionItemAmounts,
    ) -> Result<&mut Self, TransactionError> {
        self.outputs
            .checked_add_mut(&output_amounts.amounts)
            .ok_or(TRANSACTION_OVERFLOW_ERROR)?;
        self.fees
            .checked_add_mut(&output_amounts.fees)
            .ok_or(TRANSACTION_OVERFLOW_ERROR)?;

        Ok(self)
    }

    pub fn verify_funding(mut self, version: CoreConsensusVersion) -> Result<(), TransactionError> {
        // In early versions we did not allow any overpaying
        const OVERPAY_MIN_VERSION: CoreConsensusVersion = CoreConsensusVersion::new(2, 1);

        let outputs_and_fees = self
            .outputs
            .clone()
            .checked_add(&self.fees)
            .ok_or(TRANSACTION_OVERFLOW_ERROR)?;

        for (out_unit, out_amount) in outputs_and_fees {
            let input_amount = self.inputs.get(&out_unit).copied().unwrap_or_default();

            if input_amount < out_amount
                // In early versions we did not allow any overpaying
                ||  (input_amount != out_amount  && version < OVERPAY_MIN_VERSION)
            {
                return Err(TransactionError::UnbalancedTransaction {
                    inputs: input_amount,
                    outputs: self.outputs.get(&out_unit).copied().unwrap_or_default(),
                    fee: self.fees.get(&out_unit).copied().unwrap_or_default(),
                });
            }

            // Explicitly remove for the check below to
            self.inputs.remove(&out_unit);
        }

        if version < OVERPAY_MIN_VERSION
            && let Some((inputs_unit, inputs_amount)) = self.inputs.into_iter().next()
        {
            return Err(TransactionError::UnbalancedTransaction {
                inputs: inputs_amount,
                outputs: self.outputs.get(&inputs_unit).copied().unwrap_or_default(),
                fee: self.fees.get(&inputs_unit).copied().unwrap_or_default(),
            });
        }

        Ok(())
    }
}

impl Default for FundingVerifier {
    fn default() -> Self {
        FundingVerifier {
            inputs: Amounts::ZERO,
            outputs: Amounts::ZERO,
            fees: Amounts::ZERO,
        }
    }
}

#[cfg(test)]
mod tests;
