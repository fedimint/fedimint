use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::module::{
    Amounts, CoreConsensusVersion, ModuleConsensusVersion, TransactionItemAmounts,
    TransactionItemAmountsWithFees, TransactionItemFees,
};
use fedimint_core::transaction::{TRANSACTION_OVERFLOW_ERROR, Transaction, TransactionError};
use fedimint_core::{InPoint, OutPoint};
use fedimint_server_core::ServerModuleRegistry;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::consensus::db::{consensus_unix_time, module_fee_consensus_schedules};
use crate::metrics::{CONSENSUS_TX_PROCESSED_INPUTS, CONSENSUS_TX_PROCESSED_OUTPUTS};

#[derive(Debug, PartialEq, Eq)]
pub enum TxProcessingMode {
    Submission,
    Consensus,
}

pub async fn process_transaction_with_dbtx(
    modules: ServerModuleRegistry,
    dbtx: &mut DatabaseTransaction<'_>,
    transaction: &Transaction,
    version: CoreConsensusVersion,
    module_consensus_versions: &BTreeMap<ModuleInstanceId, ModuleConsensusVersion>,
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
            let module_instance_id = input.module_instance_id();
            let module = modules.get_expect(module_instance_id);
            let module_consensus_version = *module_consensus_versions
                .get(&module_instance_id)
                .expect("Module consensus versions were precomputed");

            module.verify_input(&input, module_consensus_version)
        })
        .map_err(|_| TransactionError::InvalidWitnessLength)?;

    let mut funding_verifier = FundingVerifier::default();
    let mut public_keys = Vec::new();

    let txid = transaction.tx_hash();
    let current_time = consensus_unix_time(dbtx).await;
    let mut fee_consensus_schedules = BTreeMap::new();

    for (input, in_idx) in transaction.inputs.iter().zip(0u64..) {
        let module_instance_id = input.module_instance_id();
        let module_consensus_version = *module_consensus_versions
            .get(&module_instance_id)
            .expect("Module consensus versions were precomputed");
        if let Entry::Vacant(entry) = fee_consensus_schedules.entry(module_instance_id) {
            let module = modules.get_expect(module_instance_id);
            let schedules = module_fee_consensus_schedules(
                dbtx,
                module_instance_id,
                current_time,
                module.initial_fee_consensus(),
            )
            .await;
            entry.insert(schedules);
        }
        let module_fee_consensus = fee_consensus_schedules
            .get(&module_instance_id)
            .expect("fee consensus schedules were inserted above");

        // somewhat unfortunately, we need to do the extra checks berofe `process_x`
        // does the changes in the dbtx
        if mode == TxProcessingMode::Submission {
            modules
                .get_expect(module_instance_id)
                .verify_input_submission(
                    &mut dbtx.to_ref_with_prefix_module_id(module_instance_id).0,
                    input,
                    module_consensus_version,
                )
                .await
                .map_err(TransactionError::Input)?;
        }
        let meta = modules
            .get_expect(module_instance_id)
            .process_input_with_fees(
                &mut dbtx.to_ref_with_prefix_module_id(module_instance_id).0,
                input,
                InPoint { txid, in_idx },
                module_consensus_version,
                module_fee_consensus,
            )
            .await
            .map_err(TransactionError::Input)?;

        funding_verifier.add_input_with_fees(meta.amount)?;
        public_keys.push(meta.pub_key);
    }

    transaction.validate_signatures(&public_keys)?;

    for (output, out_idx) in transaction.outputs.iter().zip(0u64..) {
        let module_instance_id = output.module_instance_id();
        let module_consensus_version = *module_consensus_versions
            .get(&module_instance_id)
            .expect("Module consensus versions were precomputed");
        if let Entry::Vacant(entry) = fee_consensus_schedules.entry(module_instance_id) {
            let module = modules.get_expect(module_instance_id);
            let schedules = module_fee_consensus_schedules(
                dbtx,
                module_instance_id,
                current_time,
                module.initial_fee_consensus(),
            )
            .await;
            entry.insert(schedules);
        }
        let module_fee_consensus = fee_consensus_schedules
            .get(&module_instance_id)
            .expect("fee consensus schedules were inserted above");

        // somewhat unfortunately, we need to do the extra checks berofe `process_x`
        // does the changes in the dbtx
        if mode == TxProcessingMode::Submission {
            modules
                .get_expect(module_instance_id)
                .verify_output_submission(
                    &mut dbtx.to_ref_with_prefix_module_id(module_instance_id).0,
                    output,
                    OutPoint { txid, out_idx },
                    module_consensus_version,
                )
                .await
                .map_err(TransactionError::Output)?;
        }

        let amount = modules
            .get_expect(module_instance_id)
            .process_output_with_fees(
                &mut dbtx.to_ref_with_prefix_module_id(module_instance_id).0,
                output,
                OutPoint { txid, out_idx },
                module_consensus_version,
                module_fee_consensus,
            )
            .await
            .map_err(TransactionError::Output)?;

        funding_verifier.add_output_with_fees(amount)?;
    }

    funding_verifier.verify_funding(version)?;

    Ok(())
}

#[derive(Clone, Debug)]
pub struct FundingVerifier {
    inputs: Amounts,
    outputs: Amounts,
    fees: Vec<TransactionItemFees>,
}

impl FundingVerifier {
    pub fn add_input(
        &mut self,
        input: TransactionItemAmounts,
    ) -> Result<&mut Self, TransactionError> {
        self.add_input_with_fees(input.into())
    }

    pub fn add_input_with_fees(
        &mut self,
        input: TransactionItemAmountsWithFees,
    ) -> Result<&mut Self, TransactionError> {
        self.inputs
            .checked_add_mut(&input.amounts)
            .ok_or(TRANSACTION_OVERFLOW_ERROR)?;
        self.fees.push(input.fees);

        Ok(self)
    }

    pub fn add_output(
        &mut self,
        output_amounts: TransactionItemAmounts,
    ) -> Result<&mut Self, TransactionError> {
        self.add_output_with_fees(output_amounts.into())
    }

    pub fn add_output_with_fees(
        &mut self,
        output_amounts: TransactionItemAmountsWithFees,
    ) -> Result<&mut Self, TransactionError> {
        self.outputs
            .checked_add_mut(&output_amounts.amounts)
            .ok_or(TRANSACTION_OVERFLOW_ERROR)?;
        self.fees.push(output_amounts.fees);

        Ok(self)
    }

    pub fn verify_funding(mut self, version: CoreConsensusVersion) -> Result<(), TransactionError> {
        // In early versions we did not allow any overpaying
        const OVERPAY_MIN_VERSION: CoreConsensusVersion = CoreConsensusVersion::new(2, 1);

        let (dynamic_fees, legacy_floor_fees) = self.fee_totals()?;
        let fees = Self::required_fees(version, dynamic_fees, legacy_floor_fees);

        let outputs_and_fees = self
            .outputs
            .clone()
            .checked_add(&fees)
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
                    fee: fees.get(&out_unit).copied().unwrap_or_default(),
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
                fee: fees.get(&inputs_unit).copied().unwrap_or_default(),
            });
        }

        Ok(())
    }

    fn fee_totals(&self) -> Result<(Amounts, Amounts), TransactionError> {
        let max_priority = self
            .fees
            .iter()
            .map(TransactionItemFees::max_priority)
            .max()
            .unwrap_or_default();

        let dynamic_fees = self
            .fees
            .iter()
            .try_fold(Amounts::ZERO, |mut total, fees| {
                total.checked_add_mut(&fees.try_dynamic_fee(max_priority)?)?;
                Some(total)
            })
            .ok_or(TRANSACTION_OVERFLOW_ERROR)?;

        let legacy_floor_fees = self
            .fees
            .iter()
            .try_fold(Amounts::ZERO, |mut total, fees| {
                total.checked_add_mut(&fees.try_legacy_floor_fee(max_priority)?)?;
                Some(total)
            })
            .ok_or(TRANSACTION_OVERFLOW_ERROR)?;

        Ok((dynamic_fees, legacy_floor_fees))
    }

    fn required_fees(
        _version: CoreConsensusVersion,
        dynamic_fees: Amounts,
        legacy_floor_fees: Amounts,
    ) -> Amounts {
        // TODO: When preparing the 0.16 release, bump the relevant consensus
        // version again, return `dynamic_fees` for that version and remove the
        // legacy fee-floor acceptance path.
        let _ = dynamic_fees;
        legacy_floor_fees
    }
}

impl Default for FundingVerifier {
    fn default() -> Self {
        FundingVerifier {
            inputs: Amounts::ZERO,
            outputs: Amounts::ZERO,
            fees: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests;
