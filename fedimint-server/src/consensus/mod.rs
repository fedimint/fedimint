#![allow(clippy::let_unit_value)]

pub mod debug;
pub mod server;

use bls12_381::{G1Projective, Scalar};
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::module::registry::ServerModuleRegistry;
use fedimint_core::module::{ItemAmount, TransactionItemAmount};
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
                &mut dbtx.to_ref_with_prefix_module_id(input.module_instance_id()),
                input,
                input.module_instance_id(),
            )
            .await
            .map_err(TransactionError::Input)?;

        funding_verifier.add_input(meta.amount);
        public_keys.push(meta.pub_key);
    }

    transaction.validate_signatures(public_keys)?;

    for (output, out_idx) in transaction.outputs.iter().zip(0u64..) {
        let amount = modules
            .get_expect(output.module_instance_id())
            .process_output(
                &mut dbtx.to_ref_with_prefix_module_id(output.module_instance_id()),
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
    public_input: Amount,
    public_output: Amount,
    confidential_input: G1Projective,
    confidential_output: G1Projective,
    fee_amount: Amount,
}

impl FundingVerifier {
    pub fn add_input(&mut self, input_amount: TransactionItemAmount) {
        match input_amount.amount {
            ItemAmount::Public(amount) => self.public_input += amount,
            ItemAmount::Confidential(amount) => self.confidential_input += amount,
        }

        self.fee_amount += input_amount.fee;
    }

    pub fn add_output(&mut self, output_amount: TransactionItemAmount) {
        match output_amount.amount {
            ItemAmount::Public(amount) => self.public_output += amount,
            ItemAmount::Confidential(amount) => self.confidential_output += amount,
        }

        self.fee_amount += output_amount.fee;
    }

    pub fn verify_funding(self) -> Result<(), TransactionError> {
        let public_input = Scalar::from(self.public_input.msats);
        let public_output = Scalar::from(self.public_output.msats + self.fee_amount.msats);

        let input = public_input * G1Projective::generator() + self.confidential_input;
        let output = public_output * G1Projective::generator() + self.confidential_output;

        if input - output == G1Projective::identity() {
            Ok(())
        } else {
            Err(TransactionError::UnbalancedTransaction {
                inputs: self.public_input,
                outputs: self.public_output,
                fee: self.fee_amount,
            })
        }
    }
}

impl Default for FundingVerifier {
    fn default() -> Self {
        FundingVerifier {
            public_input: Amount::ZERO,
            public_output: Amount::ZERO,
            confidential_input: G1Projective::identity(),
            confidential_output: G1Projective::identity(),
            fee_amount: Amount::ZERO,
        }
    }
}
