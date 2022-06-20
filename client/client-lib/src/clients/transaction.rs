use rand::{CryptoRng, RngCore};
use secp256k1_zkp::schnorrsig;

use minimint_api::Amount;
use minimint_core::config::FeeConsensus;
use minimint_core::transaction::{Input, Output, Transaction};

pub struct TransactionBuilder {
    keys: Vec<schnorrsig::KeyPair>,
    pub tx: Transaction,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        TransactionBuilder {
            keys: vec![],
            tx: Transaction {
                inputs: vec![],
                outputs: vec![],
                signature: None,
            },
        }
    }
}

impl TransactionBuilder {
    pub fn input(&mut self, key: &mut Vec<schnorrsig::KeyPair>, input: Input) {
        self.keys.append(key);
        self.tx.inputs.push(input);
    }

    pub fn output(&mut self, output: Output) {
        self.tx.outputs.push(output);
    }

    pub fn change_required(&self, fees: &FeeConsensus) -> Amount {
        self.tx.in_amount() - self.tx.out_amount() - self.tx.fee_amount(fees)
    }

    pub fn build<R: RngCore + CryptoRng>(
        mut self,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
        mut rng: R,
    ) -> Transaction {
        if !self.keys.is_empty() {
            let signature = minimint_core::transaction::agg_sign(
                &self.keys,
                self.tx.tx_hash().as_hash(),
                secp,
                &mut rng,
            );
            self.tx.signature = Some(signature);
        }

        self.tx
    }
}
