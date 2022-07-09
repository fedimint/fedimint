use bitcoin::KeyPair;
use minimint_api::Amount;
use minimint_core::config::FeeConsensus;
use minimint_core::transaction::{Input, Output, Transaction};
use rand::{CryptoRng, RngCore};
use bitcoin::secp256k1::{All, Secp256k1};

pub struct TransactionBuilder {
    keys: Vec<KeyPair>,
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
    pub fn input(&mut self, key: &mut Vec<KeyPair>, input: Input) {
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
        secp: &Secp256k1<All>,
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
