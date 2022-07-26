use rand::{CryptoRng, RngCore};

use crate::mint::db::{CoinKey, OutputFinalizationKey, PendingCoinsKey};
use crate::mint::CoinFinalizationData;
use crate::{MintClientError, SpendableCoin};
use bitcoin::KeyPair;
use minimint_api::db::batch::{BatchItem, BatchTx};
use minimint_api::{Amount, OutPoint};
use minimint_core::config::FeeConsensus;
use minimint_core::modules::mint::tiered::coins::Coins;
use minimint_core::modules::mint::{BlindToken, Coin, Keys};
use minimint_core::transaction::{Input, Output, Transaction};
use tbs::AggregatePublicKey;

pub struct TransactionBuilder {
    input_coins: Coins<SpendableCoin>,
    output_coins: Vec<(u64, CoinFinalizationData)>,
    keys: Vec<KeyPair>,
    tx: Transaction,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        TransactionBuilder {
            input_coins: Default::default(),
            output_coins: vec![],
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
    pub fn input_coins(
        &mut self,
        coins: Coins<SpendableCoin>,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    ) -> Result<(), MintClientError> {
        self.input_coins.extend(coins.clone());
        let (mut coin_keys, coin_input) = self.create_input_from_coins(coins, secp)?;
        self.input(&mut coin_keys, Input::Mint(coin_input));
        Ok(())
    }

    pub fn create_input_from_coins(
        &mut self,
        coins: Coins<SpendableCoin>,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    ) -> Result<(Vec<KeyPair>, Coins<Coin>), MintClientError> {
        let coin_key_pairs = coins
            .into_iter()
            .map(|(amt, coin)| {
                let spend_key = bitcoin::KeyPair::from_seckey_slice(secp, &coin.spend_key)
                    .map_err(|_| MintClientError::ReceivedUspendableCoin)?;

                // We check for coin validity in case we got it from an untrusted third party. We
                // don't want to needlessly create invalid tx and bother the federation with them.
                let spend_pub_key = spend_key.public_key();
                if &spend_pub_key == coin.coin.spend_key() {
                    Ok((spend_key, (amt, coin.coin)))
                } else {
                    Err(MintClientError::ReceivedUspendableCoin)
                }
            })
            .collect::<Result<Vec<_>, MintClientError>>()?;
        Ok(coin_key_pairs.into_iter().unzip())
    }

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

    pub fn output_coins<R: RngCore + CryptoRng>(
        &mut self,
        amount: Amount,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
        tbs_pks: &Keys<AggregatePublicKey>,
        rng: R,
    ) {
        let (coin_finalization_data, coin_output) =
            self.create_output_coins(amount, secp, tbs_pks, rng);

        if !coin_output.coins.is_empty() {
            let out_idx = self.tx.outputs.len();
            self.output(Output::Mint(coin_output));
            self.output_coins
                .push((out_idx as u64, coin_finalization_data));
        }
    }

    pub fn create_output_coins<R: RngCore + CryptoRng>(
        &mut self,
        amount: Amount,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
        tbs_pks: &Keys<AggregatePublicKey>,
        rng: R,
    ) -> (CoinFinalizationData, Coins<BlindToken>) {
        let (coin_finalization_data, sig_req) =
            CoinFinalizationData::new(amount, tbs_pks, secp, rng);

        let coin_output = sig_req
            .0
            .into_iter()
            .map(|(amt, token)| (amt, BlindToken(token)))
            .collect();

        (coin_finalization_data, coin_output)
    }

    pub fn build<R: RngCore + CryptoRng>(
        mut self,
        change_required: Amount,
        mut batch: BatchTx,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
        tbs_pks: &Keys<AggregatePublicKey>,
        mut rng: R,
    ) -> Transaction {
        // add change
        self.output_coins(change_required, secp, tbs_pks, &mut rng);

        let txid = self.tx.tx_hash();
        if !self.keys.is_empty() {
            let signature =
                minimint_core::transaction::agg_sign(&self.keys, txid.as_hash(), secp, &mut rng);
            self.tx.signature = Some(signature);
        }

        // move input coins to pending state, awaiting a transaction
        if !self.input_coins.coins.is_empty() {
            batch.append_from_iter(self.input_coins.iter().map(|(amount, coin)| {
                BatchItem::delete(CoinKey {
                    amount,
                    nonce: coin.coin.0.clone(),
                })
            }));
            batch.append_insert(PendingCoinsKey(txid), self.input_coins);
        }

        // write coin output to db to await for tx success to be fetched later
        self.output_coins.iter().for_each(|(out_idx, coins)| {
            batch.append_insert_new(
                OutputFinalizationKey(OutPoint {
                    txid,
                    out_idx: *out_idx,
                }),
                coins.clone(),
            );
        });

        batch.commit();
        self.tx
    }
}
