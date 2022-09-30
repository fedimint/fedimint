use bitcoin::KeyPair;
use fedimint_api::db::batch::{BatchItem, BatchTx};
use fedimint_api::{Amount, OutPoint, Tiered, TieredMulti};
use fedimint_core::config::FeeConsensus;
use fedimint_core::modules::mint::{BlindNonce, Note};
use fedimint_core::transaction::{Input, Output, Transaction};
use rand::{CryptoRng, RngCore};
use tbs::AggregatePublicKey;

use crate::mint::db::{CoinKey, OutputFinalizationKey, PendingCoinsKey};
use crate::mint::NoteIssuanceRequests;
use crate::{MintClientError, SpendableNote};

pub struct TransactionBuilder {
    input_notes: TieredMulti<SpendableNote>,
    output_notes: Vec<(u64, NoteIssuanceRequests)>,
    keys: Vec<KeyPair>,
    tx: Transaction,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        TransactionBuilder {
            input_notes: Default::default(),
            output_notes: vec![],
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
        coins: TieredMulti<SpendableNote>,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    ) -> Result<(), MintClientError> {
        self.input_notes.extend(coins.clone());
        let (mut coin_keys, coin_input) = self.create_input_from_coins(coins, secp)?;
        self.input(&mut coin_keys, Input::Mint(coin_input));
        Ok(())
    }

    pub fn create_input_from_coins(
        &mut self,
        coins: TieredMulti<SpendableNote>,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    ) -> Result<(Vec<KeyPair>, TieredMulti<Note>), MintClientError> {
        let coin_key_pairs = coins
            .into_iter()
            .map(|(amt, coin)| {
                let spend_key = bitcoin::KeyPair::from_seckey_slice(secp, &coin.spend_key)
                    .map_err(|_| MintClientError::ReceivedUspendableCoin)?;

                // We check for coin validity in case we got it from an untrusted third party. We
                // don't want to needlessly create invalid tx and bother the federation with them.
                let spend_pub_key = spend_key.public_key();
                if &spend_pub_key == coin.note.spend_key() {
                    Ok((spend_key, (amt, coin.note)))
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

    pub fn output(&mut self, output: Output) -> u64 {
        self.tx.outputs.push(output);
        (self.tx.outputs.len() - 1) as u64
    }

    pub fn change_required(&self, fees: &FeeConsensus) -> Amount {
        self.tx.in_amount() - self.tx.out_amount() - self.tx.fee_amount(fees)
    }

    pub fn output_coins<R: RngCore + CryptoRng>(
        &mut self,
        amount: Amount,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
        tbs_pks: &Tiered<AggregatePublicKey>,
        rng: &mut R,
    ) {
        let (coin_finalization_data, coin_output) =
            self.create_output_coins(amount, secp, tbs_pks, rng);

        if !coin_output.is_empty() {
            let out_idx = self.tx.outputs.len();
            self.output(Output::Mint(coin_output));
            self.output_notes
                .push((out_idx as u64, coin_finalization_data));
        }
    }

    pub fn create_output_coins<R: RngCore + CryptoRng>(
        &mut self,
        amount: Amount,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
        tbs_pks: &Tiered<AggregatePublicKey>,
        rng: &mut R,
    ) -> (NoteIssuanceRequests, TieredMulti<BlindNonce>) {
        let (coin_finalization_data, sig_req) =
            NoteIssuanceRequests::new(amount, tbs_pks, secp, rng);

        let coin_output = sig_req
            .0
            .into_iter()
            .map(|(amt, token)| (amt, BlindNonce(token)))
            .collect();

        (coin_finalization_data, coin_output)
    }

    pub fn build<R: RngCore + CryptoRng>(
        mut self,
        change_required: Amount,
        mut batch: BatchTx,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
        tbs_pks: &Tiered<AggregatePublicKey>,
        mut rng: R,
    ) -> Transaction {
        // add change
        self.output_coins(change_required, secp, tbs_pks, &mut rng);

        let txid = self.tx.tx_hash();
        if !self.keys.is_empty() {
            let signature =
                fedimint_core::transaction::agg_sign(&self.keys, txid.as_hash(), secp, &mut rng);
            self.tx.signature = Some(signature);
        }

        // move input coins to pending state, awaiting a transaction
        if !self.input_notes.item_count() != 0 {
            batch.append_from_iter(self.input_notes.iter_items().map(|(amount, coin)| {
                // maybe_delete because coins might have been received from another user directly
                BatchItem::maybe_delete(CoinKey {
                    amount,
                    nonce: coin.note.0.clone(),
                })
            }));
            batch.append_insert(PendingCoinsKey(txid), self.input_notes);
        }

        // write coin output to db to await for tx success to be fetched later
        self.output_notes.iter().for_each(|(out_idx, coins)| {
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
