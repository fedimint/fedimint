use bitcoin::KeyPair;
use fedimint_api::config::ClientConfig;
use fedimint_api::core::client::ClientModulePlugin;
use fedimint_api::db::DatabaseTransaction;
use fedimint_api::module::TransactionItemAmount;
use fedimint_api::{Amount, OutPoint, Tiered, TieredMulti};
use fedimint_core::modules::ln::contracts::ContractOutcome;
use fedimint_core::modules::ln::LightningOutputOutcome;
use fedimint_core::modules::mint::{BlindNonce, MintInput, MintOutput, SignRequest};
use fedimint_core::outcome::legacy::OutputOutcome;
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::transaction::legacy::{Input, Output, Transaction};
use rand::{CryptoRng, RngCore};
use tbs::AggregatePublicKey;
use tracing::debug;

use crate::mint::db::{CoinKey, OutputFinalizationKey, PendingCoinsKey};
use crate::mint::{NoteIssuanceRequest, NoteIssuanceRequests};
use crate::{
    module_decode_stubs, Client, DecryptedPreimage, MintClientError, MintOutputOutcome,
    SpendableNote,
};

pub trait Final {
    fn is_final(&self) -> bool;
}

pub struct TransactionBuilder {
    input_notes: TieredMulti<SpendableNote>,
    output_notes: Vec<(u64, NoteIssuanceRequests)>,
    keys: Vec<KeyPair>,
    tx: Transaction,
}

impl Final for OutputOutcome {
    fn is_final(&self) -> bool {
        match self {
            OutputOutcome::Mint(MintOutputOutcome(Some(_))) => true,
            OutputOutcome::Mint(MintOutputOutcome(None)) => false,
            OutputOutcome::Wallet(_) => true,
            OutputOutcome::LN(LightningOutputOutcome::Offer { .. }) => true,
            OutputOutcome::LN(LightningOutputOutcome::Contract { outcome, .. }) => match outcome {
                ContractOutcome::Account(_) => true,
                ContractOutcome::Incoming(DecryptedPreimage::Some(_)) => true,
                ContractOutcome::Incoming(_) => false,
                ContractOutcome::Outgoing(_) => true,
            },
        }
    }
}

impl Final for TransactionStatus {
    fn is_final(&self) -> bool {
        let modules = module_decode_stubs();

        match self {
            TransactionStatus::Rejected(_) => true,
            TransactionStatus::Accepted { outputs, .. } => outputs.iter().all(|out| {
                let legacy_oo: OutputOutcome = out
                    .try_into_inner(&modules)
                    .expect("Federation sent invalid data") // FIXME: don't crash here
                    .into();

                legacy_oo.is_final()
            }),
        }
    }
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
    ) -> Result<(), MintClientError> {
        self.input_notes.extend(coins.clone());
        let (mut coin_keys, coin_input) = self.create_input_from_coins(coins)?;
        self.input(&mut coin_keys, Input::Mint(coin_input));
        Ok(())
    }

    pub fn create_input_from_coins(
        &mut self,
        coins: TieredMulti<SpendableNote>,
    ) -> Result<(Vec<KeyPair>, MintInput), MintClientError> {
        let coin_key_pairs = coins
            .into_iter()
            .map(|(amt, coin)| {
                // We check for coin validity in case we got it from an untrusted third party. We
                // don't want to needlessly create invalid tx and bother the federation with them.
                let spend_pub_key = coin.spend_key.x_only_public_key().0;
                if &spend_pub_key == coin.note.spend_key() {
                    Ok((coin.spend_key, (amt, coin.note)))
                } else {
                    Err(MintClientError::ReceivedUspendableCoin)
                }
            })
            .collect::<Result<Vec<_>, MintClientError>>()?;
        let (key_pairs, input) = coin_key_pairs.into_iter().unzip();
        Ok((key_pairs, MintInput(input)))
    }

    pub fn input(&mut self, key: &mut Vec<KeyPair>, input: Input) {
        self.keys.append(key);
        self.tx.inputs.push(input);
    }

    pub fn output(&mut self, output: Output) -> u64 {
        self.tx.outputs.push(output);
        (self.tx.outputs.len() - 1) as u64
    }

    pub fn change_required<C>(&self, client: &Client<C>) -> Amount
    where
        C: AsRef<ClientConfig> + Clone,
    {
        self.input_amount(client) - self.output_amount(client) - self.fee_amount(client)
    }

    pub async fn output_coins<F, Fut>(
        &mut self,
        amount: Amount,
        coin_gen: F,
        tbs_pks: &Tiered<AggregatePublicKey>,
    ) where
        F: FnMut() -> Fut,
        Fut: futures::Future<Output = (NoteIssuanceRequest, BlindNonce)>,
    {
        let (coin_finalization_data, coin_output) =
            self.create_output_coins(amount, coin_gen, tbs_pks).await;

        if !coin_output.is_empty() {
            let out_idx = self.tx.outputs.len();
            self.output(Output::Mint(MintOutput(coin_output)));
            self.output_notes
                .push((out_idx as u64, coin_finalization_data));
        }
    }

    pub async fn create_output_coins<F, Fut>(
        &mut self,
        amount: Amount,
        mut coin_gen: F,
        tbs_pks: &Tiered<AggregatePublicKey>,
    ) -> (NoteIssuanceRequests, TieredMulti<BlindNonce>)
    where
        F: FnMut() -> Fut,
        Fut: futures::Future<Output = (NoteIssuanceRequest, BlindNonce)>,
    {
        let mut amount_requests: Vec<((Amount, NoteIssuanceRequest), (Amount, BlindNonce))> =
            Vec::new();
        for (amt, ()) in TieredMulti::represent_amount(amount, tbs_pks).into_iter() {
            let (request, blind_nonce) = coin_gen().await;
            amount_requests.push(((amt, request), (amt, blind_nonce)));
        }
        let (coin_finalization_data, sig_req): (NoteIssuanceRequests, SignRequest) =
            amount_requests.into_iter().unzip();

        debug!(
            %amount,
            coins = %sig_req.0.item_count(),
            tiers = ?sig_req.0.tiers().collect::<Vec<_>>(),
            "Generated issuance request"
        );

        (coin_finalization_data, sig_req.0)
    }

    pub async fn build<'a, R: RngCore + CryptoRng, F, Fut>(
        mut self,
        change_required: Amount,
        dbtx: &mut DatabaseTransaction<'a>,
        coin_gen: F,
        secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
        tbs_pks: &Tiered<AggregatePublicKey>,
        mut rng: R,
    ) -> Transaction
    where
        F: FnMut() -> Fut,
        Fut: futures::Future<Output = (NoteIssuanceRequest, BlindNonce)>,
    {
        // add change
        self.output_coins(change_required, coin_gen, tbs_pks).await;

        let txid = self.tx.tx_hash();
        if !self.keys.is_empty() {
            let signature =
                fedimint_core::transaction::agg_sign(&self.keys, txid.as_hash(), secp, &mut rng);
            self.tx.signature = Some(signature);
        }

        // move input coins to pending state, awaiting a transaction
        if !self.input_notes.item_count() != 0 {
            for (amount, coin) in self.input_notes.iter_items() {
                // maybe_delete because coins might have been received from another user directly
                dbtx.remove_entry(&CoinKey {
                    amount,
                    nonce: coin.note.0.clone(),
                })
                .await
                .expect("DB Error");
            }
            dbtx.insert_entry(&PendingCoinsKey(txid), &self.input_notes)
                .await
                .expect("DB Error");
        }

        // write coin output to db to await for tx success to be fetched later
        for (out_idx, coins) in self.output_notes.iter() {
            dbtx.insert_new_entry(
                &OutputFinalizationKey(OutPoint {
                    txid,
                    out_idx: *out_idx,
                }),
                &coins.clone(),
            )
            .await
            .expect("DB Error");
        }

        self.tx
    }

    fn input_amount_iter<'a, C>(
        &'a self,
        client: &'a Client<C>,
    ) -> impl Iterator<Item = TransactionItemAmount> + 'a
    where
        C: AsRef<ClientConfig> + Clone,
    {
        self.tx.inputs.iter().map(|i| match i {
            Input::Mint(input) => client.mint_client().input_amount(input),
            Input::Wallet(input) => client.wallet_client().input_amount(input),
            Input::LN(input) => client.ln_client().input_amount(input),
        })
    }

    fn output_amount_iter<'a, C>(
        &'a self,
        client: &'a Client<C>,
    ) -> impl Iterator<Item = TransactionItemAmount> + 'a
    where
        C: AsRef<ClientConfig> + Clone + 'a,
    {
        self.tx.outputs.iter().map(|o| match o {
            Output::Mint(output) => client.mint_client().output_amount(output),
            Output::Wallet(output) => client.wallet_client().output_amount(output),
            Output::LN(output) => client.ln_client().output_amount(output),
        })
    }

    fn input_amount<C>(&self, client: &Client<C>) -> Amount
    where
        C: AsRef<ClientConfig> + Clone,
    {
        self.input_amount_iter(client)
            .map(|amount_info| amount_info.amount)
            .sum()
    }

    fn output_amount<C>(&self, client: &Client<C>) -> Amount
    where
        C: AsRef<ClientConfig> + Clone,
    {
        self.output_amount_iter(client)
            .map(|amount_info| amount_info.amount)
            .sum()
    }

    fn fee_amount<C>(&self, client: &Client<C>) -> Amount
    where
        C: AsRef<ClientConfig> + Clone,
    {
        self.input_amount_iter(client)
            .chain(self.output_amount_iter(client))
            .map(|amount_info| amount_info.fee)
            .sum()
    }
}
