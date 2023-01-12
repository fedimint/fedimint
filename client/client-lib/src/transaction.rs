use bitcoin::KeyPair;
use fedimint_api::config::ClientConfig;
use fedimint_api::core::client::ClientModule;
use fedimint_api::module::TransactionItemAmount;
use fedimint_api::Amount;
use fedimint_core::modules::ln::contracts::ContractOutcome;
use fedimint_core::modules::ln::LightningOutputOutcome;
use fedimint_core::outcome::legacy::OutputOutcome;
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::transaction::legacy::{Input, Output, Transaction};
use rand::{CryptoRng, RngCore};
use secp256k1::Secp256k1;

use crate::{module_decode_stubs, Client, DecryptedPreimage, MintClient, MintOutputOutcome};

pub trait Final {
    fn is_final(&self) -> bool;
}

pub struct TransactionBuilder {
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

    /// Builds and signs the final transaction with correct change
    pub async fn build<C: AsRef<ClientConfig> + Clone, R: RngCore + CryptoRng>(
        self,
        client: &Client<C>,
        rng: R,
    ) -> Transaction {
        let change =
            self.input_amount(client) - self.output_amount(client) - self.fee_amount(client);
        self.build_with_change(
            client.mint_client(),
            rng,
            vec![change],
            &client.context.secp,
        )
        .await
    }

    /// Builds and signs the final transaction with exact change amounts
    /// WARNING - could result in an unbalanced tx that will be rejected by the federation
    pub async fn build_with_change<R: RngCore + CryptoRng>(
        mut self,
        change_module: MintClient,
        mut rng: R,
        change: Vec<Amount>,
        secp: &Secp256k1<secp256k1_zkp::All>,
    ) -> Transaction {
        change_module.finalize_change(&mut self.tx, change).await;

        let txid = self.tx.tx_hash();
        if !self.keys.is_empty() {
            let signature =
                fedimint_core::transaction::agg_sign(&self.keys, txid.as_hash(), secp, &mut rng);
            self.tx.signature = Some(signature);
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
