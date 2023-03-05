use bitcoin::KeyPair;
use fedimint_core::config::ClientConfig;
use fedimint_core::core::client::ClientModule;
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::module::TransactionItemAmount;
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::Amount;
use rand::{CryptoRng, RngCore};
use secp256k1::Secp256k1;

use crate::modules::ln::contracts::ContractOutcome;
use crate::modules::ln::LightningOutputOutcome;
use crate::outcome::legacy::OutputOutcome;
use crate::transaction::legacy::{Input, Output, Transaction};
use crate::{module_decode_stubs, Client, DecryptedPreimage, MintClient, MintOutputOutcome};

/// Old transaction definition used by old client.
pub mod legacy {
    use bitcoin_hashes::Hash;
    use fedimint_core::core::{
        DynInput, DynOutput, LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
        LEGACY_HARDCODED_INSTANCE_ID_WALLET,
    };
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::ModuleCommon;
    use fedimint_core::transaction::{agg_keys, TransactionError};
    use fedimint_core::{ServerModule, TransactionId};
    use secp256k1_zkp::{schnorr, XOnlyPublicKey};
    use serde::{Deserialize, Serialize};

    /// An atomic value transfer operation within the Fedimint system and
    /// consensus
    ///
    /// The mint enforces that the total value of the outputs equals the total
    /// value of the inputs, to prevent creating funds out of thin air. In some
    /// cases, the value of the inputs and outputs can both be 0 e.g. when
    /// creating an offer to a Lightning Gateway.
    #[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
    pub struct Transaction {
        /// [`Input`]s consumed by the transaction
        pub inputs: Vec<Input>,
        /// [`Output`]s created as a result of the transaction
        pub outputs: Vec<Output>,
        /// Aggregated MuSig2 signature over all the public keys of the inputs
        pub signature: Option<schnorr::Signature>,
    }

    /// An Input consumed by a Transaction is defined within a Fedimint Module.
    ///
    /// The user must be able to produce an aggregate Schnorr signature for the
    /// transaction over all the inputs.
    ///
    /// Each input has an associated secret/public key pair.
    /// Inputs can not have keys if the transaction value is 0. This is useful
    /// for non-monetary transactions to announce information to the mint like
    /// incoming LN contract offers.
    #[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
    pub enum Input {
        // TODO: maybe treat every note as a seperate input?
        Mint(<fedimint_mint_client::MintModuleTypes as ModuleCommon>::Input),
        Wallet(<<fedimint_wallet::Wallet as ServerModule>::Common as ModuleCommon>::Input),
        LN(<<fedimint_ln::Lightning as ServerModule>::Common as ModuleCommon>::Input),
    }

    // TODO: check if clippy is right
    #[allow(clippy::large_enum_variant)]
    #[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
    pub enum Output {
        Mint(<fedimint_mint_client::MintModuleTypes as ModuleCommon>::Output),
        Wallet(<<fedimint_wallet::Wallet as ServerModule>::Common as ModuleCommon>::Output),
        LN(<<fedimint_ln::Lightning as ServerModule>::Common as ModuleCommon>::Output),
    }

    impl Transaction {
        /// Hash of the transaction (excluding the signature).
        ///
        /// Transaction signature commits to this hash.
        /// To generate it without already having a signature use
        /// [`Self::tx_hash_from_parts`].
        pub fn tx_hash(&self) -> TransactionId {
            Self::tx_hash_from_parts(&self.inputs, &self.outputs)
        }

        /// Generate the transaction hash.
        pub fn tx_hash_from_parts(inputs: &[Input], outputs: &[Output]) -> TransactionId {
            let erased_inputs = inputs
                .iter()
                .map(|input| match input.clone() {
                    Input::Mint(i) => DynInput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_MINT, i),
                    Input::Wallet(i) => {
                        DynInput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_WALLET, i)
                    }
                    Input::LN(i) => DynInput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_LN, i),
                })
                .collect::<Vec<DynInput>>();
            let erased_outputs = outputs
                .iter()
                .map(|output| match output.clone() {
                    Output::Mint(o) => DynOutput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_MINT, o),
                    Output::Wallet(o) => {
                        DynOutput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_WALLET, o)
                    }
                    Output::LN(o) => DynOutput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_LN, o),
                })
                .collect::<Vec<DynOutput>>();

            let mut engine = TransactionId::engine();
            erased_inputs
                .consensus_encode(&mut engine)
                .expect("write to hash engine can't fail");
            erased_outputs
                .consensus_encode(&mut engine)
                .expect("write to hash engine can't fail");
            TransactionId::from_engine(engine)
        }

        /// Validate the aggregated Schnorr Signature signed over the tx_hash
        pub fn validate_signature(
            &self,
            keys: impl Iterator<Item = XOnlyPublicKey>,
        ) -> Result<(), TransactionError> {
            let keys = keys.collect::<Vec<_>>();

            // If there are no keys from inputs there are no inputs to protect from
            // re-binding. This behavior is useful for non-monetary transactions
            // that just announce something, like LN incoming contract offers.
            if keys.is_empty() {
                return Ok(());
            }

            // Unless keys were empty we require a signature
            let signature = self
                .signature
                .as_ref()
                .ok_or(TransactionError::MissingSignature)?;

            let agg_pub_key = agg_keys(&keys);
            let msg = secp256k1_zkp::Message::from_slice(&self.tx_hash()[..])
                .expect("hash has right length");

            if secp256k1_zkp::global::SECP256K1
                .verify_schnorr(signature, &msg, &agg_pub_key)
                .is_ok()
            {
                Ok(())
            } else {
                Err(TransactionError::InvalidSignature)
            }
        }

        pub fn into_type_erased(self) -> fedimint_core::transaction::Transaction {
            fedimint_core::transaction::Transaction {
                inputs: self
                    .inputs
                    .into_iter()
                    .map(|input| match input {
                        Input::Mint(input) => {
                            DynInput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_MINT, input)
                        }
                        Input::Wallet(input) => {
                            DynInput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_WALLET, input)
                        }
                        Input::LN(input) => {
                            DynInput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_LN, input)
                        }
                    })
                    .collect(),
                outputs: self
                    .outputs
                    .into_iter()
                    .map(|output| match output {
                        Output::Mint(output) => {
                            DynOutput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_MINT, output)
                        }
                        Output::Wallet(output) => {
                            DynOutput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_WALLET, output)
                        }
                        Output::LN(output) => {
                            DynOutput::from_typed(LEGACY_HARDCODED_INSTANCE_ID_LN, output)
                        }
                    })
                    .collect(),
                signature: self.signature,
            }
        }
    }
}

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
        C: AsRef<ClientConfig> + Clone + Send,
    {
        self.input_amount(client) - self.output_amount(client) - self.fee_amount(client)
    }

    /// Builds and signs the final transaction with correct change
    pub async fn build<C: AsRef<ClientConfig> + Clone + Send, R: RngCore + CryptoRng>(
        self,
        client: &Client<C>,
        dbtx: &mut DatabaseTransaction<'_>,
        rng: R,
    ) -> Transaction {
        let change =
            self.input_amount(client) - self.output_amount(client) - self.fee_amount(client);
        self.build_with_change(
            client.mint_client(),
            dbtx,
            rng,
            vec![change],
            &client.context.secp,
        )
        .await
    }

    /// Builds and signs the final transaction with exact change amounts
    /// WARNING - could result in an unbalanced tx that will be rejected by the
    /// federation
    pub async fn build_with_change<R: RngCore + CryptoRng>(
        mut self,
        change_module: MintClient,
        dbtx: &mut DatabaseTransaction<'_>,
        mut rng: R,
        change: Vec<Amount>,
        secp: &Secp256k1<secp256k1_zkp::All>,
    ) -> Transaction {
        change_module
            .finalize_change(&mut self.tx, dbtx, change)
            .await;

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
        C: AsRef<ClientConfig> + Clone + Send,
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
        C: AsRef<ClientConfig> + Clone + Send + 'a,
    {
        self.tx.outputs.iter().map(|o| match o {
            Output::Mint(output) => client.mint_client().output_amount(output),
            Output::Wallet(output) => client.wallet_client().output_amount(output),
            Output::LN(output) => client.ln_client().output_amount(output),
        })
    }

    fn input_amount<C>(&self, client: &Client<C>) -> Amount
    where
        C: AsRef<ClientConfig> + Send + Clone,
    {
        self.input_amount_iter(client)
            .map(|amount_info| amount_info.amount)
            .sum()
    }

    fn output_amount<C>(&self, client: &Client<C>) -> Amount
    where
        C: AsRef<ClientConfig> + Send + Clone,
    {
        self.output_amount_iter(client)
            .map(|amount_info| amount_info.amount)
            .sum()
    }

    fn fee_amount<C>(&self, client: &Client<C>) -> Amount
    where
        C: AsRef<ClientConfig> + Send + Clone,
    {
        self.input_amount_iter(client)
            .chain(self.output_amount_iter(client))
            .map(|amount_info| amount_info.fee)
            .sum()
    }
}
