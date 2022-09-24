use crate::config::FeeConsensus;
use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::XOnlyPublicKey;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{Amount, FederationModule, TransactionId};
use rand::Rng;
use secp256k1_zkp::{schnorr, Secp256k1, Signing, Verification};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An atomic value transfer operation within the Fedimint system and consensus
///
/// The mint enforces that the total value of the outputs equals the total value of the inputs, to prevent creating funds out of thin air. In some cases, the value of the inputs and outputs can both be 0 e.g. when creating an offer to a Lightning Gateway.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
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
/// The user must be able to produce an aggregate Schnorr signature for the transaction over all the inputs.
///
/// Each input has an associated secret/public key pair.
/// Inputs can not have keys if the transaction value is 0. This is useful for non-monetary transactions to announce information to the mint like incoming LN contract offers.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum Input {
    // TODO: maybe treat every coin as a seperate input?
    Mint(<fedimint_mint::Mint as FederationModule>::TxInput),
    Wallet(<fedimint_wallet::Wallet as FederationModule>::TxInput),
    LN(<fedimint_ln::LightningModule as FederationModule>::TxInput),
}

// TODO: check if clippy is right
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum Output {
    Mint(<fedimint_mint::Mint as FederationModule>::TxOutput),
    Wallet(<fedimint_wallet::Wallet as FederationModule>::TxOutput),
    LN(<fedimint_ln::LightningModule as FederationModule>::TxOutput),
}

/// Common properties of value transfer for inputs and outputs.
///
/// Input and output both define amount transferred and fee. The fee is paid to the federation.
pub trait TransactionItem {
    /// The amount before fees represented by the in/output
    fn amount(&self) -> fedimint_api::Amount;

    /// The fee that will be charged for this in/output
    fn fee(&self, fee_consensus: &FeeConsensus) -> fedimint_api::Amount;
}

impl TransactionItem for Input {
    fn amount(&self) -> Amount {
        match self {
            Input::Mint(coins) => coins.total_amount(),
            Input::Wallet(peg_in) => Amount::from_sat(peg_in.tx_output().value),
            Input::LN(input) => input.amount,
        }
    }

    fn fee(&self, fee_consensus: &FeeConsensus) -> Amount {
        match self {
            Input::Mint(coins) => fee_consensus.mint.coin_spend_abs * (coins.tier_count() as u64),
            Input::Wallet(_) => fee_consensus.wallet.peg_in_abs,
            Input::LN(_) => fee_consensus.ln.contract_input,
        }
    }
}

impl TransactionItem for Output {
    fn amount(&self) -> Amount {
        match self {
            Output::Mint(coins) => coins.total_amount(),
            Output::Wallet(peg_out) => (peg_out.amount + peg_out.fees.amount()).into(),
            Output::LN(fedimint_ln::ContractOrOfferOutput::Contract(output)) => output.amount,
            Output::LN(fedimint_ln::ContractOrOfferOutput::Offer(_)) => Amount::ZERO,
            Output::LN(fedimint_ln::ContractOrOfferOutput::CancelOutgoing { .. }) => Amount::ZERO,
        }
    }

    fn fee(&self, fee_consensus: &FeeConsensus) -> Amount {
        match self {
            Output::Mint(coins) => fee_consensus.mint.coin_spend_abs * (coins.tier_count() as u64),
            Output::Wallet(_) => fee_consensus.wallet.peg_out_abs,
            Output::LN(fedimint_ln::ContractOrOfferOutput::Contract(_)) => {
                fee_consensus.ln.contract_output
            }
            // TODO: maybe not hard code this? otoh non-zero fee offers make onboarding kinda impossible
            Output::LN(fedimint_ln::ContractOrOfferOutput::Offer(_)) => Amount::ZERO,
            Output::LN(fedimint_ln::ContractOrOfferOutput::CancelOutgoing { .. }) => Amount::ZERO,
        }
    }
}

impl Transaction {
    pub fn in_amount(&self) -> Amount {
        self.inputs
            .iter()
            .map(TransactionItem::amount)
            .sum::<Amount>()
    }

    pub fn out_amount(&self) -> Amount {
        self.outputs
            .iter()
            .map(TransactionItem::amount)
            .sum::<Amount>()
    }

    /// The sum of fees across all inputs and outputs.
    pub fn fee_amount(&self, fee_consensus: &FeeConsensus) -> Amount {
        self.inputs
            .iter()
            .map(|input| input.fee(fee_consensus))
            .sum::<Amount>()
            + self
                .outputs
                .iter()
                .map(|output| output.fee(fee_consensus))
                .sum::<Amount>()
    }

    /// Validate amounts balance.
    ///
    /// A valid transaction maintains 1:1 ratio of assets to liabilities.

    // TODO: better named validate_amounts?
    pub fn validate_funding(&self, fee_consensus: &FeeConsensus) -> Result<(), TransactionError> {
        let in_amount = self.in_amount();
        let out_amount = self.out_amount();
        let fee_amount = self.fee_amount(fee_consensus);

        if in_amount == (out_amount + fee_amount) {
            Ok(())
        } else {
            Err(TransactionError::UnbalancedTransaction {
                inputs: in_amount,
                outputs: out_amount,
                fee: fee_amount,
            })
        }
    }

    /// Hash of the transaction (excluding the signature).
    ///
    /// Transaction signature commits to this hash.
    /// To generate it without already having a signature use [`Self::tx_hash_from_parts`].
    pub fn tx_hash(&self) -> TransactionId {
        Self::tx_hash_from_parts(&self.inputs, &self.outputs)
    }

    /// Generate the transaction hash.
    pub fn tx_hash_from_parts(inputs: &[Input], outputs: &[Output]) -> TransactionId {
        let mut engine = TransactionId::engine();
        inputs
            .consensus_encode(&mut engine)
            .expect("write to hash engine can't fail");
        outputs
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

        // If there are no keys from inputs there are no inputs to protect from re-binding. This
        // behavior is useful for non-monetary transactions that just announce something, like LN
        // incoming contract offers.
        if keys.is_empty() {
            return Ok(());
        }

        // Unless keys were empty we require a signature
        let signature = self
            .signature
            .as_ref()
            .ok_or(TransactionError::MissingSignature)?;

        let agg_pub_key = agg_keys(&keys);
        let msg =
            secp256k1_zkp::Message::from_slice(&self.tx_hash()[..]).expect("hash has right length");

        if secp256k1_zkp::global::SECP256K1
            .verify_schnorr(signature, &msg, &agg_pub_key)
            .is_ok()
        {
            Ok(())
        } else {
            Err(TransactionError::InvalidSignature)
        }
    }
}

/// Aggregate a stream of public keys.
///
/// Be aware that the order of the keys matters for the aggregation result.
/// # Panics
/// * If the `keys` iterator does not yield any keys
pub fn agg_keys(keys: &[XOnlyPublicKey]) -> XOnlyPublicKey {
    new_pre_session(keys, secp256k1_zkp::SECP256K1).agg_pk()
}

/// Precompute a combined public key and the hash of the given public keys for Musig2.
fn new_pre_session<C>(
    keys: &[XOnlyPublicKey],
    ctx: &Secp256k1<C>,
) -> secp256k1_zkp::MusigKeyAggCache
where
    C: Signing + Verification,
{
    assert!(
        !keys.is_empty(),
        "Must supply more than 0 keys for aggregation"
    );
    secp256k1_zkp::MusigKeyAggCache::new(ctx, keys)
}

/// Create an aggregated signature over the `msg`
pub fn agg_sign<R, C, M>(
    keys: &[bitcoin::KeyPair],
    msg: M,
    ctx: &Secp256k1<C>,
    mut rng: R,
) -> schnorr::Signature
where
    R: rand::RngCore + rand::CryptoRng,
    C: Signing + Verification,
    M: Into<secp256k1_zkp::Message>,
{
    let msg = msg.into();
    let pub_keys = keys.iter().map(|key| key.public_key()).collect::<Vec<_>>();
    let pre_session = new_pre_session(&pub_keys, ctx);

    let session_id: [u8; 32] = rng.gen();
    let (sec_nonces, pub_nonces): (Vec<_>, Vec<_>) = keys
        .iter()
        .map(|key| {
            // FIXME: upstream
            pre_session
                .nonce_gen(ctx, session_id, key.into(), msg, None)
                .expect("should not fail for valid inputs (ensured by type system)")
        })
        .unzip();

    let agg_nonce = secp256k1_zkp::MusigAggNonce::new(ctx, &pub_nonces);

    let session = secp256k1_zkp::MusigSession::new(ctx, &pre_session, agg_nonce, msg, None);

    let partial_sigs = sec_nonces
        .into_iter()
        .zip(keys.iter())
        .map(|(mut nonce, key)| {
            session
                .partial_sign(ctx, &mut nonce, key, &pre_session)
                .expect("Should not fail for cooperative protocol runs")
        })
        .collect::<Vec<_>>();

    session.partial_sig_agg(&partial_sigs)
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("The transaction is unbalanced (in={inputs}, out={outputs}, fee={fee})")]
    UnbalancedTransaction {
        inputs: Amount,
        outputs: Amount,
        fee: Amount,
    },
    #[error("The transaction's signature is invalid")]
    InvalidSignature,
    #[error("The transaction did not have a signature although there were inputs to be signed")]
    MissingSignature,
}
