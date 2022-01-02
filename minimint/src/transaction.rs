use crate::config::FeeConsensus;
use bitcoin::hashes::Hash as BitcoinHash;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::{Amount, FederationModule, TransactionId};
use rand::Rng;
use secp256k1_zkp::{schnorrsig, Secp256k1, Signing};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub signature: Option<schnorrsig::Signature>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum Input {
    // TODO: maybe treat every coin as a seperate input?
    Mint(<minimint_mint::Mint as FederationModule>::TxInput),
    Wallet(<minimint_wallet::Wallet as FederationModule>::TxInput),
    LN(<minimint_ln::LightningModule as FederationModule>::TxInput),
}

// TODO: check if clippy is right
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum Output {
    Mint(<minimint_mint::Mint as FederationModule>::TxOutput),
    Wallet(<minimint_wallet::Wallet as FederationModule>::TxOutput),
    LN(<minimint_ln::LightningModule as FederationModule>::TxOutput),
}

/// Common properties of transaction in- and outputs
pub trait TransactionItem {
    /// The amount before fees represented by the in/output
    fn amount(&self) -> minimint_api::Amount;

    /// The fee that will be charged for this in/output
    fn fee(&self, fee_consensus: &FeeConsensus) -> minimint_api::Amount;
}

impl TransactionItem for Input {
    fn amount(&self) -> Amount {
        match self {
            Input::Mint(coins) => coins.amount(),
            Input::Wallet(peg_in) => Amount::from_sat(peg_in.tx_output().value),
            Input::LN(input) => input.amount,
        }
    }

    fn fee(&self, fee_consensus: &FeeConsensus) -> Amount {
        match self {
            Input::Mint(coins) => fee_consensus.fee_coin_spend_abs * (coins.coins.len() as u64),
            Input::Wallet(_) => fee_consensus.fee_peg_in_abs,
            Input::LN(_) => fee_consensus.fee_contract_input,
        }
    }
}

impl TransactionItem for Output {
    fn amount(&self) -> Amount {
        match self {
            Output::Mint(coins) => coins.amount(),
            Output::Wallet(peg_out) => peg_out.amount.into(),
            Output::LN(minimint_ln::ContractOrOfferOutput::Contract(output)) => output.amount,
            Output::LN(minimint_ln::ContractOrOfferOutput::Offer(_)) => Amount::ZERO,
        }
    }

    fn fee(&self, fee_consensus: &FeeConsensus) -> Amount {
        match self {
            Output::Mint(coins) => fee_consensus.fee_coin_spend_abs * (coins.coins.len() as u64),
            Output::Wallet(_) => fee_consensus.fee_peg_out_abs,
            Output::LN(minimint_ln::ContractOrOfferOutput::Contract(_)) => {
                fee_consensus.fee_contract_output
            }
            // TODO: maybe not hard code this? otoh non-zero fee offers make onboarding kinda impossible
            Output::LN(minimint_ln::ContractOrOfferOutput::Offer(_)) => Amount::ZERO,
        }
    }
}

impl Transaction {
    pub fn validate_funding(&self, fee_consensus: &FeeConsensus) -> Result<(), TransactionError> {
        let in_amount = self
            .inputs
            .iter()
            .map(TransactionItem::amount)
            .sum::<Amount>();
        let out_amount = self
            .outputs
            .iter()
            .map(TransactionItem::amount)
            .sum::<Amount>();
        let fee_amount = self
            .inputs
            .iter()
            .map(|input| input.fee(fee_consensus))
            .sum::<Amount>()
            + self
                .outputs
                .iter()
                .map(|output| output.fee(fee_consensus))
                .sum::<Amount>();

        if in_amount >= (out_amount + fee_amount) {
            Ok(())
        } else {
            Err(TransactionError::InsufficientlyFunded {
                inputs: in_amount,
                outputs: out_amount,
                fee: fee_amount,
            })
        }
    }

    /// Hash the transaction excluding the signature. This hash is what the signature inside the
    /// transaction commits to. To generate it without already having a signature use [tx_hash_from_parts].
    pub fn tx_hash(&self) -> TransactionId {
        Self::tx_hash_from_parts(&self.inputs, &self.outputs)
    }

    /// Generates the transaction hash without constructing the transaction (which would require a
    /// signature).
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

    pub fn validate_signature(
        &self,
        keys: impl Iterator<Item = schnorrsig::PublicKey>,
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
            .schnorrsig_verify(signature, &msg, &agg_pub_key)
            .is_ok()
        {
            Ok(())
        } else {
            Err(TransactionError::InvalidSignature)
        }
    }
}

/// Aggregates a stream of public keys. Be aware that the order of the keys matters for the
/// aggregation result.
///
/// # Panics
/// * If the `keys` iterator does not yield any keys
pub fn agg_keys(keys: &[schnorrsig::PublicKey]) -> schnorrsig::PublicKey {
    new_pre_session(keys, secp256k1_zkp::SECP256K1).agg_pk()
}

fn new_pre_session<C>(
    keys: &[schnorrsig::PublicKey],
    ctx: &Secp256k1<C>,
) -> secp256k1_zkp::MusigPreSession
where
    C: Signing,
{
    assert!(
        !keys.is_empty(),
        "Must supply more than 0 keys for aggregation"
    );

    secp256k1_zkp::MusigPreSession::new(ctx, keys).expect("more than zero were supplied")
}

pub fn agg_sign<R, C, M>(
    keys: &[schnorrsig::KeyPair],
    msg: M,
    ctx: &Secp256k1<C>,
    mut rng: R,
) -> schnorrsig::Signature
where
    R: rand::RngCore + rand::CryptoRng,
    C: Signing,
    M: Into<secp256k1_zkp::Message>,
{
    let msg = msg.into();
    let pub_keys = keys
        .iter()
        .map(|key| schnorrsig::PublicKey::from_keypair(ctx, key))
        .collect::<Vec<_>>();
    let pre_session = new_pre_session(&pub_keys, ctx);

    let session_id: [u8; 32] = rng.gen();
    let (sec_nonces, pub_nonces): (Vec<_>, Vec<_>) = keys
        .iter()
        .map(|key| {
            // FIXME: upstream
            pre_session
                .nonce_gen(ctx, &session_id, key, &msg, None)
                .expect("should not fail for valid inputs (ensured by type system)")
        })
        .unzip();

    let agg_nonce = secp256k1_zkp::MusigAggNonce::new(ctx, &pub_nonces)
        .expect("Should not fail for cooperative protocol runs");

    let session = pre_session
        .nonce_process(ctx, &agg_nonce, &msg, None)
        .expect("Should not fail for cooperative protocol runs");

    let partial_sigs = sec_nonces
        .into_iter()
        .zip(keys.iter())
        .map(|(mut nonce, key)| {
            session
                .partial_sign(ctx, &mut nonce, key, &pre_session)
                .expect("Should not fail for cooperative protocol runs")
        })
        .collect::<Vec<_>>();

    session
        .partial_sig_agg(ctx, &partial_sigs)
        .expect("Should not fail for cooperative protocol runs")
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("The transaction is insufficiently funded (in={inputs}, out={outputs}, fee={fee})")]
    InsufficientlyFunded {
        inputs: Amount,
        outputs: Amount,
        fee: Amount,
    },
    #[error("The transaction's signature is invalid")]
    InvalidSignature,
    #[error("The transaction did not have a signature although there were inputs to be signed")]
    MissingSignature,
}
