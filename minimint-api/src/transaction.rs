use crate::encoding::{Decodable, Encodable};
use crate::{Amount, Coin, Coins, FeeConsensus, PegInProof, TransactionId};
use bitcoin_hashes::Hash as BitcoinHash;
use rand::Rng;
use secp256k1_zkp::{schnorrsig, Secp256k1, Signing};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub signature: schnorrsig::Signature,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum Input {
    // TODO: maybe treat every coin as a seperate input?
    Coins(Coins<Coin>),
    PegIn(Box<PegInProof>),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum Output {
    Coins(Coins<BlindToken>),
    PegOut(PegOut),
    // TODO: lightning integration goes here
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PegOut {
    pub recipient: bitcoin::Address,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct BlindToken(pub tbs::BlindedMessage);

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct OutPoint {
    pub txid: TransactionId,
    pub out_idx: u64,
}

/// Common properties of transaction in- and outputs
pub trait TransactionItem {
    /// The amount before fees represented by the in/output
    fn amount(&self) -> crate::Amount;

    /// The fee that will be charged for this in/output
    fn fee(&self, fee_consensus: &FeeConsensus) -> crate::Amount;
}

impl Input {
    // TODO: probably make this a single returned key once coins are separate inputs
    /// Returns an iterator over all the keys that need to sign the transaction for the input to
    /// be valid.
    fn authorization_keys<'a>(&'a self) -> Box<dyn Iterator<Item = schnorrsig::PublicKey> + 'a> {
        match self {
            Input::Coins(coins) => Box::new(coins.iter().map(|(_, coin)| *coin.spend_key())),
            Input::PegIn(proof) => Box::new(std::iter::once(*proof.tweak_contract_key())),
        }
    }
}

impl TransactionItem for Input {
    fn amount(&self) -> Amount {
        match self {
            Input::Coins(coins) => coins.amount(),
            Input::PegIn(peg_in) => Amount::from_sat(peg_in.tx_output().value),
        }
    }

    fn fee(&self, fee_consensus: &FeeConsensus) -> Amount {
        match self {
            Input::Coins(coins) => fee_consensus.fee_coin_spend_abs * (coins.coins.len() as u64),
            Input::PegIn(_) => fee_consensus.fee_peg_in_abs,
        }
    }
}

impl TransactionItem for Output {
    fn amount(&self) -> Amount {
        match self {
            Output::Coins(coins) => coins.amount(),
            Output::PegOut(peg_out) => peg_out.amount.into(),
        }
    }

    fn fee(&self, fee_consensus: &FeeConsensus) -> Amount {
        match self {
            Output::Coins(coins) => fee_consensus.fee_coin_spend_abs * (coins.coins.len() as u64),
            Output::PegOut(_) => fee_consensus.fee_peg_out_abs,
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

    pub fn validate_signature(&self) -> Result<(), TransactionError> {
        let ctx = secp256k1_zkp::global::SECP256K1;
        let agg_pub_key = agg_keys(
            self.inputs
                .iter()
                .flat_map(|input| input.authorization_keys()),
        );
        let msg =
            secp256k1_zkp::Message::from_slice(&self.tx_hash()[..]).expect("hash has right length");

        if ctx
            .schnorrsig_verify(&self.signature, &msg, &agg_pub_key)
            .is_ok()
        {
            Ok(())
        } else {
            Err(TransactionError::InvalidSignature)
        }
    }
}

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.out_idx)
    }
}

/// Aggregates a stream of public keys. Be aware that the order of the keys matters for the
/// aggregation result.
///
/// # Panics
/// * If the `keys` iterator does not yield any keys
pub fn agg_keys<I>(keys: I) -> schnorrsig::PublicKey
where
    I: Iterator<Item = schnorrsig::PublicKey>,
{
    new_pre_session(keys, &secp256k1_zkp::SECP256K1).agg_pk()
}

fn new_pre_session<I, C>(keys: I, ctx: &Secp256k1<C>) -> secp256k1_zkp::MusigPreSession
where
    I: Iterator<Item = schnorrsig::PublicKey>,
    C: Signing,
{
    let keys = keys.collect::<Vec<_>>();
    assert!(
        !keys.is_empty(),
        "Must supply more than 0 keys for aggregation"
    );

    secp256k1_zkp::MusigPreSession::new(ctx, &keys).expect("more than zero were supplied")
}

pub fn agg_sign<I, R, C, M>(
    keys: I,
    msg: M,
    ctx: &Secp256k1<C>,
    mut rng: R,
) -> schnorrsig::Signature
where
    I: Iterator<Item = schnorrsig::KeyPair>,
    R: rand::RngCore + rand::CryptoRng,
    C: Signing,
    M: Into<secp256k1_zkp::Message>,
{
    let keys = keys.collect::<Vec<_>>();
    let msg = msg.into();
    let pre_session = new_pre_session(
        keys.iter()
            .map(|key| schnorrsig::PublicKey::from_keypair(ctx, key)),
        ctx,
    );

    let session_id: [u8; 32] = rng.gen();
    let (sec_nonces, pub_nonces): (Vec<_>, Vec<_>) = keys
        .iter()
        .map(|key| {
            // FIXME: upstream
            pre_session
                .nonce_gen(ctx, &session_id, &key, &msg, None)
                .expect("should not fail for valid inputs (ensured by type system)")
        })
        .unzip();

    let agg_nonce = secp256k1_zkp::MusigAggNonce::new(&ctx, &pub_nonces)
        .expect("Should not fail for cooperative protocol runs");

    let session = pre_session
        .nonce_process(ctx, &agg_nonce, &msg, None)
        .expect("Should not fail for cooperative protocol runs");

    let partial_sigs = sec_nonces
        .into_iter()
        .zip(keys.iter())
        .map(|(mut nonce, key)| {
            session
                .partial_sign(ctx, &mut nonce, &key, &pre_session)
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
}
