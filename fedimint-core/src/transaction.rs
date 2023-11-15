use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::XOnlyPublicKey;
use bitcoin_hashes::hex::ToHex;
use fedimint_core::core::{DynInput, DynOutput};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::{Amount, TransactionId};
use rand::Rng;
use secp256k1_zkp::{schnorr, Secp256k1, Signing, Verification};
use thiserror::Error;

use crate::core::{DynInputError, DynOutputError};

/// An atomic value transfer operation within the Fedimint system and consensus
///
/// The mint enforces that the total value of the outputs equals the total value
/// of the inputs, to prevent creating funds out of thin air. In some cases, the
/// value of the inputs and outputs can both be 0 e.g. when creating an offer to
/// a Lightning Gateway.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct Transaction {
    /// [`DynInput`]s consumed by the transaction
    pub inputs: Vec<DynInput>,
    /// [`DynOutput`]s created as a result of the transaction
    pub outputs: Vec<DynOutput>,
    /// No defined meaning, can be used to send the otherwise exactly same
    /// transaction multiple times if the module inputs and outputs don't
    /// introduce enough entropy.
    ///
    /// In the future the nonce can be used for grinding a tx hash that fulfills
    /// certain PoW requirements.
    pub nonce: [u8; 8],
    /// Aggregated MuSig2 signature over all the public keys of the inputs
    pub signature: Option<schnorr::Signature>,
}

pub type SerdeTransaction = SerdeModuleEncoding<Transaction>;

impl Transaction {
    /// Hash of the transaction (excluding the signature).
    ///
    /// Transaction signature commits to this hash.
    /// To generate it without already having a signature use
    /// [`Self::tx_hash_from_parts`].
    pub fn tx_hash(&self) -> TransactionId {
        Self::tx_hash_from_parts(&self.inputs, &self.outputs, self.nonce)
    }

    /// Generate the transaction hash.
    pub fn tx_hash_from_parts(
        inputs: &[DynInput],
        outputs: &[DynOutput],
        nonce: [u8; 8],
    ) -> TransactionId {
        let mut engine = TransactionId::engine();
        inputs
            .consensus_encode(&mut engine)
            .expect("write to hash engine can't fail");
        outputs
            .consensus_encode(&mut engine)
            .expect("write to hash engine can't fail");
        nonce
            .consensus_encode(&mut engine)
            .expect("write to hash engine can't fail");
        TransactionId::from_engine(engine)
    }

    /// Validate the aggregated Schnorr Signature signed over the `tx_hash`
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
        let msg =
            secp256k1_zkp::Message::from_slice(&self.tx_hash()[..]).expect("hash has right length");

        if secp256k1_zkp::global::SECP256K1
            .verify_schnorr(signature, &msg, &agg_pub_key)
            .is_ok()
        {
            Ok(())
        } else {
            Err(TransactionError::InvalidSignature {
                tx: self.consensus_encode_to_hex().expect("Can't fail"),
                hash: self.tx_hash().to_hex(),
                sig: signature.consensus_encode_to_hex().expect("Can't fail"),
                key: agg_pub_key.consensus_encode_to_hex().expect("Can't fail"),
            })
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

/// Precompute a combined public key and the hash of the given public keys for
/// Musig2.
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
    let pub_keys = keys
        .iter()
        .map(|key| key.x_only_public_key().0)
        .collect::<Vec<_>>();
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

#[derive(Debug, Error, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum TransactionError {
    #[error("The transaction is unbalanced (in={inputs}, out={outputs}, fee={fee})")]
    UnbalancedTransaction {
        inputs: Amount,
        outputs: Amount,
        fee: Amount,
    },
    #[error("The transaction's signature is invalid: tx={tx}, hash={hash}, sig={sig}, key={key}")]
    InvalidSignature {
        tx: String,
        hash: String,
        sig: String,
        key: String,
    },
    #[error("The transaction did not have a signature although there were inputs to be signed")]
    MissingSignature,
    #[error("The transaction had an invalid input")]
    Input(DynInputError),
    #[error("The transaction had an invalid output")]
    Output(DynOutputError),
}
