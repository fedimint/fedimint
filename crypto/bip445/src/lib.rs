//! # Threshold Schnorr Signatures
//!
//! This library implements the FROST threshold signature scheme as specified
//! in BIP 445 over secp256k1, producing BIP340 signatures for use with
//! taproot. The implementation is validated against the BIP 445 test vectors.
//!
//! Signing runs in two broadcast rounds among the signing set: exchange of
//! the public nonce pairs and exchange of the signature shares. The single
//! binding coefficient ties every signature share to the exact signing set,
//! nonce set and message, which makes the scheme secure under concurrent
//! signing sessions without a nonce commitment round.
//!
//! BIP 445's accumulated tweak context is deliberately omitted: callers
//! tweak the secret key shares and the aggregate public key externally,
//! which is equivalent since additive tweaks pass through Lagrange
//! interpolation.

use std::collections::BTreeMap;

use bitcoin::hashes::{Hash as BitcoinHash, HashEngine, sha256};
use fedimint_core::encoding::{Decodable, Encodable};
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand_chacha::ChaChaRng;
use secp256k1::{Message, Parity, PublicKey, SECP256K1, Scalar, SecretKey, constants, schnorr};
use serde::{Deserialize, Serialize};

const TAG_NONCECOEF: &[u8] = b"BIP0445/noncecoef";
const TAG_CHALLENGE: &[u8] = b"BIP0340/challenge";

/// Our share of the threshold secret key.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct SecretKeyShare(pub SecretKey);

/// The public key corresponding to one peer's secret key share.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct PublicKeyShare(pub PublicKey);

/// The public key of the federation; its x-only form is the BIP340 public
/// key our signatures verify under.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct AggregatePublicKey(pub PublicKey);

/// The secret nonce pair for one signing session. Signing two different
/// sessions with the same nonce leaks the secret key share.
#[derive(Debug)]
pub struct SecretNonce(SecretKey, SecretKey);

/// The public nonce pair of one peer for one signing session.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct PublicNonce(pub PublicKey, pub PublicKey);

/// One peer's additive share of the final signature's response scalar.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub struct SignatureShare(pub SecretKey);

impl std::hash::Hash for SignatureShare {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0.secret_bytes());
    }
}

/// Derives the public key share for a secret key share.
pub fn derive_pk_share(sks: &SecretKeyShare) -> PublicKeyShare {
    PublicKeyShare(sks.0.public_key(SECP256K1))
}

/// Generates a fresh random nonce pair for one signing session.
pub fn generate_nonce() -> (SecretNonce, PublicNonce) {
    let nonce = SecretNonce(SecretKey::new(&mut OsRng), SecretKey::new(&mut OsRng));

    let public_nonce = derive_public_nonce(&nonce);

    (nonce, public_nonce)
}

/// Derives the nonce pair for one signing session from a seed. The caller
/// must guarantee that a seed is used for at most one signing session, since
/// signing two different sessions with the same nonce leaks the secret key
/// share.
pub fn derive_nonce(seed: &[u8; 32]) -> SecretNonce {
    let mut rng = ChaChaRng::from_seed(*seed);

    SecretNonce(SecretKey::new(&mut rng), SecretKey::new(&mut rng))
}

/// Derives the public nonce pair for a secret nonce pair.
pub fn derive_public_nonce(nonce: &SecretNonce) -> PublicNonce {
    PublicNonce(nonce.0.public_key(SECP256K1), nonce.1.public_key(SECP256K1))
}

/// Creates our signature share for the message. The keys of the nonces define
/// the signing set, which has to contain our identity. The secret nonce is
/// consumed since signing twice with the same nonce leaks our secret key
/// share.
/// # Panics
/// If nonces is empty
pub fn sign_share(
    msg: [u8; 32],
    sks: &SecretKeyShare,
    nonce: SecretNonce,
    nonces: &BTreeMap<u64, PublicNonce>,
    identity: u64,
    pk: &AggregatePublicKey,
) -> SignatureShare {
    let (binding, group_nonce, challenge) = session_values(&msg, nonces, pk);

    let lambda = lagrange_multiplier(nonces, identity);

    // BIP340 verifies against the even-y points for the x-only aggregate
    // nonce and public key, so we sign for their negations if necessary.

    let SecretNonce(first, second) = nonce;

    let (first, second) = match group_nonce.x_only_public_key().1 {
        Parity::Even => (first, second),
        Parity::Odd => (first.negate(), second.negate()),
    };

    let sks = match pk.0.x_only_public_key().1 {
        Parity::Even => sks.0,
        Parity::Odd => sks.0.negate(),
    };

    let share = sks
        .mul_tweak(&key_scalar(&lambda))
        .expect("A product of nonzero scalars is nonzero")
        .mul_tweak(&challenge)
        .expect("The challenge is zero with negligible probability");

    let second = second
        .mul_tweak(&binding)
        .expect("The binding coefficient is zero with negligible probability");

    SignatureShare(
        first
            .add_tweak(&key_scalar(&second))
            .expect("The sum is zero with negligible probability since our nonces are random")
            .add_tweak(&key_scalar(&share))
            .expect("The sum is zero with negligible probability since our nonces are random"),
    )
}

/// Verifies a peer's signature share against its public key share and the
/// nonces of the signing set.
pub fn verify_signature_share(
    msg: [u8; 32],
    peer: u64,
    pks: &PublicKeyShare,
    share: &SignatureShare,
    nonces: &BTreeMap<u64, PublicNonce>,
    pk: &AggregatePublicKey,
) -> bool {
    let Some(nonce) = nonces.get(&peer) else {
        return false;
    };

    let (binding, group_nonce, challenge) = session_values(&msg, nonces, pk);

    let lambda = lagrange_multiplier(nonces, peer);

    let Ok(second) = nonce.1.mul_tweak(SECP256K1, &binding) else {
        return false;
    };

    let Ok(effective_nonce) = nonce.0.combine(&second) else {
        return false;
    };

    let effective_nonce = match group_nonce.x_only_public_key().1 {
        Parity::Even => effective_nonce,
        Parity::Odd => effective_nonce.negate(SECP256K1),
    };

    let pks = match pk.0.x_only_public_key().1 {
        Parity::Even => pks.0,
        Parity::Odd => pks.0.negate(SECP256K1),
    };

    let Ok(coefficient) = lambda.mul_tweak(&challenge) else {
        return false;
    };

    let Ok(share_point) = pks.mul_tweak(SECP256K1, &key_scalar(&coefficient)) else {
        return false;
    };

    let Ok(expected) = effective_nonce.combine(&share_point) else {
        return false;
    };

    share.0.public_key(SECP256K1) == expected
}

/// Combines the exact threshold of valid signature shares into a BIP340
/// signature. The responsibility of verifying the shares and supplying the
/// shares of exactly the signing set that created them lies with the caller.
/// # Panics
/// If nonces or shares is empty
pub fn aggregate_signature_shares(
    msg: [u8; 32],
    nonces: &BTreeMap<u64, PublicNonce>,
    shares: &BTreeMap<u64, SignatureShare>,
    pk: &AggregatePublicKey,
) -> schnorr::Signature {
    let (_, group_nonce, _) = session_values(&msg, nonces, pk);

    let response = shares
        .values()
        .map(|share| share.0)
        .reduce(|accumulator, share| {
            accumulator
                .add_tweak(&key_scalar(&share))
                .expect("The intermediate sums are zero with negligible probability")
        })
        .expect("We have at least one share");

    let mut bytes = [0; 64];

    bytes[..32].copy_from_slice(&group_nonce.x_only_public_key().0.serialize());
    bytes[32..].copy_from_slice(&response.secret_bytes());

    schnorr::Signature::from_slice(&bytes).expect("We provided exactly 64 bytes")
}

/// Verifies a BIP340 signature under the aggregate public key.
pub fn verify(msg: [u8; 32], signature: &schnorr::Signature, pk: &AggregatePublicKey) -> bool {
    SECP256K1
        .verify_schnorr(
            signature,
            &Message::from_digest(msg),
            &pk.0.x_only_public_key().0,
        )
        .is_ok()
}

/// The binding coefficient, group nonce and challenge of the signing session
/// defined by the message, the nonces of the signing set and the aggregate
/// public key.
fn session_values(
    msg: &[u8],
    nonces: &BTreeMap<u64, PublicNonce>,
    pk: &AggregatePublicKey,
) -> (Scalar, PublicKey, Scalar) {
    let halves = aggregate_nonce_halves(nonces);

    session_values_from(msg, &serialize_ids(nonces.keys().copied()), &halves, pk)
}

fn session_values_from(
    msg: &[u8],
    ids: &[u8],
    halves: &(Option<PublicKey>, Option<PublicKey>),
    pk: &AggregatePublicKey,
) -> (Scalar, PublicKey, Scalar) {
    let pk_xonly = pk.0.x_only_public_key().0;

    let signers = u32::try_from(ids.len() / 4).expect("The signing set size fits four bytes");

    let binding = scalar_mod_order(tagged_hash(
        TAG_NONCECOEF,
        &[
            &signers.to_be_bytes(),
            ids,
            &serialize_point(&halves.0),
            &serialize_point(&halves.1),
            &pk_xonly.serialize(),
            msg,
        ],
    ));

    let group_nonce = group_nonce(halves, &binding);

    let challenge = scalar_mod_order(tagged_hash(
        TAG_CHALLENGE,
        &[
            &group_nonce.x_only_public_key().0.serialize(),
            &pk_xonly.serialize(),
            msg,
        ],
    ));

    (binding, group_nonce, challenge)
}

/// The coordinate-wise sums of the nonce pairs of the signing set, where
/// `None` represents the point at infinity.
fn aggregate_nonce_halves(
    nonces: &BTreeMap<u64, PublicNonce>,
) -> (Option<PublicKey>, Option<PublicKey>) {
    let mut first = None;
    let mut second = None;

    for nonce in nonces.values() {
        first = add_point(first, &nonce.0);
        second = add_point(second, &nonce.1);
    }

    (first, second)
}

fn add_point(accumulator: Option<PublicKey>, point: &PublicKey) -> Option<PublicKey> {
    match accumulator {
        Some(accumulator) => accumulator.combine(point).ok(),
        None => Some(*point),
    }
}

fn serialize_point(point: &Option<PublicKey>) -> [u8; 33] {
    match point {
        Some(point) => point.serialize(),
        None => [0; 33],
    }
}

/// The group nonce `R1 + b * R2`; BIP 445 falls back to the generator if the
/// sum is the point at infinity so that a valid BIP340 signature exists.
fn group_nonce(halves: &(Option<PublicKey>, Option<PublicKey>), binding: &Scalar) -> PublicKey {
    let second = halves.1.map(|second| {
        second
            .mul_tweak(SECP256K1, binding)
            .expect("The binding coefficient is zero with negligible probability")
    });

    let sum = match (halves.0, second) {
        (Some(first), Some(second)) => first.combine(&second).ok(),
        (Some(first), None) => Some(first),
        (None, second) => second,
    };

    sum.unwrap_or_else(|| key_from_u64(1).public_key(SECP256K1))
}

/// The sorted participant identifiers, each serialized as four big-endian
/// bytes, as bound into the binding coefficient.
fn serialize_ids(ids: impl Iterator<Item = u64>) -> Vec<u8> {
    let mut ids = ids
        .map(|id| u32::try_from(id).expect("A participant identifier fits four bytes"))
        .collect::<Vec<u32>>();

    ids.sort_unstable();

    ids.into_iter().flat_map(u32::to_be_bytes).collect()
}

fn tagged_hash(tag: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    let tag = sha256::Hash::hash(tag);

    let mut engine = sha256::Hash::engine();

    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());

    for chunk in chunks {
        engine.input(chunk);
    }

    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Interprets 32 bytes as a big-endian integer modulo the curve order, as
/// required by BIP340 and BIP445. A single conditional subtraction suffices
/// since the curve order exceeds 2^255.
fn scalar_mod_order(mut bytes: [u8; 32]) -> Scalar {
    if let Ok(scalar) = Scalar::from_be_bytes(bytes) {
        return scalar;
    }

    let mut borrow = 0;

    for i in (0..32).rev() {
        let diff = i32::from(bytes[i]) - i32::from(constants::CURVE_ORDER[i]) - borrow;

        bytes[i] = diff.rem_euclid(256) as u8;
        borrow = i32::from(diff < 0);
    }

    Scalar::from_be_bytes(bytes).expect("The value is reduced below the curve order")
}

/// The Lagrange multiplier at zero for the peer's evaluation point in the
/// signing set given by the keys of the nonces.
fn lagrange_multiplier(nonces: &BTreeMap<u64, PublicNonce>, identity: u64) -> SecretKey {
    let mut numerator = key_from_u64(1);
    let mut denominator = key_from_u64(1);

    for peer in nonces.keys().copied().filter(|peer| *peer != identity) {
        numerator = numerator
            .mul_tweak(&scalar_from_u64(peer + 1))
            .expect("A product of nonzero scalars is nonzero");

        denominator = denominator
            .mul_tweak(&key_scalar(&difference(peer, identity)))
            .expect("A product of nonzero scalars is nonzero");
    }

    numerator
        .mul_tweak(&key_scalar(&invert(&denominator)))
        .expect("A product of nonzero scalars is nonzero")
}

/// The difference (a + 1) - (b + 1) of two distinct evaluation points as a
/// field element.
fn difference(a: u64, b: u64) -> SecretKey {
    if a > b {
        key_from_u64(a - b)
    } else {
        key_from_u64(b - a).negate()
    }
}

/// The modular inverse of a nonzero scalar via Fermat's little theorem, since
/// rust-secp256k1 does not expose modular inversion.
fn invert(key: &SecretKey) -> SecretKey {
    let mut exponent = constants::CURVE_ORDER;

    exponent[31] -= 2; // no borrow occurs since the order ends in 0x41

    let mut accumulator = key_from_u64(1);

    for byte in exponent {
        for bit in (0..8).rev() {
            accumulator = accumulator
                .mul_tweak(&key_scalar(&accumulator))
                .expect("A product of nonzero scalars is nonzero");

            if (byte >> bit) & 1 == 1 {
                accumulator = accumulator
                    .mul_tweak(&key_scalar(key))
                    .expect("A product of nonzero scalars is nonzero");
            }
        }
    }

    accumulator
}

fn key_scalar(key: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(key.secret_bytes()).expect("A secret key is a valid scalar")
}

fn scalar_from_u64(value: u64) -> Scalar {
    let mut bytes = [0; 32];

    bytes[24..].copy_from_slice(&value.to_be_bytes());

    Scalar::from_be_bytes(bytes).expect("A u64 is smaller than the curve order")
}

fn key_from_u64(value: u64) -> SecretKey {
    let mut bytes = [0; 32];

    bytes[24..].copy_from_slice(&value.to_be_bytes());

    SecretKey::from_slice(&bytes).expect("A nonzero u64 is a valid secret key")
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod vector_tests;
