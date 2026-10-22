//! Tests for the FROST key tweak: signatures made with tweaked shares must
//! verify under the output key of the UTXO's address, for every combination
//! of key parities the tweak steps can hit.
use std::collections::{BTreeMap, BTreeSet};

use bip445::{
    PublicKeyShare, SignatureShare, aggregate_signature_shares, derive_nonce, derive_public_nonce,
    generate_nonce, sign_share, verify_signature_share,
};
use bitcoin::hashes::{Hash, sha256};
use fedimint_core::{NumPeersExt, PeerId};
use fedimint_server_core::config::eval_poly_secp;
use fedimint_walletv2_common::config::WalletDescriptor;
use fedimint_walletv2_common::taproot::frost::FrostPolynomial;
use fedimint_walletv2_common::taproot::{descriptor_tr, nums_point, script_pubkey_for_descriptor};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use secp256k1::{Message, Parity, PublicKey, SECP256K1, Scalar, SecretKey, XOnlyPublicKey};

use super::FrostTweak;
use crate::taproot::frost::{FrostNonceSeed, signer_id, trusted_setup};

/// Federation size: large enough that signing sets of the threshold differ.
const PEERS: u16 = 7;

/// Upper bound on the iterations the parity matrix may take to see all eight
/// combinations. Each has probability 1/8 per iteration, so missing one in
/// this many happens with probability below 2^-45.
const MAX_PARITY_ITERATIONS: usize = 256;

/// The key material of a FROST federation created by the trusted dealer.
struct Federation {
    bitcoin_pks: BTreeMap<PeerId, PublicKey>,
    polynomial: FrostPolynomial,
    secret_shares: BTreeMap<PeerId, SecretKey>,
}

impl Federation {
    fn new() -> Self {
        let peers = (0..PEERS).map(PeerId::from).collect::<Vec<_>>();

        let bitcoin_pks = peers
            .iter()
            .map(|peer| (*peer, SecretKey::new(&mut OsRng).public_key(SECP256K1)))
            .collect();

        let (polynomial, secret_shares) = trusted_setup(&peers);

        Self {
            bitcoin_pks,
            polynomial,
            secret_shares,
        }
    }

    fn public_share(&self, peer: PeerId) -> PublicKey {
        eval_poly_secp(&self.polynomial.0, &peer).expect("The polynomial evaluates")
    }

    /// The tweak for `utxo_tweak`, built from the same descriptor as the
    /// wallet does.
    fn tweak(&self, utxo_tweak: &sha256::Hash) -> FrostTweak {
        let tr = descriptor_tr(
            &self.bitcoin_pks,
            utxo_tweak,
            self.polynomial.internal_key(),
        );

        FrostTweak::new(self.polynomial.aggregate_key(), utxo_tweak, &tr)
    }

    /// The output key of the UTXO's address, read from its `script_pubkey`
    /// independently of the tweak.
    fn output_key(&self, utxo_tweak: &sha256::Hash) -> XOnlyPublicKey {
        let script_pubkey = script_pubkey_for_descriptor(
            &WalletDescriptor::Frost(self.polynomial.clone()),
            &self.bitcoin_pks,
            utxo_tweak,
        );

        assert!(script_pubkey.is_p2tr());

        XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..])
            .expect("A P2TR script pubkey holds an x-only key")
    }

    /// A random signing set of threshold size.
    fn signing_set(&self) -> Vec<PeerId> {
        let peers = self.bitcoin_pks.keys().copied().collect::<Vec<_>>();

        peers
            .choose_multiple(&mut OsRng, self.bitcoin_pks.to_num_peers().threshold())
            .copied()
            .collect()
    }

    /// Signs `message` for the UTXO with `signers`, verifying every share
    /// against the signer's tweaked public key share.
    fn sign(
        &self,
        message: [u8; 32],
        utxo_tweak: &sha256::Hash,
        signers: &[PeerId],
    ) -> secp256k1::schnorr::Signature {
        let tweak = self.tweak(utxo_tweak);

        let (secret_nonces, public_nonces): (BTreeMap<_, _>, BTreeMap<_, _>) = signers
            .iter()
            .map(|peer| {
                let (secret_nonce, public_nonce) = generate_nonce();

                ((*peer, secret_nonce), (signer_id(*peer), public_nonce))
            })
            .unzip();

        let shares = secret_nonces
            .into_iter()
            .map(|(peer, secret_nonce)| {
                let share = sign_share(
                    message,
                    &tweak.secret_share(self.secret_shares[&peer]),
                    secret_nonce,
                    &public_nonces,
                    signer_id(peer),
                    tweak.aggregate(),
                );

                assert!(
                    verify_signature_share(
                        message,
                        signer_id(peer),
                        &tweak.public_share(self.public_share(peer)),
                        &share,
                        &public_nonces,
                        tweak.aggregate(),
                    ),
                    "The share of peer {peer} must verify"
                );

                (signer_id(peer), share)
            })
            .collect();

        aggregate_signature_shares(message, &public_nonces, &shares, tweak.aggregate())
    }
}

fn random_utxo_tweak() -> sha256::Hash {
    sha256::Hash::hash(&OsRng.r#gen::<[u8; 32]>())
}

/// The parities of the aggregate key `P`, of `P'` after the per-UTXO step, and
/// of the output key `Q` after the tap step, computed independently of
/// `FrostTweak`.
fn parities(federation: &Federation, utxo_tweak: &sha256::Hash) -> (Parity, Parity, Parity) {
    let aggregate_key = federation.polynomial.aggregate_key();

    let utxo_tweaked =
        PublicKey::from_x_only_public_key(federation.polynomial.internal_key(), Parity::Even)
            .add_exp_tweak(
                SECP256K1,
                &Scalar::from_be_bytes(utxo_tweak.to_byte_array())
                    .expect("Hash is within field order"),
            )
            .expect("The tweaked key is not infinity");

    (
        aggregate_key.x_only_public_key().1,
        utxo_tweaked.x_only_public_key().1,
        federation
            .tweak(utxo_tweak)
            .aggregate()
            .0
            .x_only_public_key()
            .1,
    )
}

/// Signs with random key material, UTXO tweaks and signing sets until every
/// combination of the parities of `P`, `P'` and `Q` has produced a signature
/// that verifies under the output key of the UTXO's address.
#[test]
fn signatures_verify_under_the_output_key_for_every_parity() {
    let mut seen = BTreeSet::new();

    for _ in 0..MAX_PARITY_ITERATIONS {
        let federation = Federation::new();
        let utxo_tweak = random_utxo_tweak();

        let mut message = [0; 32];
        OsRng.fill_bytes(&mut message);

        let signature = federation.sign(message, &utxo_tweak, &federation.signing_set());

        SECP256K1
            .verify_schnorr(
                &signature,
                &Message::from_digest(message),
                &federation.output_key(&utxo_tweak),
            )
            .expect("The signature verifies under the output key of the address");

        let (p, p_utxo, q) = parities(&federation, &utxo_tweak);

        seen.insert((p as u8, p_utxo as u8, q as u8));

        if seen.len() == 8 {
            return;
        }
    }

    panic!("Only saw the parity combinations {seen:?}");
}

/// The tweak must refuse a descriptor whose output key it doesn't produce.
#[test]
#[should_panic(expected = "The tweaked FROST key must be the output key")]
fn tweak_rejects_a_foreign_descriptor() {
    let federation = Federation::new();
    let utxo_tweak = random_utxo_tweak();

    let tr = descriptor_tr(&federation.bitcoin_pks, &utxo_tweak, nums_point());

    FrostTweak::new(federation.polynomial.aggregate_key(), &utxo_tweak, &tr);
}

/// A share must only verify against its signer's tweaked public key share —
/// neither another peer's nor the untweaked one.
#[test]
fn shares_only_verify_against_the_tweaked_public_share() {
    let federation = Federation::new();
    let utxo_tweak = random_utxo_tweak();
    let tweak = federation.tweak(&utxo_tweak);
    let signers = federation.signing_set();
    let (signer, other) = (signers[0], signers[1]);
    let message = [7; 32];

    let mut secret_nonce = None;
    let public_nonces = signers
        .iter()
        .map(|peer| {
            let (nonce, public_nonce) = generate_nonce();

            if *peer == signer {
                secret_nonce = Some(nonce);
            }

            (signer_id(*peer), public_nonce)
        })
        .collect::<BTreeMap<_, _>>();

    let share: SignatureShare = sign_share(
        message,
        &tweak.secret_share(federation.secret_shares[&signer]),
        secret_nonce.expect("The signer is in the signing set"),
        &public_nonces,
        signer_id(signer),
        tweak.aggregate(),
    );

    let verifies = |public_share: PublicKeyShare| {
        verify_signature_share(
            message,
            signer_id(signer),
            &public_share,
            &share,
            &public_nonces,
            tweak.aggregate(),
        )
    };

    assert!(verifies(
        tweak.public_share(federation.public_share(signer))
    ));
    assert!(!verifies(
        tweak.public_share(federation.public_share(other))
    ));
    assert!(!verifies(PublicKeyShare(federation.public_share(signer))));
}

/// The public nonce a seed is stored under must be the one its nonce derives,
/// which `consume_our_nonce` relies on.
#[test]
fn nonce_seed_derives_its_public_nonce() {
    let (seed, commitment) = FrostNonceSeed::generate();

    assert_eq!(derive_public_nonce(&derive_nonce(&seed.0)), commitment.0);
}
