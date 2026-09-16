//! Tests against the BIP 445 test vectors, vendored from
//! <https://github.com/siv2r/bip-frost-signing> (python/vectors) at
//! commit 4b566d5.
//!
//! The nonce generation and deterministic signing vectors are not applicable:
//! we generate nonces from the operating system RNG instead of the spec's
//! derivation, and deterministic signing is deliberately unsupported. The
//! sign error vectors test caller-contract violations that our typed API
//! either cannot represent or documents as caller responsibility, and tweak
//! test cases do not apply since callers tweak key material externally.

use std::collections::BTreeMap;

use secp256k1::{PublicKey, SecretKey};
use serde_json::Value;

use crate::{
    AggregatePublicKey, PublicKeyShare, PublicNonce, SecretKeyShare, SecretNonce, SignatureShare,
    aggregate_nonce_halves, key_scalar, serialize_ids, serialize_point, session_values_from,
    sign_share, verify, verify_signature_share,
};

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("The value is a string")).expect("The value is hex")
}

fn message(value: &Value) -> Option<[u8; 32]> {
    bytes(value).try_into().ok()
}

fn point(value: &Value) -> PublicKey {
    PublicKey::from_slice(&bytes(value)).expect("The value is a compressed point")
}

fn public_nonce(value: &Value) -> Option<PublicNonce> {
    let bytes = bytes(value);

    Some(PublicNonce(
        PublicKey::from_slice(&bytes[..33]).ok()?,
        PublicKey::from_slice(&bytes[33..]).ok()?,
    ))
}

fn aggnonce_halves(value: &Value) -> (Option<PublicKey>, Option<PublicKey>) {
    let bytes = bytes(value);

    let parse = |half: &[u8]| {
        (half != [0; 33]).then(|| {
            PublicKey::from_slice(half).expect("The aggregate nonce half is a compressed point")
        })
    };

    (parse(&bytes[..33]), parse(&bytes[33..]))
}

fn indices(value: &Value) -> Vec<usize> {
    value
        .as_array()
        .expect("The value is an array")
        .iter()
        .map(|index| index.as_u64().expect("The index is an integer") as usize)
        .collect()
}

fn ids(value: &Value) -> Vec<u64> {
    value
        .as_array()
        .expect("The value is an array")
        .iter()
        .map(|id| id.as_u64().expect("The id is an integer"))
        .collect()
}

fn nonce_map(ids: &[u64], indices: &[usize], pubnonces: &[Value]) -> BTreeMap<u64, PublicNonce> {
    ids.iter()
        .zip(indices)
        .map(|(id, index)| {
            let nonce = public_nonce(&pubnonces[*index]).expect("The public nonce is valid");

            (*id, nonce)
        })
        .collect()
}

fn serialized_aggnonce(nonces: &BTreeMap<u64, PublicNonce>) -> Vec<u8> {
    let halves = aggregate_nonce_halves(nonces);

    [serialize_point(&halves.0), serialize_point(&halves.1)].concat()
}

#[test]
fn test_sign_verify_vectors() {
    let vectors: Value = serde_json::from_str(include_str!("vectors/sign_verify_vectors.json"))
        .expect("The vector file is valid json");

    let mut signed = 0;

    for group in vectors["test_groups"]
        .as_array()
        .expect("There are test groups")
    {
        let agg_pk = AggregatePublicKey(point(&group["thresh_pk"]));
        let pubshares = group["pubshares"].as_array().expect("There are pubshares");
        let pubnonces = group["pubnonces"].as_array().expect("There are pubnonces");
        let secshares = group["secshares"].as_array().expect("There are secshares");
        let secnonces = group["secnonces"].as_array().expect("There are secnonces");

        for test in group["valid_tests"]
            .as_array()
            .expect("There are valid tests")
        {
            let Some(msg) = message(&test["msg"]) else {
                continue; // our api signs 32-byte messages only
            };

            let ids = ids(&test["ids"]);
            let pubshare_indices = indices(&test["pubshare_indices"]);
            let nonces = nonce_map(&ids, &indices(&test["pubnonce_indices"]), pubnonces);

            assert_eq!(
                serialized_aggnonce(&nonces),
                bytes(&test["aggnonce"]),
                "aggregated nonce mismatch"
            );

            let my_id = test["my_id"].as_u64().expect("The id is an integer");

            let secnonce = bytes(
                &secnonces[test["secnonce_index"]
                    .as_u64()
                    .expect("The index is an integer") as usize],
            );

            let nonce = SecretNonce(
                SecretKey::from_slice(&secnonce[..32]).expect("The first secret nonce is valid"),
                SecretKey::from_slice(&secnonce[32..]).expect("The second secret nonce is valid"),
            );

            let sks = SecretKeyShare(
                SecretKey::from_slice(&bytes(
                    &secshares[test["secshare_index"]
                        .as_u64()
                        .expect("The index is an integer") as usize],
                ))
                .expect("The secret share is valid"),
            );

            let share = sign_share(msg, &sks, nonce, &nonces, my_id, &agg_pk);

            assert_eq!(
                share.0.secret_bytes().to_vec(),
                bytes(&test["expected"]),
                "partial signature mismatch"
            );

            let position = ids
                .iter()
                .position(|id| *id == my_id)
                .expect("The id is present");

            let pks = PublicKeyShare(point(&pubshares[pubshare_indices[position]]));

            assert!(verify_signature_share(
                msg, my_id, &pks, &share, &nonces, &agg_pk
            ));

            signed += 1;
        }

        for test in group["verify_fail_tests"]
            .as_array()
            .expect("There are fail tests")
        {
            let Some(msg) = message(&test["msg"]) else {
                continue;
            };

            // A partial signature outside the scalar field is rejected by the
            // type system before verification can run.
            let Ok(psig) = SecretKey::from_slice(&bytes(&test["psig"])) else {
                continue;
            };

            let ids = ids(&test["ids"]);
            let pubshare_indices = indices(&test["pubshare_indices"]);
            let nonces = nonce_map(&ids, &indices(&test["pubnonce_indices"]), pubnonces);

            let signer_index = test["signer_index"]
                .as_u64()
                .expect("The index is an integer") as usize;

            let pks = PublicKeyShare(point(&pubshares[pubshare_indices[signer_index]]));

            assert!(!verify_signature_share(
                msg,
                ids[signer_index],
                &pks,
                &SignatureShare(psig),
                &nonces,
                &agg_pk
            ));
        }
    }

    assert!(signed > 0, "no sign vectors were exercised");
}

#[test]
fn test_nonce_agg_vectors() {
    let vectors: Value = serde_json::from_str(include_str!("vectors/nonce_agg_vectors.json"))
        .expect("The vector file is valid json");

    let pubnonces = vectors["pubnonces"]
        .as_array()
        .expect("There are pubnonces");

    for test in vectors["valid_tests"]
        .as_array()
        .expect("There are valid tests")
    {
        let indices = indices(&test["pubnonce_indices"]);

        let nonces: BTreeMap<u64, PublicNonce> = indices
            .iter()
            .enumerate()
            .map(|(id, index)| {
                let nonce = public_nonce(&pubnonces[*index]).expect("The public nonce is valid");

                (id as u64, nonce)
            })
            .collect();

        assert_eq!(serialized_aggnonce(&nonces), bytes(&test["expected"]));
    }

    for test in vectors["error_tests"]
        .as_array()
        .expect("There are error tests")
    {
        let indices = indices(&test["pubnonce_indices"]);

        let signer_index = test["error"]["signer_index"]
            .as_u64()
            .expect("The index is an integer") as usize;

        // An invalid public nonce is rejected by the type system at decoding.
        assert!(public_nonce(&pubnonces[indices[signer_index]]).is_none());
    }
}

#[test]
fn test_sig_agg_vectors() {
    let vectors: Value = serde_json::from_str(include_str!("vectors/sig_agg_vectors.json"))
        .expect("The vector file is valid json");

    let mut aggregated = 0;

    for group in vectors["test_groups"]
        .as_array()
        .expect("There are test groups")
    {
        let agg_pk = AggregatePublicKey(point(&group["thresh_pk"]));

        for test in group["valid_tests"]
            .as_array()
            .expect("There are valid tests")
        {
            if !test["tweak_indices"]
                .as_array()
                .expect("There are tweak indices")
                .is_empty()
            {
                continue; // we tweak key material externally
            }

            let Some(msg) = message(&test["msg"]) else {
                continue;
            };

            let ids = serialize_ids(ids(&test["ids"]).into_iter());
            let halves = aggnonce_halves(&test["aggnonce"]);

            let (_, group_nonce, _) = session_values_from(&msg, &ids, &halves, &agg_pk);

            let response = test["psigs"]
                .as_array()
                .expect("There are partial signatures")
                .iter()
                .map(|psig| SecretKey::from_slice(&bytes(psig)).expect("The psig is valid"))
                .reduce(|accumulator, psig| {
                    accumulator
                        .add_tweak(&key_scalar(&psig))
                        .expect("The intermediate sums are nonzero")
                })
                .expect("There is at least one partial signature");

            let mut signature = group_nonce.x_only_public_key().0.serialize().to_vec();

            signature.extend(response.secret_bytes());

            assert_eq!(signature, bytes(&test["expected"]), "signature mismatch");

            let signature = secp256k1::schnorr::Signature::from_slice(&signature)
                .expect("The signature is 64 bytes");

            assert!(verify(msg, &signature, &agg_pk));

            aggregated += 1;
        }
    }

    assert!(aggregated > 0, "no sig agg vectors were exercised");
}
