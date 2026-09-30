use secp256k1::Message;
use secp256k1::hashes::Hash as BitcoinHash;

use super::super::tests::test_roundtrip;

#[test_log::test]
fn test_ecdsa_sig() {
    let ctx = secp256k1::Secp256k1::new();
    let (sk, _pk) = ctx.generate_keypair(&mut rand::thread_rng());
    let sig = ctx.sign_ecdsa(
        &Message::from_digest(*secp256k1::hashes::sha256::Hash::hash(b"Hello World!").as_ref()),
        &sk,
    );

    test_roundtrip(&sig);
}

#[test_log::test]
fn test_schnorr_pub_key() {
    let ctx = secp256k1::global::SECP256K1;
    let mut rng = rand::rngs::OsRng;
    let sec_key = bitcoin::key::Keypair::new(ctx, &mut rng);
    let pub_key = sec_key.public_key();
    test_roundtrip(&pub_key);

    let sig = ctx.sign_schnorr(
        &Message::from_digest(*secp256k1::hashes::sha256::Hash::hash(b"Hello World!").as_ref()),
        &sec_key,
    );

    test_roundtrip(&sig);
}
