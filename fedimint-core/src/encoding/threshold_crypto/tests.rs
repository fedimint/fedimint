use super::super::tests::test_roundtrip;

#[test_log::test]
fn test_ciphertext() {
    let sks = threshold_crypto::SecretKeySet::random(1, &mut rand::thread_rng());
    let pks = sks.public_keys();
    let pk = pks.public_key();

    let message = b"Hello world!";
    let ciphertext = pk.encrypt(message);
    let decryption_share = sks.secret_key_share(0).decrypt_share(&ciphertext).unwrap();

    test_roundtrip(&ciphertext);
    test_roundtrip(&decryption_share);
}
