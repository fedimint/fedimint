use std::error::Error as _;
use std::io::Write as _;

use assert_matches::assert_matches;

use crate::{
    DecryptError, EncryptedReadError, EncryptionKeyError, NONCE_LEN, decrypt, encrypt,
    encrypted_read, get_encryption_key,
};

#[test]
fn encrypts_and_decrypts() {
    let password = "test123";
    let salt = "salt1235";
    let message = "hello world";

    let key = get_encryption_key(password, salt).unwrap();
    let mut cipher_text = encrypt(message.as_bytes().to_vec(), &key).unwrap();
    let decrypted = decrypt(&mut cipher_text, &key).unwrap();

    assert_eq!(decrypted, message.as_bytes());
}

#[test]
fn decrypt_of_a_too_short_ciphertext_names_its_length() {
    let key = get_encryption_key("test123", "salt1235").expect("valid salt");
    let mut too_short = vec![0u8; NONCE_LEN - 1];

    let err = decrypt(&mut too_short, &key).expect_err("shorter than a nonce");

    assert_matches!(err, DecryptError::CiphertextTooShort { len } if len == NONCE_LEN - 1);
    assert_eq!(
        err.to_string(),
        format!("Ciphertext too short: {}", NONCE_LEN - 1)
    );
}

#[test]
fn decrypt_with_the_wrong_key_does_not_authenticate() {
    let encrypting_key = get_encryption_key("test123", "salt1235").expect("valid salt");
    let decrypting_key = get_encryption_key("different", "salt1235").expect("valid salt");
    let mut cipher_text = encrypt(b"hello world".to_vec(), &encrypting_key).unwrap();

    let err = decrypt(&mut cipher_text, &decrypting_key).expect_err("wrong key");

    assert_matches!(err, DecryptError::Open);
}

#[test]
fn get_encryption_key_with_a_too_short_salt_names_the_message_before_the_cause() {
    // Argon2's own wording is not copied as a literal: it is rendered from
    // the same variant the production code can produce, so this pins the
    // chain's shape (fedimint's message first, then the cause), not
    // upstream wording.
    let too_short_salt = "a".repeat(argon2::MIN_SALT_LEN - 1);

    let err = get_encryption_key("test123", &too_short_salt).expect_err("salt too short");

    assert_matches!(err, EncryptionKeyError(argon2::Error::SaltTooShort));
    assert_eq!(err.to_string(), "could not hash password");
    assert_eq!(
        err.source()
            .expect("argon2's error is the cause")
            .to_string(),
        argon2::Error::SaltTooShort.to_string(),
    );
}

#[test]
fn encrypted_read_of_non_hex_content_is_a_hex_error() {
    let path = std::env::temp_dir().join(format!(
        "fedimint-aead-test-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| file.write_all(b"not hex content"))
        .expect("temp file is writable and did not already exist");
    let key = get_encryption_key("test123", "salt1235").expect("valid salt");

    let result = encrypted_read(&key, path.clone());

    std::fs::remove_file(&path).expect("temp file still exists");
    assert_matches!(result, Err(EncryptedReadError::Hex(_)));
}
