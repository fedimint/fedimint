use std::fs;
use std::path::PathBuf;

use anyhow::{bail, format_err, Result};
use argon2::password_hash::{Salt, SaltString};
use argon2::{Argon2, PasswordHasher};
use rand::rngs::OsRng;
use rand::Rng;
use ring::aead::Nonce;
pub use ring::aead::{Aad, LessSafeKey, UnboundKey, NONCE_LEN};

/// Get a random nonce.
pub fn get_random_nonce() -> ring::aead::Nonce {
    Nonce::assume_unique_for_key(OsRng.gen())
}

/// Encrypt `plaintext` using `key`.
///
/// Prefixes the ciphertext with a nonce.
pub fn encrypt(mut plaintext: Vec<u8>, key: &LessSafeKey) -> Result<Vec<u8>> {
    let nonce = get_random_nonce();
    // prefix ciphertext with nonce
    let mut ciphertext: Vec<u8> = nonce.as_ref().to_vec();

    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut plaintext)
        .map_err(|_| anyhow::format_err!("Encryption failed due to unspecified aead error"))?;

    ciphertext.append(&mut plaintext);

    Ok(ciphertext)
}

/// Decrypts a `ciphertext` using `key`.
///
/// Expect nonce in the prefix, like [`encrypt`] produces.
pub fn decrypt<'c>(ciphertext: &'c mut [u8], key: &LessSafeKey) -> Result<&'c [u8]> {
    if ciphertext.len() < NONCE_LEN {
        bail!("Ciphertext too short: {}", ciphertext.len());
    }

    let (nonce_bytes, encrypted_bytes) = ciphertext.split_at_mut(NONCE_LEN);

    key.open_in_place(
        Nonce::assume_unique_for_key(nonce_bytes.try_into().expect("nonce size known")),
        Aad::empty(),
        encrypted_bytes,
    )
    .map_err(|_| format_err!("Decryption failed due to unspecified aead error"))?;

    Ok(&encrypted_bytes[..encrypted_bytes.len() - key.algorithm().tag_len()])
}

/// Write `data` encrypted to a `file` with a random `nonce` that will be
/// encoded in the file
pub fn encrypted_write(data: Vec<u8>, key: &LessSafeKey, file: PathBuf) -> Result<()> {
    let bytes = encrypt(data, key)?;
    fs::write(file.clone(), hex::encode(bytes))
        .map_err(|_| format_err!("Unable to write file {:?}", file))?;
    Ok(())
}

/// Reads encrypted data from a file
pub fn encrypted_read(key: &LessSafeKey, file: PathBuf) -> Result<Vec<u8>> {
    let hex = fs::read_to_string(file)?;
    let mut bytes = hex::decode(hex)?;

    Ok(decrypt(&mut bytes, key)?.to_vec())
}

/// Key used to encrypt and authenticate data stored on the filesystem with a
/// user password.
///
/// We encrypt certain configs to prevent attackers from learning the private
/// keys if they gain file access.  We authenticate the configs to prevent
/// attackers from manipulating the encrypted files.
///
/// Users can safely back-up config and salt files on other media the attacker
/// accesses if they do not learn the password and the password has enough
/// entropy to prevent brute-forcing (e.g. 6 random words).
///
/// We use the ChaCha20 stream cipher with Poly1305 message authentication
/// standardized in IETF RFC 8439.  Argon2 is used for memory-hard key
/// stretching along with a 128-bit salt that is randomly generated to
/// discourage rainbow attacks.
///
/// * `password` - Strong user-created password
/// * `salt` - Nonce >8 bytes to discourage rainbow attacks
fn get_encryption_key(password: &str, salt: &[u8]) -> Result<LessSafeKey> {
    let mut key = [0u8; ring::digest::SHA256_OUTPUT_LEN];

    argon2()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format_err!("could not hash password").context(e))?;
    let key = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key)
        .map_err(|_| anyhow::Error::msg("Unable to create key"))?;
    Ok(LessSafeKey::new(key))
}

/// Helper for `get_encryption_key` reading the salt from a path
pub fn get_encryption_key_with_path(password: &str, salt_path: PathBuf) -> Result<LessSafeKey> {
    let salt_str = fs::read_to_string(salt_path)?;
    let salt = hex::decode(salt_str)?;
    get_encryption_key(password, &salt)
}

/// Memory-hard Argon2 key stretching for password-based authentication
///
/// * `password` - Strong user-created password
/// * `salt` - B64 encoded nonce between 4 and 64 bytes
pub fn get_password_hash(password: &str, salt_string: &str) -> Result<String> {
    let salt =
        Salt::from_b64(salt_string).map_err(|e| format_err!("could not create salt").context(e))?;
    argon2()
        .hash_password(password.as_bytes(), salt)
        .map(|password| password.to_string())
        .map_err(|e| format_err!("could not hash password").context(e))
}

/// Generates a B64-encoded random salt string of the recommended 16 byte length
pub fn random_salt() -> String {
    SaltString::generate(OsRng).to_string()
}

/// Constructs Argon2 with default params, easier if the weak crypto flag is set
/// for testing
fn argon2() -> Argon2<'static> {
    let mut params = argon2::ParamsBuilder::default();
    if let Ok("1") = std::env::var("FM_TEST_FAST_WEAK_CRYPTO").as_deref() {
        params.m_cost(1);
    }
    Argon2::from(params.build().expect("valid params"))
}

#[cfg(test)]
mod tests {
    use crate::{decrypt, encrypt, get_encryption_key, get_password_hash, random_salt};

    #[test]
    fn encrypts_and_decrypts() {
        let password = "test123";
        let salt = "salt1235".as_bytes();
        let message = "hello world";

        let key = get_encryption_key(password, salt).unwrap();
        let mut cipher_text = encrypt(message.as_bytes().to_vec(), &key).unwrap();
        let decrypted = decrypt(&mut cipher_text, &key).unwrap();

        assert_eq!(decrypted, message.as_bytes());
    }

    #[test]
    fn password_hashing_works() {
        let password = "test1";
        let salt1 = random_salt();
        let salt2 = "HVwJovQIaTEXAkPyXl3MqQ";

        let key1 = get_password_hash(password, salt1.as_str()).unwrap();
        let key2 = get_password_hash(password, salt2).unwrap();

        assert_ne!(key1, key2);
        assert_eq!(key2, "$argon2id$v=19$m=19456,t=2,p=1$HVwJovQIaTEXAkPyXl3MqQ$pQ1T/qsHMGBWxQFLSZ4hqBUfLInIAQzPWIQiVNt4UNI");
    }
}
