use std::fs;
use std::num::NonZeroU32;
use std::path::PathBuf;

use anyhow::{bail, format_err, Result};
use rand::rngs::OsRng;
use rand::Rng;
use ring::aead::Nonce;
pub use ring::aead::{Aad, LessSafeKey, UnboundKey, NONCE_LEN};

const ITERATIONS_PROD: Option<NonZeroU32> = NonZeroU32::new(1_000_000);
const ITERATIONS_DEBUG: Option<NonZeroU32> = NonZeroU32::new(1);

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
/// entropy to prevent brute-forcing (e.g. 6 random words).  Switching to a
/// memory-hard algorithm like Argon2 would be more future-proof and safe for
/// weaker passwords.
///
/// We use the ChaCha20 stream cipher with Poly1305 message authentication
/// standardized in IETF RFC 8439.  PBKDF2 with 1M iterations is used for key
/// stretching along with a 128-bit salt that is randomly generated to
/// discourage rainbow attacks.  HMAC-SHA256 is used for the authentication
/// code.  All crypto is from the widely-used `ring` crate we also use for TLS.
pub fn get_key(password: Option<String>, salt_path: PathBuf) -> Result<LessSafeKey> {
    let password = match password {
        None => rpassword::prompt_password("Enter a password to encrypt configs: ").unwrap(),
        Some(password) => password,
    };

    let salt_str = fs::read_to_string(salt_path)?;
    let salt = hex::decode(salt_str)?;
    let mut key = [0u8; ring::digest::SHA256_OUTPUT_LEN];
    let algo = ring::pbkdf2::PBKDF2_HMAC_SHA256;
    ring::pbkdf2::derive(
        algo,
        if std::env::var("FM_TEST_FAST_WEAK_CRYPTO").as_deref() == Ok("1") {
            ITERATIONS_DEBUG.unwrap()
        } else {
            ITERATIONS_PROD.unwrap()
        },
        &salt,
        password.as_bytes(),
        &mut key,
    );
    let key = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key)
        .map_err(|_| anyhow::Error::msg("Unable to create key"))?;
    Ok(LessSafeKey::new(key))
}
