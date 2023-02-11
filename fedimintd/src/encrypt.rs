/// Encrypt and authenticate data stored on the filesystem with a user-supplied password.
///
/// We encrypt the configs to prevent attackers from learning the private keys if they gain
/// file access.  We authenticate the configs to prevent attackers from manipulating the
/// encrypted files.
///
/// Users can safely back-up config and salt files on other media the attacker accesses if they do
/// not learn the password and the password has enough entropy to prevent brute-forcing (e.g.
/// 6 random words).  Switching to a memory-hard algorithm like Argon2 would be more future-proof
/// and safe for weaker passwords.
///
/// We use the ChaCha20 stream cipher with Poly1305 message authentication standardized
/// in IETF RFC 8439.  PBKDF2 with 1M iterations is used for key stretching along with a 128-bit
/// salt that is randomly generated to discourage rainbow attacks.  HMAC-SHA256 is used for the
/// authentication code.  All crypto is from the widely-used `ring` crate we also use for TLS.
use std::fs;
use std::num::NonZeroU32;
use std::path::PathBuf;

use anyhow::format_err;
use bitcoin::hashes::hex::{FromHex, ToHex};
use ring::aead::{LessSafeKey, UnboundKey};
use ring::{digest, pbkdf2};

const ITERATIONS_PROD: Option<NonZeroU32> = NonZeroU32::new(1_000_000);
const ITERATIONS_DEBUG: Option<NonZeroU32> = NonZeroU32::new(1);

/// Write `data` encrypted to a `file` with a random `nonce` that will be encoded in the file
pub fn encrypted_write(data: Vec<u8>, key: &LessSafeKey, file: PathBuf) -> anyhow::Result<()> {
    let bytes = aead::encrypt(data, key)?;
    fs::write(file.clone(), bytes.to_hex())
        .map_err(|_| format_err!("Unable to write file {:?}", file))?;
    Ok(())
}

/// Reads encrypted data from a file
pub fn encrypted_read(key: &LessSafeKey, file: PathBuf) -> anyhow::Result<Vec<u8>> {
    tracing::warn!("READ {:?}", file);
    let hex = fs::read_to_string(file)?;
    let mut bytes = Vec::from_hex(&hex)?;

    Ok(aead::decrypt(&mut bytes, key)?.to_vec())
}

// TODO: Move to `aead` crate?
pub fn get_key(password: Option<String>, salt_path: PathBuf) -> anyhow::Result<LessSafeKey> {
    let password = match password {
        None => rpassword::prompt_password("Enter a password to encrypt configs: ").unwrap(),
        Some(password) => password,
    };

    let salt_str = fs::read_to_string(salt_path)?;
    let salt = Vec::from_hex(&salt_str)?;
    let mut key = [0u8; digest::SHA256_OUTPUT_LEN];
    let algo = pbkdf2::PBKDF2_HMAC_SHA256;
    pbkdf2::derive(
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
