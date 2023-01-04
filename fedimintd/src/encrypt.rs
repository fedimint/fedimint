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

use ring::aead::{LessSafeKey, UnboundKey};
use ring::{digest, pbkdf2};

const ITERATIONS_PROD: Option<NonZeroU32> = NonZeroU32::new(1_000_000);
const ITERATIONS_DEBUG: Option<NonZeroU32> = NonZeroU32::new(1);

/// Write `data` encrypted to a `file` with a random `nonce` that will be encoded in the file
// TODO: Use anyhow to handle errors
pub fn encrypted_write(data: Vec<u8>, key: &LessSafeKey, file: PathBuf) {
    let bytes = aead::encrypt(data, key).expect("encryption should not fail");
    fs::write(file, hex::encode(bytes)).expect("Can't write file.");
}

/// Reads encrypted data from a file
// TODO: Use anyhow to handle errors
pub fn encrypted_read(key: &LessSafeKey, file: PathBuf) -> Vec<u8> {
    tracing::warn!("READ {:?}", file);
    let hex = fs::read_to_string(file).expect("Can't read file.");
    let mut bytes = hex::decode(hex).expect("not hex encoded");

    aead::decrypt(&mut bytes, key)
        .expect("decryption failed")
        .to_vec()
}

// TODO: Move to `aead` crate?
pub fn get_key(password: Option<String>, salt_path: PathBuf) -> LessSafeKey {
    let password = match password {
        None => rpassword::prompt_password("Enter a password to encrypt configs: ").unwrap(),
        Some(password) => password,
    };

    let salt_str = fs::read_to_string(salt_path).expect("Can't read salt file");
    let salt = hex::decode(salt_str).expect("Can't decode hex");
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
    let key = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).expect("created key");
    LessSafeKey::new(key)
}
