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

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, NONCE_LEN};
use ring::{aead, digest, pbkdf2};

const ITERATIONS: Option<NonZeroU32> = NonZeroU32::new(1_000_000);

// server files
pub const SALT_FILE: &str = "salt";
pub const CONFIG_FILE: &str = "config";
pub const DB_FILE: &str = "database";
pub const TLS_PK: &str = "tls-pk";
pub const TLS_CERT: &str = "tls-cert";

/// Write `data` encrypted to a `file` with an unused `nonce` that will be encoded in the file
pub fn encrypted_write(mut data: Vec<u8>, key: &LessSafeKey, nonce: Nonce, file: PathBuf) {
    let mut bytes = nonce.as_ref().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut data)
        .expect("encrypted");
    bytes.append(&mut data);
    fs::write(file, &hex::encode(bytes)).expect("Can't write file.");
}

/// Reads encrypted data from a file, returns an incremented nonce for encrypting the next file
pub fn encrypted_read(key: &LessSafeKey, file: PathBuf) -> (Vec<u8>, Nonce) {
    let hex = fs::read_to_string(file).expect("Can't read file.");
    let mut bytes = hex::decode(hex).expect("not hex encoded");
    let (nonce_bytes, encrypted_bytes) = bytes.split_at_mut(NONCE_LEN);
    let (nonce, incremented) = increment_nonce(nonce_bytes);
    key.open_in_place(nonce, Aad::empty(), encrypted_bytes)
        .expect("decrypts");
    let mut encrypted_bytes = encrypted_bytes.to_vec();
    encrypted_bytes.truncate(encrypted_bytes.len() - key.algorithm().tag_len());
    (encrypted_bytes, incremented)
}

pub fn get_key(password: Option<String>, salt_path: PathBuf) -> LessSafeKey {
    let password = match password {
        None => rpassword::prompt_password("Enter a password to encrypt configs: ").unwrap(),
        Some(password) => {
            println!("WARNING: Passing in a password from the command line may be less secure!");
            password
        }
    };

    let salt_str = fs::read_to_string(salt_path).expect("Can't read salt file");
    let salt = hex::decode(salt_str).expect("Can't decode hex");
    let mut key = [0u8; digest::SHA256_OUTPUT_LEN];
    let algo = pbkdf2::PBKDF2_HMAC_SHA256;
    pbkdf2::derive(
        algo,
        ITERATIONS.unwrap(),
        &salt,
        password.as_bytes(),
        &mut key,
    );
    let key = UnboundKey::new(&aead::CHACHA20_POLY1305, &key).expect("created key");
    LessSafeKey::new(key)
}

/// returns a nonce from bytes and an incremented nonce for encrpyting the next message
fn increment_nonce(nonce: &[u8]) -> (Nonce, Nonce) {
    let mut bytes = nonce.to_vec();
    bytes[0] += 1;
    let n1 = Nonce::assume_unique_for_key(nonce.try_into().expect("right len"));
    let n2 = Nonce::assume_unique_for_key(bytes.try_into().expect("right len"));
    (n1, n2)
}

pub fn zero_nonce() -> Nonce {
    Nonce::assume_unique_for_key([0; NONCE_LEN])
}
