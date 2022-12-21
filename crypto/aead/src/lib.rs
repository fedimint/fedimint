use anyhow::{bail, Result};
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
    .map_err(|_| anyhow::format_err!("Decryption failed due to unspecified aead error"))?;

    Ok(&encrypted_bytes[..encrypted_bytes.len() - key.algorithm().tag_len()])
}
