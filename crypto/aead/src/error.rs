use thiserror::Error;

/// Why [`encrypt`](crate::encrypt) could not seal a plaintext.
///
/// The cipher refuses a plaintext longer than it can process as one message.
#[derive(Debug, Error)]
#[error("Encryption failed due to unspecified aead error")]
pub struct EncryptError;

/// Why [`decrypt`](crate::decrypt) could not open a ciphertext.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecryptError {
    /// The ciphertext is shorter than the nonce it must start with.
    #[error("Ciphertext too short: {len}")]
    CiphertextTooShort {
        /// The length of the ciphertext, in bytes.
        len: usize,
    },

    /// The ciphertext does not authenticate under the key: the key is wrong,
    /// the ciphertext was altered, or it is too short to hold the tag.
    #[error("Decryption failed due to unspecified aead error")]
    Open,
}

/// Why [`encrypted_write`](crate::encrypted_write) could not write a file.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EncryptedWriteError {
    /// The file could not be created, written or synced; it must not exist
    /// yet.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The data could not be encrypted.
    #[error(transparent)]
    Encrypt(#[from] EncryptError),
}

/// Why [`encrypted_read`](crate::encrypted_read) could not read a file.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EncryptedReadError {
    /// The file could not be read as UTF-8 text.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The file's content is not hex.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    /// The decoded content could not be decrypted.
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
}

/// Why [`get_encryption_key`](crate::get_encryption_key) could not derive a
/// key: Argon2 rejected the password or the salt, such as a salt that is too
/// short.
#[derive(Debug, Error)]
#[error("could not hash password")]
pub struct EncryptionKeyError(#[source] pub(crate) argon2::Error);
