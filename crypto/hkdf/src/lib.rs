//! This crate implements the [RFC5869] hash based key derivation function using
//! [`bitcoin_hashes`].
//!
//! [RFC5869]: https://www.rfc-editor.org/rfc/rfc5869
//! [`bitcoin_hashes`]: https://docs.rs/bitcoin_hashes/latest/bitcoin_hashes/

use std::cmp::min;

pub use bitcoin_hashes;
pub use bitcoin_hashes::Hash as BitcoinHash;
use bitcoin_hashes::{HashEngine, Hmac, HmacEngine};

pub mod hashes {
    pub use bitcoin_hashes::hash160::Hash as Hash160;
    pub use bitcoin_hashes::ripemd160::Hash as Ripemd160;
    pub use bitcoin_hashes::sha1::Hash as Sha1;
    pub use bitcoin_hashes::sha256::Hash as Sha256;
    pub use bitcoin_hashes::sha256d::Hash as Sha256d;
    pub use bitcoin_hashes::sha512::Hash as Sha512;
    pub use bitcoin_hashes::siphash24::Hash as Siphash24;
}

/// Implements the [RFC5869] hash based key derivation function using the hash
/// function `H`.
///
/// [RFC5869]: https://www.rfc-editor.org/rfc/rfc5869
#[derive(Clone)]
pub struct Hkdf<H: BitcoinHash> {
    prk: Hmac<H>,
}

impl<H: BitcoinHash> Hkdf<H> {
    /// Run HKDF-extract and keep the resulting pseudo random key as internal
    /// state
    ///
    /// ## Inputs
    /// * `ikm`: Input keying material, secret key material our keys will be
    ///   derived from
    /// * `salt`: Optional salt value, if not required set to `&[0; H::LEN]`. As
    ///   noted in the RFC the salt value can also be a secret.
    pub fn new(ikm: &[u8], salt: Option<&[u8]>) -> Self {
        let mut engine = HmacEngine::new(salt.unwrap_or(&vec![0x00; H::LEN]));
        engine.input(ikm);

        Hkdf {
            prk: Hmac::from_engine(engine),
        }
    }

    /// Construct the HKDF from a pseudo random key that has the correct
    /// distribution and length already (e.g. because it's the output of a
    /// previous HKDF round), skipping the HKDF-extract step. **If in doubt,
    /// please use `Hkdf::new` instead!**
    ///
    /// See also [`Hkdf::derive_hmac`].
    pub fn from_prk(prk: Hmac<H>) -> Self {
        Hkdf { prk }
    }

    /// Run HKDF-expand to generate new key material
    ///
    /// ## Inputs
    /// * `info`: Defines which key to derive. Different values lead to
    ///   different keys.
    /// * `LEN`: Defines the length of the key material to generate in octets.
    ///   Note that `LEN <= H::LEN * 255` has to be true.
    ///
    /// ## Panics
    /// If `LEN > H::LEN * 255`.
    pub fn derive<const LEN: usize>(&self, info: &[u8]) -> [u8; LEN] {
        // TODO: make const once rust allows
        let iterations = if LEN % H::LEN == 0 {
            LEN / H::LEN
        } else {
            LEN / H::LEN + 1
        };

        // Make sure we can cast iteration numbers to u8 later
        assert!(
            iterations <= 255,
            "RFC5869 only supports output length of up to 255*HashLength"
        );

        let mut output = [0u8; LEN];
        for iteration in 0..iterations {
            let current_slice = (H::LEN * iteration)..min(H::LEN * (iteration + 1), LEN);
            let last_slice = if iteration == 0 {
                0..0
            } else {
                (H::LEN * (iteration - 1))..(H::LEN * iteration)
            };

            // TODO: re-use midstate
            let mut engine = HmacEngine::<H>::new(&self.prk[..]);
            engine.input(&output[last_slice]);
            engine.input(info);
            engine.input(&[(iteration + 1) as u8]);
            let output_bytes = Hmac::from_engine(engine);

            let bytes_to_copy = current_slice.end - current_slice.start;
            output[current_slice].copy_from_slice(&output_bytes[0..bytes_to_copy]);
        }

        output
    }

    /// Run HKDF-expand to generate new key material with `L = H::LEN`
    ///
    /// See [`Hkdf::derive`] for more information.
    pub fn derive_hmac(&self, info: &[u8]) -> Hmac<H> {
        let mut engine = HmacEngine::<H>::new(&self.prk[..]);
        engine.input(info);
        engine.input(&[1u8]);
        Hmac::from_engine(engine)
    }
}

#[cfg(test)]
mod tests;
