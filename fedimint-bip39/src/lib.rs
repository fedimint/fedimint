#![deny(clippy::pedantic)]

//! BIP39 client secret support crate

use std::io::{Read, Write};

pub use bip39::{Language, Mnemonic};
use fedimint_client::derivable_secret::DerivableSecret;
use fedimint_client::secret::RootSecretStrategy;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleRegistry;
use rand::{CryptoRng, RngCore};

/// BIP39 root secret encoding strategy allowing retrieval of the seed phrase.
#[derive(Debug)]
pub struct Bip39RootSecretStrategy<const WORD_COUNT: usize = 12>;

impl<const WORD_COUNT: usize> RootSecretStrategy for Bip39RootSecretStrategy<WORD_COUNT> {
    type Encoding = Mnemonic;

    fn to_root_secret(secret: &Self::Encoding) -> DerivableSecret {
        const FEDIMINT_CLIENT_NONCE: &[u8] = b"Fedimint Client Salt";
        const EMPTY_PASSPHRASE: &str = "";

        DerivableSecret::new_root(
            secret.to_seed_normalized(EMPTY_PASSPHRASE).as_ref(),
            FEDIMINT_CLIENT_NONCE,
        )
    }

    fn consensus_encode(
        secret: &Self::Encoding,
        writer: &mut impl Write,
    ) -> std::io::Result<usize> {
        secret.to_entropy().consensus_encode(writer)
    }

    fn consensus_decode(
        reader: &mut impl Read,
    ) -> Result<Self::Encoding, fedimint_core::encoding::DecodeError> {
        let bytes = Vec::<u8>::consensus_decode(reader, &ModuleRegistry::default())?;
        Mnemonic::from_entropy(&bytes).map_err(DecodeError::from_err)
    }

    fn random<R>(rng: &mut R) -> Self::Encoding
    where
        R: RngCore + CryptoRng,
    {
        Mnemonic::generate_in_with(rng, Language::English, WORD_COUNT)
            .expect("Failed to generate mnemonic, bad word count")
    }
}
