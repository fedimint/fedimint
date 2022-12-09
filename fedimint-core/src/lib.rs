use fedimint_api::core::{Decoder, MODULE_KEY_LN, MODULE_KEY_MINT, MODULE_KEY_WALLET};
use fedimint_api::module::registry::ModuleDecoderRegistry;
use fedimint_ln::common::LightningModuleDecoder;
use fedimint_mint::common::MintModuleDecoder;
use fedimint_wallet::common::WalletModuleDecoder;
use thiserror::Error;

pub mod modules {
    pub use fedimint_ln as ln;
    pub use fedimint_mint as mint;
    pub use fedimint_wallet as wallet;
}

/// Fedimint toplevel config
pub mod config;
pub mod epoch;
pub mod outcome;
pub mod transaction;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Mismatching outcome variant: expected {0}, got {1}")]
    MismatchingVariant(&'static str, &'static str),
    #[error("Pending preimage decryption")]
    PendingPreimage,
}

impl CoreError {
    /// Returns `true` if queried outpoint isn't ready yet but may become ready later
    pub fn is_retryable(&self) -> bool {
        matches!(self, CoreError::PendingPreimage)
    }
}

pub fn all_decoders() -> ModuleDecoderRegistry {
    ModuleDecoderRegistry::new([
        (MODULE_KEY_LN, Decoder::from_typed(&LightningModuleDecoder)),
        (MODULE_KEY_MINT, Decoder::from_typed(&MintModuleDecoder)),
        (MODULE_KEY_WALLET, Decoder::from_typed(&WalletModuleDecoder)),
    ])
}
