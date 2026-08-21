pub use bitcoin::Network;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::btc::NetworkLegacyEncodingWrapper;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::{Amount, msats, plugin_types_trait_impl_config};
use lightning_invoice::RoutingFees;
use serde::{Deserialize, Serialize};
use threshold_crypto::serde_impl::SerdeSecret;

use crate::LightningCommonInit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfig {
    pub private: LightningConfigPrivate,
    pub consensus: LightningConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct LightningConfigLocal {
    /// Configures which bitcoin RPC to use
    pub bitcoin_rpc: BitcoinRpcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct LightningConfigConsensus {
    /// The threshold public keys for encrypting the LN preimage
    pub threshold_pub_keys: threshold_crypto::PublicKeySet,
    /// Fees charged for LN transactions
    pub fee_consensus: FeeConsensus,
    pub network: NetworkLegacyEncodingWrapper,
}

impl LightningConfigConsensus {
    /// The number of decryption shares required
    pub fn threshold(&self) -> usize {
        self.threshold_pub_keys.threshold() + 1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfigPrivate {
    // TODO: propose serde(with = "…") based protection upstream instead
    /// Our secret key for decrypting preimages
    pub threshold_sec_key: SerdeSecret<threshold_crypto::SecretKeyShare>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct LightningClientConfig {
    pub threshold_pub_key: threshold_crypto::PublicKey,
    pub fee_consensus: FeeConsensus,
    pub network: NetworkLegacyEncodingWrapper,
}

impl std::fmt::Display for LightningClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LightningClientConfig {}",
            serde_json::to_string(self).map_err(|_e| std::fmt::Error)?
        )
    }
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    LightningCommonInit,
    LightningConfig,
    LightningConfigPrivate,
    LightningConfigConsensus,
    LightningClientConfig
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    pub contract_input: fedimint_core::Amount,
    pub contract_output: fedimint_core::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            contract_input: fedimint_core::Amount::ZERO,
            contract_output: fedimint_core::Amount::ZERO,
        }
    }
}

/// Trait for converting a fee type to specific `Amount`,
/// relative to a given payment `Amount`
pub trait FeeToAmount {
    /// The fee the rate names: `base_msat + floor(payment * ppm / 1_000_000)`.
    ///
    /// Never larger than [`FeeToAmount::to_amount_legacy`], which is why a
    /// gateway validates outgoing contracts against this one: it accepts both
    /// what deployed clients fund today and what they will fund once they move
    /// off the legacy calculation.
    fn to_amount(&self, payment: &Amount) -> Amount;

    /// The fee deployed LNv1 clients fund an outgoing contract with:
    /// `base_msat + floor(payment / floor(1_000_000 / ppm))`.
    ///
    /// Truncating the divisor before dividing over-charges every rate that does
    /// not divide `1_000_000` exactly — the default 3_000 ppm bills 0.3003% —
    /// and bills a flat 100% above 500_000 ppm. Wrong, but a client that funds
    /// less than this is rejected as `Underfunded` by every gateway still
    /// validating with it, so clients keep funding it until the fleet has
    /// rolled over. New callers want [`FeeToAmount::to_amount`].
    fn to_amount_legacy(&self, payment: &Amount) -> Amount;
}

impl FeeToAmount for RoutingFees {
    fn to_amount(&self, payment: &Amount) -> Amount {
        // Widened to `u128`: the rate arrives unvalidated in a gateway
        // registration, and clients union the announcements they get from each
        // guardian, so it is not bounded by what `register_gateway` accepts.
        // An absurd fee has to surface as an absurd `Amount` the caller
        // rejects, never as an overflow.
        let margin_fee =
            u128::from(payment.msats) * u128::from(self.proportional_millionths) / 1_000_000;

        msats(
            u64::try_from(margin_fee)
                .unwrap_or(u64::MAX)
                .saturating_add(u64::from(self.base_msat)),
        )
    }

    fn to_amount_legacy(&self, payment: &Amount) -> Amount {
        let margin_fee = match 1_000_000_u64.checked_div(u64::from(self.proportional_millionths)) {
            // A zero rate has no margin at all.
            None => 0,
            // Above one million ppm the divisor truncates to zero, which used to
            // panic. There is no representable divisor, so price it out of range.
            Some(0) => u64::MAX,
            Some(divisor) => payment.msats / divisor,
        };

        msats(margin_fee.saturating_add(u64::from(self.base_msat)))
    }
}

#[cfg(test)]
mod tests;
