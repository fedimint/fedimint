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
    /// Calculates fee `Amount` given a payment `Amount`
    fn to_amount(&self, payment: &Amount) -> Amount;
}

impl FeeToAmount for RoutingFees {
    /// Prices `payment` at this fee schedule.
    ///
    /// The result is
    /// `base_msat + floor(payment / floor(1_000_000 /
    /// proportional_millionths))`, with a margin of zero when the rate is
    /// zero. Note the inner `floor`: the divisor is truncated before it is
    /// used, so every rate that does not divide `1_000_000` exactly charges
    /// slightly more than the rate it names, and any rate above `500_000`
    /// charges a flat one hundred percent. That is not the arithmetic the
    /// rate implies, but it is the arithmetic every already-deployed LNv1
    /// gateway validates outgoing contracts with, and a client that funds
    /// less than its gateway expects has its payment rejected as
    /// `Underfunded`. Correcting it therefore cannot be done here alone;
    /// see the callers in `fedimint-ln-client` and `fedimint-gw-client`.
    ///
    /// A rate above `1_000_000` prices the payment above its own value, which
    /// this form cannot express — the truncated divisor is zero. Such a fee
    /// saturates the margin to `u64::MAX` so that callers reject it, and the
    /// final addition saturates rather than overflowing. The value arrives in
    /// a gateway registration served by a public API endpoint, and clients
    /// union the announcements they get from each guardian, so no bound on it
    /// can be assumed here even though `register_gateway` now rejects one:
    /// an absurd fee has to surface as an absurd `Amount` the caller rejects,
    /// never as a panic taking down the whole client.
    fn to_amount(&self, payment: &Amount) -> Amount {
        let margin_fee = match 1_000_000_u64.checked_div(u64::from(self.proportional_millionths)) {
            // A zero rate has no margin at all.
            None => 0,
            // A rate above one million: unrepresentable, so price it out of range.
            Some(0) => u64::MAX,
            Some(divisor) => payment.msats / divisor,
        };

        msats(margin_fee.saturating_add(u64::from(self.base_msat)))
    }
}

#[cfg(test)]
mod tests;
