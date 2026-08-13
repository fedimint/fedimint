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
    fn to_amount(&self, payment: &Amount) -> Amount {
        // `proportional_millionths` arrives in a gateway registration served by a
        // public API endpoint, and clients union the announcements they get from
        // each guardian, so no bound on it can be assumed here even once
        // guardians validate it. Compute the margin in `u128` and saturate on the
        // way back down: an absurd fee has to surface as an absurd `Amount` the
        // caller rejects, never as a panic taking down the whole client.
        //
        // Multiplying before dividing is also what makes this agree with the
        // other places that price the same fee — `PaymentFee::absolute_fee`, the
        // gateway ranking in `fedimint-ln-client`, and `fedimint-recurringd`.
        // Dividing `1_000_000` by the rate first, as this used to, truncates the
        // divisor and overcharges: 3_000 millionths billed 0.3003% rather than
        // 0.3%, and any rate above 500_000 billed a flat 100%.
        let margin_fee =
            u128::from(payment.msats) * u128::from(self.proportional_millionths) / 1_000_000;

        msats(
            u64::try_from(margin_fee)
                .unwrap_or(u64::MAX)
                .saturating_add(u64::from(self.base_msat)),
        )
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::{Amount, msats};
    use lightning_invoice::RoutingFees;

    use super::FeeToAmount;

    fn fees(base_msat: u32, proportional_millionths: u32) -> RoutingFees {
        RoutingFees {
            base_msat,
            proportional_millionths,
        }
    }

    /// A rate above one million used to make `1_000_000 / rate` truncate to
    /// zero, and the division by it panicked. The value reaches this code
    /// straight off the wire, so it has to price instead of panic.
    #[test]
    fn rate_above_one_million_does_not_panic() {
        assert_eq!(
            fees(0, 1_000_001).to_amount(&msats(1_000_000)),
            msats(1_000_001)
        );

        // The whole range that used to panic, including its top end.
        assert_eq!(
            fees(0, u32::MAX).to_amount(&msats(1_000_000)),
            msats(u64::from(u32::MAX))
        );
    }

    #[test]
    fn fee_is_the_stated_fraction_of_the_payment() {
        // 100 millionths of 1_000_000 msat is 0.01%.
        assert_eq!(fees(0, 100).to_amount(&msats(1_000_000)), msats(100));

        // 3_000 millionths is 0.3% exactly. The old divisor form billed 3_003
        // here, because `1_000_000 / 3_000` truncated 333.33 to 333.
        assert_eq!(fees(0, 3_000).to_amount(&msats(1_000_000)), msats(3_000));

        // A rate this side of one million is not a flat 100% either: the old
        // form truncated the divisor to 1 for everything above 500_000.
        assert_eq!(
            fees(0, 600_000).to_amount(&msats(1_000_000)),
            msats(600_000)
        );

        assert_eq!(
            fees(0, 1_000_000).to_amount(&msats(1_000_000)),
            msats(1_000_000)
        );
    }

    #[test]
    fn base_fee_is_added_to_the_margin() {
        assert_eq!(fees(500, 0).to_amount(&msats(1_000_000)), msats(500));
        assert_eq!(fees(500, 100).to_amount(&msats(1_000_000)), msats(600));
        assert_eq!(fees(500, 0).to_amount(&Amount::ZERO), msats(500));
    }

    /// Neither the margin nor the base fee added to it may overflow `u64`.
    #[test]
    fn absurd_fees_saturate_rather_than_overflow() {
        assert_eq!(
            fees(u32::MAX, u32::MAX).to_amount(&msats(u64::MAX)),
            msats(u64::MAX)
        );

        // The margin alone fits, but adding the base fee to it does not.
        assert_eq!(
            fees(u32::MAX, 1_000_000).to_amount(&msats(u64::MAX)),
            msats(u64::MAX)
        );
    }
}
