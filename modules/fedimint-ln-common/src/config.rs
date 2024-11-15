use std::str::FromStr;

use anyhow::Context;
pub use bitcoin::Network;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::btc::NetworkLegacyEncodingWrapper;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::{msats, plugin_types_trait_impl_config, Amount};
use lightning_invoice::RoutingFees;
use serde::{Deserialize, Serialize};
use threshold_crypto::serde_impl::SerdeSecret;

use crate::LightningCommonInit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningGenParams {
    pub local: LightningGenParamsLocal,
    pub consensus: LightningGenParamsConsensus,
}

impl LightningGenParams {
    pub fn regtest(bitcoin_rpc: BitcoinRpcConfig) -> Self {
        Self {
            local: LightningGenParamsLocal { bitcoin_rpc },
            consensus: LightningGenParamsConsensus {
                network: Network::Regtest,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningGenParamsConsensus {
    pub network: Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningGenParamsLocal {
    pub bitcoin_rpc: BitcoinRpcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfig {
    pub local: LightningConfigLocal,
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
    LightningGenParams,
    LightningGenParamsLocal,
    LightningGenParamsConsensus,
    LightningConfig,
    LightningConfigLocal,
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

/// Gateway routing fees
#[derive(Debug, Clone)]
pub struct GatewayFee(pub RoutingFees);

impl FromStr for GatewayFee {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let routing_fees = parse_routing_fees(s)?;
        Ok(GatewayFee(routing_fees))
    }
}

pub fn parse_routing_fees(raw: &str) -> anyhow::Result<RoutingFees> {
    let mut parts = raw.split(',');
    let base_msat = parts
        .next()
        .context("missing base fee in millisatoshis")?
        .parse()?;
    let proportional_millionths = parts
        .next()
        .context("missing liquidity based fee as proportional millionths of routed amount")?
        .parse()?;
    Ok(RoutingFees {
        base_msat,
        proportional_millionths,
    })
}

/// Trait for converting a fee type to specific `Amount`,
/// relative to a given payment `Amount`
pub trait FeeToAmount {
    /// Calculates fee `Amount` given a payment `Amount`
    fn to_amount(&self, payment: &Amount) -> Amount;
}

impl FeeToAmount for RoutingFees {
    fn to_amount(&self, payment: &Amount) -> Amount {
        let base_fee = u64::from(self.base_msat);
        let margin_fee: u64 = if self.proportional_millionths > 0 {
            let fee_percent = 1_000_000 / u64::from(self.proportional_millionths);
            payment.msats / fee_percent
        } else {
            0
        };

        msats(base_fee + margin_fee)
    }
}

impl FeeToAmount for GatewayFee {
    fn to_amount(&self, payment: &Amount) -> Amount {
        self.0.to_amount(payment)
    }
}

#[cfg(test)]
mod tests {
    use lightning_invoice::RoutingFees;

    use super::parse_routing_fees;

    #[test]
    fn test_routing_fee_parsing() {
        let test_cases = [
            ("0,0", Some((0, 0))),
            ("10,5000", Some((10, 5000))),
            ("-10,5000", None),
            ("10,-5000", None),
            ("0;5000", None),
            ("xpto", None),
        ];
        for (input, expected) in test_cases {
            if let Some((base_msat, proportional_millionths)) = expected {
                let actual = parse_routing_fees(input).expect("parsed routing fees");
                assert_eq!(
                    actual,
                    RoutingFees {
                        base_msat,
                        proportional_millionths
                    }
                );
            } else {
                let result = parse_routing_fees(input);
                assert!(result.is_err());
            }
        }
    }
}
