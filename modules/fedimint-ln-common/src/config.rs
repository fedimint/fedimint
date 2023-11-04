use std::str::FromStr;

pub use bitcoin::Network;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
use lightning_invoice::RoutingFees;
use serde::{Deserialize, Serialize};
use threshold_crypto::serde_impl::SerdeSecret;

use crate::LightningCommonGen;

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
    pub network: Network,
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
    pub network: Network,
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
    LightningCommonGen,
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
        let mut parts = s.split(',');
        let base_msat = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing base fee in millisatoshis"))?
            .parse()?;
        let proportional_millionths = parts
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "missing liquidity based fee as proportional millionths of routed amount"
                )
            })?
            .parse()?;
        Ok(GatewayFee(RoutingFees {
            base_msat,
            proportional_millionths,
        }))
    }
}
