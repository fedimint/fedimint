use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::config::EmptyGenParams;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
use serde::{Deserialize, Serialize};
use threshold_crypto::serde_impl::SerdeSecret;

use crate::LightningCommonGen;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningGenParams {
    pub local: LightningGenParamsLocal,
    pub consensus: EmptyGenParams,
}

impl LightningGenParams {
    pub fn new(bitcoin_rpc: BitcoinRpcConfig) -> Self {
        Self {
            local: LightningGenParamsLocal { bitcoin_rpc },
            consensus: Default::default(),
        }
    }
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
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    LightningCommonGen,
    LightningGenParams,
    LightningGenParamsLocal,
    EmptyGenParams,
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
