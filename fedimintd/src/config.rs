use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{plugin_types_trait_impl_config, Amount};
use serde::{Deserialize, Serialize};

use crate::FedimintdCommonInit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedimintdGenParams {
    pub local: FedimintdGenParamsLocal,
    pub consensus: FedimintdGenParamsConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedimintdGenParamsLocal;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedimintdGenParamsConsensus {
    pub tx_fee: Amount,
}

impl Default for FedimintdGenParams {
    fn default() -> Self {
        Self {
            local: FedimintdGenParamsLocal,
            consensus: FedimintdGenParamsConsensus {
                tx_fee: Amount::ZERO,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FedimintdConfig {
    pub local: FedimintdConfigLocal,
    pub private: FedimintdConfigPrivate,
    pub consensus: FedimintdConfigConsensus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct FedimintdClientConfig {
    /// Accessible to clients
    pub tx_fee: Amount,
}

/// Locally unencrypted config unique to each member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct FedimintdConfigLocal;

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct FedimintdConfigConsensus {
    /// Will be the same for all peers
    pub tx_fee: Amount,
}

/// Will be encrypted and not shared such as private key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FedimintdConfigPrivate;

plugin_types_trait_impl_config!(
    FedimintdCommonInit,
    FedimintdGenParams,
    FedimintdGenParamsLocal,
    FedimintdGenParamsConsensus,
    FedimintdConfig,
    FedimintdConfigLocal,
    FedimintdConfigPrivate,
    FedimintdConfigConsensus,
    FedimintdClientConfig
);
