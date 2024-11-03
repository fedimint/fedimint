use std::collections::BTreeMap;

pub use bitcoin::Network;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::fee_consensus::FeeConsensus;
use fedimint_core::{plugin_types_trait_impl_config, PeerId};
use group::Curve;
use serde::{Deserialize, Serialize};
use tpe::{AggregatePublicKey, PublicKeyShare, SecretKeyShare};

use crate::LightningCommonInit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningGenParams {
    pub local: LightningGenParamsLocal,
    pub consensus: LightningGenParamsConsensus,
}

impl LightningGenParams {
    #[allow(clippy::missing_panics_doc)]
    pub fn regtest(bitcoin_rpc: BitcoinRpcConfig) -> Self {
        Self {
            local: LightningGenParamsLocal { bitcoin_rpc },
            consensus: LightningGenParamsConsensus {
                fee_consensus: FeeConsensus::new_lnv2(1000).expect("Relative fee is within range"),
                network: Network::Regtest,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningGenParamsConsensus {
    pub fee_consensus: FeeConsensus,
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
    pub bitcoin_rpc: BitcoinRpcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct LightningConfigConsensus {
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub fee_consensus: FeeConsensus,
    pub network: Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfigPrivate {
    pub sk: SecretKeyShare,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct LightningClientConfig {
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub fee_consensus: FeeConsensus,
    pub network: Network,
}

impl std::fmt::Display for LightningClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LightningClientConfig {self:?}")
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

#[allow(dead_code)]
fn migrate_config_consensus(
    config: &fedimint_ln_common::config::LightningConfigConsensus,
    peer_count: u16,
) -> LightningConfigConsensus {
    LightningConfigConsensus {
        tpe_agg_pk: AggregatePublicKey(config.threshold_pub_keys.public_key().0.to_affine()),
        tpe_pks: (0..peer_count)
            .map(|peer| {
                (
                    PeerId::from(peer),
                    PublicKeyShare(
                        config
                            .threshold_pub_keys
                            .public_key_share(peer as usize)
                            .0
                             .0
                            .to_affine(),
                    ),
                )
            })
            .collect(),
        fee_consensus: FeeConsensus::new_lnv2(1000).expect("Relative fee is within range"),
        network: config.network,
    }
}

#[allow(dead_code)]
fn migrate_config_private(
    config: &fedimint_ln_common::config::LightningConfigPrivate,
) -> LightningConfigPrivate {
    LightningConfigPrivate {
        sk: SecretKeyShare(config.threshold_sec_key.0 .0 .0),
    }
}

#[allow(dead_code)]
fn migrate_config_local(
    config: fedimint_ln_common::config::LightningConfigLocal,
) -> LightningConfigLocal {
    LightningConfigLocal {
        bitcoin_rpc: config.bitcoin_rpc,
    }
}
