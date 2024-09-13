use std::collections::BTreeMap;

pub use bitcoin::Network;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::{plugin_types_trait_impl_config, Amount, PeerId};
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
pub struct FeeConsensus {
    pub base: Amount,
    pub parts_per_million: u64,
}

impl FeeConsensus {
    pub fn fee(&self, amount: Amount) -> Amount {
        Amount::from_msats(self.fee_msats(amount.msats))
    }

    fn fee_msats(&self, msats: u64) -> u64 {
        self.base.msats
            + msats
                .saturating_mul(self.parts_per_million)
                .saturating_div(1_000_000)
    }
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            base: Amount::from_sats(1),
            parts_per_million: 1_000,
        }
    }
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
        fee_consensus: FeeConsensus::default(),
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

#[test]
fn test_fee_consensus() {
    assert_eq!(
        FeeConsensus::default().fee(Amount::from_msats(999)),
        Amount::from_sats(1)
    );

    assert_eq!(
        FeeConsensus::default().fee(Amount::from_sats(1)),
        Amount::from_msats(1001)
    );

    assert_eq!(
        FeeConsensus::default().fee(Amount::from_sats(1000)),
        Amount::from_sats(2)
    );

    assert_eq!(
        FeeConsensus::default().fee(Amount::from_bitcoins(1)),
        Amount::from_sats(100_001)
    );
}
