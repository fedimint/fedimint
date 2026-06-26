use std::collections::BTreeMap;

pub use bitcoin::Network;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::FeeRate;
use fedimint_core::{Amount, PeerId, plugin_types_trait_impl_config};
use group::Curve;
use serde::{Deserialize, Serialize};
use tpe::{AggregatePublicKey, PublicKeyShare, SecretKeyShare};

use crate::LightningCommonInit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfig {
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
    pub fee_consensus: FeeConfig,
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
    pub fee_consensus: FeeConfig,
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
    LightningConfig,
    LightningConfigPrivate,
    LightningConfigConsensus,
    LightningClientConfig
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConfig {
    pub base: Amount,
    pub parts_per_million: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    pub incoming_contract_input: FeeRate,
    pub incoming_contract_output: FeeRate,
    pub outgoing_contract_input: FeeRate,
    pub outgoing_contract_output: FeeRate,
}

impl FeeConsensus {
    pub fn from_config(config: &FeeConfig) -> anyhow::Result<Self> {
        let fee_rate = FeeRate::new(config.base, config.parts_per_million)?;

        Ok(Self {
            incoming_contract_input: fee_rate,
            incoming_contract_output: fee_rate,
            outgoing_contract_input: fee_rate,
            outgoing_contract_output: fee_rate,
        })
    }
}

impl TryFrom<FeeConfig> for FeeConsensus {
    type Error = anyhow::Error;

    fn try_from(config: FeeConfig) -> Result<Self, Self::Error> {
        Self::from_config(&config)
    }
}

impl FeeConfig {
    /// The lightning module will charge a non-configurable base fee of one
    /// satoshi per transaction input and output to account for the costs
    /// incurred by the federation for processing the transaction. On top of
    /// that the federation may charge a additional relative fee per input and
    /// output of up to one thousand parts per million which is equal to one
    /// tenth of one percent.
    ///
    /// # Errors
    /// - This constructor returns an error if the relative fee is in excess of
    ///   one thousand parts per million.
    pub fn new(parts_per_million: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            parts_per_million <= 1_000,
            "Relative fee over one thousand parts per million is excessive"
        );

        Ok(Self {
            base: Amount::from_sats(1),
            parts_per_million,
        })
    }

    pub fn zero() -> Self {
        Self {
            base: Amount::ZERO,
            parts_per_million: 0,
        }
    }

    pub fn fee(&self, amount: Amount) -> Amount {
        Amount::from_msats(self.fee_msats(amount.msats))
    }

    fn fee_msats(&self, msats: u64) -> u64 {
        msats
            .saturating_mul(self.parts_per_million)
            .saturating_div(1_000_000)
            .checked_add(self.base.msats)
            .expect("The division creates sufficient headroom to add the base fee")
    }
}

#[test]
fn test_fee_consensus() {
    let fee_consensus = FeeConfig::new(1_000).expect("Relative fee is within range");

    assert_eq!(
        fee_consensus.fee(Amount::from_msats(999)),
        Amount::from_sats(1)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_sats(1)),
        Amount::from_msats(1) + Amount::from_sats(1)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_sats(1000)),
        Amount::from_sats(1) + Amount::from_sats(1)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_bitcoins(1)),
        Amount::from_sats(100_000) + Amount::from_sats(1)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_bitcoins(100_000)),
        Amount::from_bitcoins(100) + Amount::from_sats(1)
    );
}

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
        fee_consensus: FeeConfig::new(1000).expect("Relative fee is within range"),
        network: config.network.0,
    }
}

#[allow(dead_code)]
fn migrate_config_private(
    config: &fedimint_ln_common::config::LightningConfigPrivate,
) -> LightningConfigPrivate {
    LightningConfigPrivate {
        sk: SecretKeyShare(config.threshold_sec_key.0.0.0),
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
