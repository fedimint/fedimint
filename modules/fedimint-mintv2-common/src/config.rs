use std::collections::BTreeMap;

use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::serde_json;
use fedimint_core::{Amount, PeerId, plugin_types_trait_impl_config};
use serde::{Deserialize, Serialize};
use tbs::{AggregatePublicKey, PublicKeyShare};

use crate::{Denomination, MintCommonInit};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintGenParams {
    pub fee_consensus: FeeConsensus,
}

pub fn consensus_denominations() -> impl DoubleEndedIterator<Item = Denomination> {
    (0..42).map(Denomination)
}

pub fn client_denominations() -> impl DoubleEndedIterator<Item = Denomination> {
    (10..42).map(Denomination)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfig {
    pub private: MintConfigPrivate,
    pub consensus: MintConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct MintConfigConsensus {
    pub tbs_agg_pks: BTreeMap<Denomination, AggregatePublicKey>,
    pub tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
    pub fee_consensus: FeeConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfigPrivate {
    pub tbs_sks: BTreeMap<Denomination, tbs::SecretKeyShare>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct MintClientConfig {
    pub tbs_agg_pks: BTreeMap<Denomination, AggregatePublicKey>,
    pub tbs_pks: BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>,
    pub fee_consensus: FeeConsensus,
}

impl std::fmt::Display for MintClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MintClientConfig {}",
            serde_json::to_string(self).map_err(|_e| std::fmt::Error)?
        )
    }
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    MintCommonInit,
    MintConfig,
    MintConfigPrivate,
    MintConfigConsensus,
    MintClientConfig
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    base: Amount,
    parts_per_million: u64,
}

impl FeeConsensus {
    /// The mint module will charge a non-configurable base fee of one hundred
    /// millisatoshis per transaction input and output to account for the costs
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
            base: Amount::from_msats(100),
            parts_per_million,
        })
    }

    /// Creates a fee consensus with zero fees (no base fee, no relative fee)
    pub fn zero() -> Self {
        Self {
            base: Amount::ZERO,
            parts_per_million: 0,
        }
    }

    pub fn base_fee(&self) -> Amount {
        self.base
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
    let fee_consensus = FeeConsensus::new(1_000).expect("Relative fee is within range");

    assert_eq!(
        fee_consensus.fee(Amount::from_msats(999)),
        Amount::from_msats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_sats(1)),
        Amount::from_msats(100) + Amount::from_msats(1)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_sats(1000)),
        Amount::from_sats(1) + Amount::from_msats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_bitcoins(1)),
        Amount::from_sats(100_000) + Amount::from_msats(100)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_bitcoins(100_000)),
        Amount::from_bitcoins(100) + Amount::from_msats(100)
    );
}
