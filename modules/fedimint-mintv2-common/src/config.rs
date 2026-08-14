use std::collections::BTreeMap;

use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{AmountUnit, serde_json};
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
    (9..42).map(Denomination)
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
    pub amount_unit: AmountUnit,
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
    pub amount_unit: AmountUnit,
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Encodable)]
pub struct FeeConsensus {
    base: Amount,
    parts_per_million: u64,
}

#[derive(Deserialize)]
struct UnvalidatedFeeConsensus {
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

    fn from_unvalidated(base: Amount, parts_per_million: u64) -> anyhow::Result<FeeConsensus> {
        // Preserve the legacy static-config invariant. The dynamic-fee design in
        // #8758 moves broader policy to separate FeeConsensus/FeeRate types.
        anyhow::ensure!(
            (base == Amount::ZERO && parts_per_million == 0)
                || (base == Amount::from_msats(100) && parts_per_million <= 1_000),
            "Mint fees must be zero or use the 100 msat base fee and at most one thousand parts per million"
        );

        Ok(Self {
            base,
            parts_per_million,
        })
    }
}

impl<'de> Deserialize<'de> for FeeConsensus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let unvalidated = UnvalidatedFeeConsensus::deserialize(deserializer)?;
        Self::from_unvalidated(unvalidated.base, unvalidated.parts_per_million)
            .map_err(serde::de::Error::custom)
    }
}

impl Decodable for FeeConsensus {
    fn consensus_decode_partial<R: std::io::Read>(
        reader: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let base = Amount::consensus_decode_partial(reader, modules)?;
        let parts_per_million = u64::consensus_decode_partial(reader, modules)?;

        Self::from_unvalidated(base, parts_per_million)
            .map_err(fedimint_core::encoding::DecodeError::new_custom)
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

#[test]
fn decoded_fee_consensus_is_validated() {
    use fedimint_core::encoding::Encodable as _;
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    let modules = ModuleDecoderRegistry::default();
    for fee in [
        FeeConsensus::zero(),
        FeeConsensus::new(0).expect("zero ppm is valid"),
        FeeConsensus::new(1_000).expect("maximum ppm is valid"),
    ] {
        assert_eq!(
            serde_json::from_str::<FeeConsensus>(
                &serde_json::to_string(&fee).expect("fee consensus can be encoded")
            )
            .expect("valid JSON fee consensus can be decoded"),
            fee
        );
        assert_eq!(
            FeeConsensus::consensus_decode_whole(&fee.consensus_encode_to_vec(), &modules)
                .expect("valid consensus fee can be decoded"),
            fee
        );
    }

    for malformed in [
        (Amount::ZERO, 1),
        (Amount::from_msats(99), 0),
        (Amount::from_msats(100), 1_001),
        (Amount::from_msats(u64::MAX), u64::MAX),
    ] {
        let json = serde_json::json!({
            "base": malformed.0,
            "parts_per_million": malformed.1,
        });
        assert!(serde_json::from_value::<FeeConsensus>(json).is_err());

        let encoded = malformed.consensus_encode_to_vec();
        assert!(FeeConsensus::consensus_decode_whole(&encoded, &modules).is_err());
    }
}
