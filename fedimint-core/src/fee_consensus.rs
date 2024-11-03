use serde::{Deserialize, Serialize};

use crate::{Amount, Decodable, Encodable};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    base: Amount,
    parts_per_million: u64,
}

impl FeeConsensus {
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
    pub fn new_lnv2(parts_per_million: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            parts_per_million <= 1_000,
            "Relative fee over one thousand parts per million is excessive"
        );

        Ok(Self {
            base: Amount::from_sats(1),
            parts_per_million,
        })
    }

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
    pub fn new_mint(parts_per_million: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            parts_per_million <= 1_000,
            "Relative fee over one thousand parts per million is excessive"
        );

        Ok(Self {
            base: Amount::from_msats(100),
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
    let fee_consensus_lnv2 = FeeConsensus::new_lnv2(1_000).expect("Relative fee is within range");

    assert_eq!(
        fee_consensus_lnv2.fee(Amount::from_msats(999)),
        Amount::from_sats(1)
    );

    assert_eq!(
        fee_consensus_lnv2.fee(Amount::from_sats(1)),
        Amount::from_msats(1001)
    );

    assert_eq!(
        fee_consensus_lnv2.fee(Amount::from_sats(1000)),
        Amount::from_sats(2)
    );

    assert_eq!(
        fee_consensus_lnv2.fee(Amount::from_bitcoins(1)),
        Amount::from_sats(100_001)
    );

    assert_eq!(
        fee_consensus_lnv2.fee(Amount::from_bitcoins(100_000)),
        Amount::from_bitcoins(100) + Amount::from_sats(1)
    );

    let fee_consensus_mint = FeeConsensus::new_mint(1_000).expect("Relative fee is within range");

    assert_eq!(
        fee_consensus_mint.fee(Amount::from_msats(999)),
        Amount::from_msats(100)
    );

    assert_eq!(
        fee_consensus_mint.fee(Amount::from_sats(1)),
        Amount::from_msats(101)
    );

    assert_eq!(
        fee_consensus_mint.fee(Amount::from_sats(1000)),
        Amount::from_sats(1) + Amount::from_msats(100)
    );

    assert_eq!(
        fee_consensus_mint.fee(Amount::from_bitcoins(1)),
        Amount::from_sats(100_000) + Amount::from_msats(100)
    );

    assert_eq!(
        fee_consensus_mint.fee(Amount::from_bitcoins(100_000)),
        Amount::from_bitcoins(100) + Amount::from_msats(100)
    );
}
