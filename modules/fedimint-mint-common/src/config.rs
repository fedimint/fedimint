use std::collections::BTreeMap;

use fedimint_core::config::EmptyGenParams;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::serde_json;
use fedimint_core::{plugin_types_trait_impl_config, Amount, PeerId, Tiered};
use serde::{Deserialize, Serialize};
use tbs::{AggregatePublicKey, PublicKeyShare};

use crate::MintCommonInit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintGenParams {
    pub local: EmptyGenParams,
    pub consensus: MintGenParamsConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintGenParamsConsensus {
    denomination_base: u16,
    fee_consensus: FeeConsensus,
}

// The maximum size of an E-Cash note (1,000,000 coins)
// Changing this value is considered a breaking change because it is not saved
// in `MintGenParamsConsensus` but instead is hardcoded here
const MAX_DENOMINATION_SIZE: Amount = Amount::from_bitcoins(1_000_000);

impl MintGenParamsConsensus {
    pub fn new(denomination_base: u16, fee_consensus: FeeConsensus) -> Self {
        Self {
            denomination_base,
            fee_consensus,
        }
    }

    pub fn denomination_base(&self) -> u16 {
        self.denomination_base
    }

    pub fn fee_consensus(&self) -> FeeConsensus {
        self.fee_consensus.clone()
    }

    pub fn gen_denominations(&self) -> Vec<Amount> {
        Tiered::gen_denominations(self.denomination_base, MAX_DENOMINATION_SIZE)
            .tiers()
            .copied()
            .collect()
    }
}

impl Default for MintGenParams {
    fn default() -> Self {
        MintGenParams {
            consensus: MintGenParamsConsensus::new(2, FeeConsensus::default()),
            local: EmptyGenParams {},
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfig {
    pub local: MintConfigLocal,
    pub private: MintConfigPrivate,
    pub consensus: MintConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct MintConfigLocal;

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct MintConfigConsensus {
    /// The set of public keys for blind-signing all peers and note
    /// denominations
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
    /// Fees charged for ecash transactions
    pub fee_consensus: FeeConsensus,
    /// The maximum amount of change a client can request
    pub max_notes_per_denomination: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfigPrivate {
    /// Secret keys for blind-signing ecash of varying note denominations
    pub tbs_sks: Tiered<tbs::SecretKeyShare>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct MintClientConfig {
    pub tbs_pks: Tiered<AggregatePublicKey>,
    pub fee_consensus: FeeConsensus,
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<tbs::PublicKeyShare>>,
    pub max_notes_per_denomination: u16,
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
    MintGenParams,
    EmptyGenParams,
    MintGenParamsConsensus,
    MintConfig,
    MintConfigLocal,
    MintConfigPrivate,
    MintConfigConsensus,
    MintClientConfig
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    pub note_issuance_abs: fedimint_core::Amount,
    pub note_spend_abs: fedimint_core::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            note_issuance_abs: fedimint_core::Amount::ZERO,
            note_spend_abs: fedimint_core::Amount::ZERO,
        }
    }
}
