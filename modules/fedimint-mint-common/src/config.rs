use std::collections::BTreeMap;

use fedimint_core::config::EmptyGenParams;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{plugin_types_trait_impl_config, Amount, PeerId, Tiered};
use serde::{Deserialize, Serialize};
use tbs::{AggregatePublicKey, PublicKeyShare};

use crate::MintCommonGen;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintGenParams {
    pub local: EmptyGenParams,
    pub consensus: MintGenParamsConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintGenParamsConsensus {
    pub mint_amounts: Vec<Amount>,
}

const TEN_BTC_IN_SATS: u64 = 10 * 100_000_000;

impl Default for MintGenParams {
    fn default() -> Self {
        MintGenParams {
            consensus: MintGenParamsConsensus {
                mint_amounts: Tiered::gen_denominations(Amount::from_sats(TEN_BTC_IN_SATS))
                    .tiers()
                    .cloned()
                    .collect(),
            },
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct MintClientConfig {
    pub tbs_pks: Tiered<AggregatePublicKey>,
    pub fee_consensus: FeeConsensus,
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<tbs::PublicKeyShare>>,
    pub max_notes_per_denomination: u16,
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    MintCommonGen,
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
