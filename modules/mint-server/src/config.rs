use std::collections::BTreeMap;

use fedimint_api::{NumPeers, PeerId, Tiered};
use fedimint_mint_common::FeeConsensus;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfig {
    pub tbs_sks: Tiered<tbs::SecretKeyShare>,
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<tbs::PublicKeyShare>>,
    pub fee_consensus: FeeConsensus,
    pub threshold: usize,
}
