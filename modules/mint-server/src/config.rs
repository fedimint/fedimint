use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use fedimint_api::config::{scalar, DkgMessage, DkgRunner};
use fedimint_api::net::peers::AnyPeerConnections;
use fedimint_api::{Amount, NumPeers, PeerId, Tiered, TieredMultiZip};
use fedimint_mint_common::{FeeConsensus, MintClientConfig};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tbs::{dealer_keygen, Aggregatable, AggregatePublicKey, PublicKeyShare};
use threshold_crypto::group::Curve;
use threshold_crypto::G2Projective;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfig {
    pub tbs_sks: Tiered<tbs::SecretKeyShare>,
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<tbs::PublicKeyShare>>,
    pub fee_consensus: FeeConsensus,
    pub threshold: usize,
}
