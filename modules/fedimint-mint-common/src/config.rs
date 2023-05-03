use std::collections::BTreeMap;

use fedimint_core::config::{
    ClientModuleConfig, TypedClientModuleConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, Tiered};
use serde::{Deserialize, Serialize};
use tbs::{AggregatePublicKey, PublicKeyShare};

use crate::KIND;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfig {
    /// Contains all configuration that will be encrypted such as private key
    /// material
    pub private: MintConfigPrivate,
    /// Contains all configuration that needs to be the same for every server
    pub consensus: MintConfigConsensus,
}

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

impl TypedClientModuleConfig for MintClientConfig {
    fn kind(&self) -> ModuleKind {
        crate::KIND
    }

    fn version(&self) -> fedimint_core::module::ModuleConsensusVersion {
        crate::CONSENSUS_VERSION
    }

    fn to_erased(&self) -> ClientModuleConfig {
        ClientModuleConfig::from_typed(self.kind(), self.version(), self)
            .expect("serialization can't fail")
    }
}

impl TypedServerModuleConsensusConfig for MintConfigConsensus {
    fn kind(&self) -> ModuleKind {
        crate::KIND
    }

    fn version(&self) -> fedimint_core::module::ModuleConsensusVersion {
        crate::CONSENSUS_VERSION
    }
}

impl TypedServerModuleConfig for MintConfig {
    type Local = ();
    type Private = MintConfigPrivate;
    type Consensus = MintConfigConsensus;

    fn from_parts(_local: Self::Local, private: Self::Private, consensus: Self::Consensus) -> Self {
        Self { private, consensus }
    }

    fn to_parts(self) -> (ModuleKind, Self::Local, Self::Private, Self::Consensus) {
        (KIND, (), self.private, self.consensus)
    }
}

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
