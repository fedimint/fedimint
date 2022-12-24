use std::collections::{BTreeMap, HashMap};
use std::iter::FromIterator;

use anyhow::bail;
use fedimint_api::config::{ClientModuleConfig, TypedClientModuleConfig, TypedServerModuleConfig};
use fedimint_api::module::__reexports::serde_json;
use fedimint_api::{Amount, PeerId, Tiered, TieredMultiZip};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tbs::{Aggregatable, AggregatePublicKey, PublicKeyShare};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfig {
    /// Contains all configuration that will be encrypted such as private key material
    pub private: MintConfigPrivate,
    /// Contains all configuration that needs to be the same for every server
    pub consensus: MintConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfigConsensus {
    /// The set of public keys for blind-signing all peers and note denominations
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
    /// Fees charged for ecash transactions
    pub fee_consensus: FeeConsensus,
    /// Number of signers required
    pub threshold: usize,
    /// The maximum amount of change a client can request
    pub max_notes_per_denomination: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfigPrivate {
    /// Secret keys for blind-signing ecash of varying note denominations
    pub tbs_sks: Tiered<tbs::SecretKeyShare>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MintClientConfig {
    pub tbs_pks: Tiered<AggregatePublicKey>,
    pub fee_consensus: FeeConsensus,
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<tbs::PublicKeyShare>>,
    pub max_notes_per_denomination: u16,
}

impl TypedClientModuleConfig for MintClientConfig {}

impl TypedServerModuleConfig for MintConfig {
    type Local = ();
    type Private = MintConfigPrivate;
    type Consensus = MintConfigConsensus;

    fn from_parts(_local: Self::Local, private: Self::Private, consensus: Self::Consensus) -> Self {
        Self { private, consensus }
    }

    fn to_parts(self) -> (Self::Local, Self::Private, Self::Consensus) {
        ((), self.private, self.consensus)
    }

    fn to_client_config(&self) -> ClientModuleConfig {
        let pub_key: HashMap<Amount, AggregatePublicKey> = TieredMultiZip::new(
            self.consensus
                .peer_tbs_pks
                .values()
                .map(|keys| keys.iter())
                .collect(),
        )
        .map(|(amt, keys)| {
            // TODO: avoid this through better aggregation API allowing references or
            let keys = keys.into_iter().copied().collect::<Vec<_>>();
            (amt, keys.aggregate(self.consensus.threshold))
        })
        .collect();

        serde_json::to_value(&MintClientConfig {
            tbs_pks: Tiered::from_iter(pub_key.into_iter()),
            fee_consensus: self.consensus.fee_consensus.clone(),
            peer_tbs_pks: self.consensus.peer_tbs_pks.clone(),
            max_notes_per_denomination: self.consensus.max_notes_per_denomination,
        })
        .expect("Serialization can't fail")
        .into()
    }

    fn validate_config(&self, identity: &PeerId) -> anyhow::Result<()> {
        let sks: BTreeMap<Amount, PublicKeyShare> = self
            .private
            .tbs_sks
            .iter()
            .map(|(amount, sk)| (amount, sk.to_pub_key_share()))
            .collect();
        let pks: BTreeMap<Amount, PublicKeyShare> = self
            .consensus
            .peer_tbs_pks
            .get(identity)
            .unwrap()
            .as_map()
            .clone();
        if sks != pks {
            bail!("Mint private key doesn't match pubkey share");
        }
        if !sks.keys().contains(&Amount::from_msats(1)) {
            bail!("No msat 1 denomination");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub coin_issuance_abs: fedimint_api::Amount,
    pub coin_spend_abs: fedimint_api::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            coin_issuance_abs: fedimint_api::Amount::ZERO,
            coin_spend_abs: fedimint_api::Amount::ZERO,
        }
    }
}
