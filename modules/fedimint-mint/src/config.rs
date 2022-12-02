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
    pub tbs_sks: Tiered<tbs::SecretKeyShare>,
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<tbs::PublicKeyShare>>,
    pub fee_consensus: FeeConsensus,
    pub threshold: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MintClientConfig {
    pub tbs_pks: Tiered<AggregatePublicKey>,
    pub fee_consensus: FeeConsensus,
}

impl TypedClientModuleConfig for MintClientConfig {}

impl TypedServerModuleConfig for MintConfig {
    fn to_client_config(&self) -> ClientModuleConfig {
        let pub_key: HashMap<Amount, AggregatePublicKey> = TieredMultiZip::new(
            self.peer_tbs_pks
                .iter()
                .map(|(_, keys)| keys.iter())
                .collect(),
        )
        .map(|(amt, keys)| {
            // TODO: avoid this through better aggregation API allowing references or
            let keys = keys.into_iter().copied().collect::<Vec<_>>();
            (amt, keys.aggregate(self.threshold))
        })
        .collect();

        serde_json::to_value(&MintClientConfig {
            tbs_pks: Tiered::from_iter(pub_key.into_iter()),
            fee_consensus: self.fee_consensus.clone(),
        })
        .expect("Serialization can't fail")
        .into()
    }

    fn validate_config(&self, identity: &PeerId) -> anyhow::Result<()> {
        let sks: BTreeMap<Amount, PublicKeyShare> = self
            .tbs_sks
            .iter()
            .map(|(amount, sk)| (amount, sk.to_pub_key_share()))
            .collect();
        let pks: BTreeMap<Amount, PublicKeyShare> =
            self.peer_tbs_pks.get(identity).unwrap().as_map().clone();
        if sks != pks {
            bail!("Mint private key doesn't match pubkey share");
        }
        if !sks.keys().contains(&Amount::from_msat(1)) {
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
