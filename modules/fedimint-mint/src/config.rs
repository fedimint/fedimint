use crate::tiered::TieredMultiZip;
use crate::Tiered;
use fedimint_api::config::GenerateConfig;
use fedimint_api::{Amount, PeerId};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::iter::FromIterator;
use tbs::{dealer_keygen, Aggregatable, AggregatePublicKey};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfig {
    pub tbs_sks: Tiered<tbs::SecretKeyShare>,
    pub peer_tbs_pks: BTreeMap<PeerId, Tiered<tbs::PublicKeyShare>>,
    pub fee_consensus: FeeConsensus,
    pub threshold: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintClientConfig {
    pub tbs_pks: Tiered<AggregatePublicKey>,
    pub fee_consensus: FeeConsensus,
}

impl GenerateConfig for MintConfig {
    type Params = [Amount];
    type ClientConfig = MintClientConfig;

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        _rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let tbs_threshold = peers.len() - max_evil;

        let tbs_keys = params
            .iter()
            .map(|&amount| {
                let (tbs_pk, tbs_pks, tbs_sks) = dealer_keygen(tbs_threshold, peers.len());
                (amount, (tbs_pk, tbs_pks, tbs_sks))
            })
            .collect::<HashMap<_, _>>();

        let mint_cfg = peers
            .iter()
            .map(|&peer| {
                let config = MintConfig {
                    threshold: tbs_threshold,
                    tbs_sks: params
                        .iter()
                        .map(|amount| (*amount, tbs_keys[amount].2[peer.to_usize()]))
                        .collect(),
                    peer_tbs_pks: peers
                        .iter()
                        .map(|&key_peer| {
                            let keys = params
                                .iter()
                                .map(|amount| (*amount, tbs_keys[amount].1[key_peer.to_usize()]))
                                .collect();
                            (key_peer, keys)
                        })
                        .collect(),
                    fee_consensus: FeeConsensus::default(),
                };
                (peer, config)
            })
            .collect();

        let client_cfg = MintClientConfig {
            tbs_pks: tbs_keys
                .into_iter()
                .map(|(amount, (pk, _, _))| (amount, pk))
                .collect(),
            fee_consensus: FeeConsensus::default(),
        };

        (mint_cfg, client_cfg)
    }

    fn to_client_config(&self) -> Self::ClientConfig {
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
        MintClientConfig {
            tbs_pks: Tiered::from_iter(pub_key.into_iter()),
            fee_consensus: self.fee_consensus.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
