use crate::Keys;
use minimint_api::config::GenerateConfig;
use minimint_api::{Amount, PeerId};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tbs::{dealer_keygen, AggregatePublicKey};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintConfig {
    pub tbs_sks: Keys<tbs::SecretKeyShare>,
    pub peer_tbs_pks: BTreeMap<PeerId, Keys<tbs::PublicKeyShare>>,
    pub fee_consensus: FeeConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintClientConfig {
    pub tbs_pks: Keys<AggregatePublicKey>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub coin_issuance_abs: minimint_api::Amount,
    pub coin_spend_abs: minimint_api::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            coin_issuance_abs: minimint_api::Amount::ZERO,
            coin_spend_abs: minimint_api::Amount::ZERO,
        }
    }
}
