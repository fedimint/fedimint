use fedimint_api::config::GenerateConfig;
use fedimint_api::rand::Rand085Compat;
use fedimint_api::PeerId;
use secp256k1::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleConfig {
    pub threshold_pub_keys: threshold_crypto::PublicKeySet,
    // TODO: propose serde(with = "…") based protection upstream instead
    pub threshold_sec_key:
        threshold_crypto::serde_impl::SerdeSecret<threshold_crypto::SecretKeyShare>,
    pub threshold: usize,
    pub fee_consensus: FeeConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleClientConfig {
    pub threshold_pub_key: threshold_crypto::PublicKey,
    pub fee_consensus: FeeConsensus,
}

impl GenerateConfig for LightningModuleConfig {
    type Params = ();
    type ClientConfig = LightningModuleClientConfig;

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        _params: &Self::Params,
        rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let threshold = peers.len() - max_evil;
        let sks = threshold_crypto::SecretKeySet::random(threshold - 1, &mut Rand085Compat(rng));
        let pks = sks.public_keys();

        let server_cfg = peers
            .iter()
            .map(|&peer| {
                let sk = sks.secret_key_share(peer.to_usize());

                (
                    peer,
                    LightningModuleConfig {
                        threshold_pub_keys: pks.clone(),
                        threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret(sk),
                        threshold,
                        fee_consensus: FeeConsensus::default(),
                    },
                )
            })
            .collect();

        let client_cfg = LightningModuleClientConfig {
            threshold_pub_key: pks.public_key(),
            fee_consensus: FeeConsensus::default(),
        };

        (server_cfg, client_cfg)
    }

    fn to_client_config(&self) -> Self::ClientConfig {
        LightningModuleClientConfig {
            threshold_pub_key: self.threshold_pub_keys.public_key(),
            fee_consensus: self.fee_consensus.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub contract_input: fedimint_api::Amount,
    pub contract_output: fedimint_api::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            contract_input: fedimint_api::Amount::ZERO,
            contract_output: fedimint_api::Amount::ZERO,
        }
    }
}
