use minimint_api::config::GenerateConfig;
use minimint_api::rand::Rand07Compat;
use minimint_api::PeerId;
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleClientConfig {
    pub threshold_pub_key: threshold_crypto::PublicKey,
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
        let sks = threshold_crypto::SecretKeySet::random(threshold - 1, &mut Rand07Compat(rng));
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
                    },
                )
            })
            .collect();

        let client_cfg = LightningModuleClientConfig {
            threshold_pub_key: pks.public_key(),
        };

        (server_cfg, client_cfg)
    }
}
