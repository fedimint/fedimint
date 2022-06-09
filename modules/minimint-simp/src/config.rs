use minimint_api::config::GenerateConfig;
use minimint_api::PeerId;
use secp256k1::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleConfig {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleClientConfig {}

impl GenerateConfig for LightningModuleConfig {
    type Params = ();
    type ClientConfig = LightningModuleClientConfig;

    fn trusted_dealer_gen(
        peers: &[PeerId],
        _max_evil: usize,
        _params: &Self::Params,
        mut _rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let server_cfg = peers
            .iter()
            .map(|&peer| (peer, LightningModuleConfig {}))
            .collect();

        let client_cfg = LightningModuleClientConfig {};

        (server_cfg, client_cfg)
    }
}
