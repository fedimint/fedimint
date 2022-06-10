use minimint_api::config::GenerateConfig;
use minimint_api::PeerId;
use secp256k1::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplicityModuleConfig {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplicityModuleClientConfig {}

impl GenerateConfig for SimplicityModuleConfig {
    type Params = ();
    type ClientConfig = SimplicityModuleClientConfig;

    fn trusted_dealer_gen(
        peers: &[PeerId],
        _max_evil: usize,
        _params: &Self::Params,
        mut _rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let server_cfg = peers
            .iter()
            .map(|&peer| (peer, SimplicityModuleConfig {}))
            .collect();

        let client_cfg = SimplicityModuleClientConfig {};

        (server_cfg, client_cfg)
    }
}
