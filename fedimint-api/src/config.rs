use std::collections::BTreeMap;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::PeerId;

/// Part of a config that needs to be generated to bootstrap a new federation.
pub trait GenerateConfig: Sized {
    type Params: ?Sized;
    type ClientConfig;

    /// Function that generates the config of all peers locally. This is only meant to be used for
    /// testing as the generating machine would be a single point of failure/compromise.
    fn trusted_dealer_gen(
        peers: &[PeerId],
        params: &Self::Params,
        rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig);

    fn to_client_config(&self) -> Self::ClientConfig;

    /// Asserts that the public keys in the config are and panics otherwise (no way to recover)
    fn validate_config(&self, identity: &PeerId);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoindRpcCfg {
    pub btc_rpc_address: String,
    pub btc_rpc_user: String,
    pub btc_rpc_pass: String,
}
