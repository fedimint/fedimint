use async_trait::async_trait;
use fedimint_api::config::{DkgMessage, DkgRunner, GenerateConfig};
use fedimint_api::net::peers::AnyPeerConnections;
use fedimint_api::rand::Rand07Compat;
use fedimint_api::{NumPeers, PeerId};
use secp256k1::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::G1Projective;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleConfig {
    pub threshold_pub_keys: threshold_crypto::PublicKeySet,
    // TODO: propose serde(with = "…") based protection upstream instead
    pub threshold_sec_key:
        threshold_crypto::serde_impl::SerdeSecret<threshold_crypto::SecretKeyShare>,
    pub threshold: usize,
    pub fee_consensus: FeeConsensus,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct LightningModuleClientConfig {
    pub threshold_pub_key: threshold_crypto::PublicKey,
    pub fee_consensus: FeeConsensus,
}

#[async_trait(?Send)]
impl GenerateConfig for LightningModuleConfig {
    type Params = ();
    type ClientConfig = LightningModuleClientConfig;
    type ConfigMessage = ((), DkgMessage<G1Projective>);
    type ConfigError = ();

    fn trusted_dealer_gen(
        peers: &[PeerId],
        _params: &Self::Params,
        rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let sks = threshold_crypto::SecretKeySet::random(peers.degree(), &mut Rand07Compat(rng));
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
                        threshold: peers.threshold(),
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

    fn validate_config(&self, identity: &PeerId) {
        assert_eq!(
            self.threshold_sec_key.public_key_share(),
            self.threshold_pub_keys
                .public_key_share(identity.to_usize()),
            "Lightning private key doesn't match pubkey share"
        )
    }

    async fn distributed_gen(
        connections: &mut AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        _params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, Self::ClientConfig), Self::ConfigError> {
        let mut dkg = DkgRunner::new((), peers.threshold(), our_id, peers);
        let (pks, sks) = dkg.run_g1(connections, &mut rng).await[&()].threshold_crypto();

        let server = LightningModuleConfig {
            threshold_pub_keys: pks.clone(),
            threshold_sec_key: SerdeSecret(sks),
            threshold: peers.threshold(),
            fee_consensus: Default::default(),
        };

        let client = LightningModuleClientConfig {
            threshold_pub_key: pks.public_key(),
            fee_consensus: Default::default(),
        };

        Ok((server, client))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
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
