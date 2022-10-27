use std::collections::BTreeMap;

use async_trait::async_trait;
use bitcoin::secp256k1::rand::{CryptoRng, RngCore};
use bitcoin::Network;
use fedimint_api::config::{BitcoindRpcCfg, GenerateConfig};
use fedimint_api::net::peers::AnyPeerConnections;
use fedimint_api::task::TaskGroup;
use fedimint_api::{Feerate, NumPeers, PeerId};
use miniscript::descriptor::Wsh;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

use crate::keys::CompressedPublicKey;
use crate::PegInDescriptor;

const FINALITY_DELAY: u32 = 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub network: Network,
    pub peg_in_descriptor: PegInDescriptor,
    pub peer_peg_in_keys: BTreeMap<PeerId, CompressedPublicKey>,
    pub peg_in_key: secp256k1::SecretKey,
    pub finality_delay: u32,
    pub default_fee: Feerate,
    pub fee_consensus: FeeConsensus,
    #[serde(flatten)]
    pub btc_rpc: BitcoindRpcCfg,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct WalletClientConfig {
    /// The federations public peg-in-descriptor
    pub peg_in_descriptor: PegInDescriptor,
    /// The bitcoin network the client will use
    pub network: Network,
    /// Confirmations required for a peg in to be accepted by federation
    pub finality_delay: u32,
    pub fee_consensus: FeeConsensus,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub peg_in_abs: fedimint_api::Amount,
    pub peg_out_abs: fedimint_api::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            peg_in_abs: fedimint_api::Amount::ZERO,
            peg_out_abs: fedimint_api::Amount::ZERO,
        }
    }
}

#[async_trait(?Send)]
impl GenerateConfig for WalletConfig {
    type Params = BitcoindRpcCfg;
    type ClientConfig = WalletClientConfig;
    type ConfigMessage = CompressedPublicKey;
    type ConfigError = ();

    fn trusted_dealer_gen(
        peers: &[PeerId],
        params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let secp = secp256k1::Secp256k1::new();

        let btc_pegin_keys = peers
            .iter()
            .map(|&id| (id, secp.generate_keypair(&mut rng)))
            .collect::<Vec<_>>();

        let wallet_cfg: BTreeMap<PeerId, WalletConfig> = btc_pegin_keys
            .iter()
            .map(|(id, (sk, _))| {
                let cfg = WalletConfig::new(
                    btc_pegin_keys
                        .iter()
                        .map(|(peer_id, (_, pk))| (*peer_id, CompressedPublicKey { key: *pk }))
                        .collect(),
                    *sk,
                    peers.threshold(),
                    params.clone(),
                );
                (*id, cfg)
            })
            .collect();

        let descriptor = wallet_cfg[&PeerId::from(0)].peg_in_descriptor.clone();
        let client_cfg = WalletClientConfig::new(descriptor);

        (wallet_cfg, client_cfg)
    }

    fn to_client_config(&self) -> Self::ClientConfig {
        WalletClientConfig {
            peg_in_descriptor: self.peg_in_descriptor.clone(),
            network: self.network,
            fee_consensus: self.fee_consensus.clone(),
            finality_delay: self.finality_delay,
        }
    }

    fn validate_config(&self, identity: &PeerId) {
        let pubkey = secp256k1::PublicKey::from_secret_key_global(&self.peg_in_key);

        assert_eq!(
            self.peer_peg_in_keys.get(identity).unwrap(),
            &CompressedPublicKey::new(pubkey),
            "Bitcoin wallet private key doesn't match multisig pubkey"
        );
    }

    async fn distributed_gen(
        connections: &mut AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
        _task_group: &mut TaskGroup,
    ) -> Result<Option<(Self, Self::ClientConfig)>, Self::ConfigError> {
        let secp = secp256k1::Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut rng);
        let our_key = CompressedPublicKey { key: pk };
        let mut peer_peg_in_keys: BTreeMap<PeerId, CompressedPublicKey> = BTreeMap::new();

        connections.send(peers, our_key.clone()).await;

        peer_peg_in_keys.insert(*our_id, our_key);
        while peer_peg_in_keys.len() < peers.len() {
            if let Some((peer, msg)) = connections.receive().await {
                peer_peg_in_keys.insert(peer, msg);
            } else {
                return Ok(None);
            }
        }

        let wallet_cfg = WalletConfig::new(peer_peg_in_keys, sk, peers.threshold(), params.clone());
        let client_cfg = WalletClientConfig::new(wallet_cfg.peg_in_descriptor.clone());

        Ok(Some((wallet_cfg, client_cfg)))
    }
}

impl WalletConfig {
    pub fn new(
        pubkeys: BTreeMap<PeerId, CompressedPublicKey>,
        sk: SecretKey,
        threshold: usize,
        btc_rpc: BitcoindRpcCfg,
    ) -> Self {
        let peg_in_descriptor = PegInDescriptor::Wsh(
            Wsh::new_sortedmulti(
                threshold,
                pubkeys.iter().map(|(_, pk)| pk.clone()).collect(),
            )
            .unwrap(),
        );

        Self {
            network: Network::Regtest,
            peg_in_descriptor,
            peer_peg_in_keys: pubkeys,
            peg_in_key: sk,
            default_fee: Feerate { sats_per_kvb: 1000 },
            finality_delay: FINALITY_DELAY,
            fee_consensus: FeeConsensus::default(),
            btc_rpc,
        }
    }
}

impl WalletClientConfig {
    pub fn new(peg_in_descriptor: PegInDescriptor) -> Self {
        Self {
            peg_in_descriptor,
            network: Network::Regtest,
            finality_delay: FINALITY_DELAY,
            fee_consensus: Default::default(),
        }
    }
}
