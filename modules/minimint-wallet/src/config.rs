use crate::keys::CompressedPublicKey;
use crate::{Feerate, PegInDescriptor};
use async_trait::async_trait;
use bitcoin::secp256k1::rand::{CryptoRng, RngCore};
use bitcoin::Network;
use minimint_api::config::GenerateConfig;
use minimint_api::net::peers::AnyPeerConnections;
use minimint_api::PeerId;
use miniscript::descriptor::Wsh;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub network: Network,
    pub peg_in_descriptor: PegInDescriptor,
    pub peer_peg_in_keys: BTreeMap<PeerId, CompressedPublicKey>,
    pub peg_in_key: secp256k1::SecretKey,
    pub finalty_delay: u32,
    pub default_fee: Feerate,
    pub btc_rpc_address: String,
    pub btc_rpc_user: String,
    pub btc_rpc_pass: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletClientConfig {
    /// The federations public peg-in-descriptor
    pub peg_in_descriptor: PegInDescriptor,
    /// The bitcoin network the client will use
    pub network: Network,
}

#[async_trait(?Send)]
impl GenerateConfig for WalletConfig {
    type Params = ();
    type ClientConfig = WalletClientConfig;
    type ConfigMessage = CompressedPublicKey;
    type ConfigError = ();

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        _params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let secp = secp256k1::Secp256k1::new();

        let btc_pegin_keys = peers
            .iter()
            .map(|&id| (id, secp.generate_keypair(&mut rng)))
            .collect::<Vec<_>>();

        let peg_in_descriptor = PegInDescriptor::Wsh(
            Wsh::new_sortedmulti(
                peers.len() - max_evil,
                btc_pegin_keys
                    .iter()
                    .map(|(_, (_, pk))| CompressedPublicKey { key: *pk })
                    .collect(),
            )
            .unwrap(),
        );

        let wallet_cfg = btc_pegin_keys
            .iter()
            .map(|(id, (sk, _))| {
                let cfg = WalletConfig {
                    network: Network::Regtest,
                    peg_in_descriptor: peg_in_descriptor.clone(), // TODO: remove redundancy?
                    peer_peg_in_keys: btc_pegin_keys
                        .iter()
                        .map(|(peer_id, (_, pk))| (*peer_id, CompressedPublicKey { key: *pk }))
                        .collect(),
                    peg_in_key: *sk,
                    finalty_delay: 10,
                    default_fee: Feerate { sats_per_kvb: 1000 },
                    btc_rpc_address: "127.0.0.1:18443".to_string(),
                    btc_rpc_user: "bitcoin".to_string(),
                    btc_rpc_pass: "bitcoin".to_string(),
                };

                (*id, cfg)
            })
            .collect();

        let client_cfg = WalletClientConfig {
            peg_in_descriptor,
            network: Network::Regtest,
        };

        (wallet_cfg, client_cfg)
    }

    async fn distributed_gen(
        connections: &mut AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        max_evil: usize,
        _params: &mut Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, Self::ClientConfig), Self::ConfigError> {
        let secp = secp256k1::Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut rng);
        let our_key = CompressedPublicKey { key: pk };
        let mut peer_peg_in_keys: BTreeMap<PeerId, CompressedPublicKey> = BTreeMap::new();

        connections.send(peers, our_key.clone()).await;

        for _ in 1..peers.len() {
            let (peer, msg) = connections.receive().await;
            peer_peg_in_keys.insert(peer, msg);
        }
        peer_peg_in_keys.insert(*our_id, our_key);
        assert_eq!(peer_peg_in_keys.len(), peers.len());

        let peg_in_descriptor = PegInDescriptor::Wsh(
            Wsh::new_sortedmulti(
                peers.len() - max_evil,
                peer_peg_in_keys.iter().map(|(_, pk)| pk.clone()).collect(),
            )
            .unwrap(),
        );

        let wallet_cfg = WalletConfig {
            network: Network::Regtest,
            peg_in_descriptor: peg_in_descriptor.clone(),
            peer_peg_in_keys,
            peg_in_key: sk,
            finalty_delay: 10,
            default_fee: Feerate { sats_per_kvb: 1000 },
            btc_rpc_address: "127.0.0.1:18443".to_string(),
            btc_rpc_user: "bitcoin".to_string(),
            btc_rpc_pass: "bitcoin".to_string(),
        };

        let client_cfg = WalletClientConfig {
            peg_in_descriptor,
            network: Network::Regtest,
        };

        Ok((wallet_cfg, client_cfg))
    }
}
