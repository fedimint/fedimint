use crate::keys::CompressedPublicKey;
use crate::{Feerate, PegInDescriptor};
use bitcoin::secp256k1::rand::{CryptoRng, RngCore};
use bitcoin::Network;
use fedimint_api::config::GenerateConfig;
use fedimint_api::PeerId;
use miniscript::descriptor::Wsh;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const FINALITY_DELAY: u32 = 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub network: Network,
    pub peg_in_descriptor: PegInDescriptor,
    pub peer_peg_in_keys: BTreeMap<PeerId, CompressedPublicKey>,
    pub peg_in_key: secp256k1::SecretKey,
    pub finality_delay: u32,
    pub default_fee: Feerate,
    pub btc_rpc_address: String,
    pub btc_rpc_user: String,
    pub btc_rpc_pass: String,
    pub fee_consensus: FeeConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletClientConfig {
    /// The federations public peg-in-descriptor
    pub peg_in_descriptor: PegInDescriptor,
    /// The bitcoin network the client will use
    pub network: Network,
    /// Confirmations required for a peg in to be accepted by federation
    pub finality_delay: u32,
    pub fee_consensus: FeeConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl GenerateConfig for WalletConfig {
    type Params = ();
    type ClientConfig = WalletClientConfig;

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
                    finality_delay: FINALITY_DELAY,
                    default_fee: Feerate { sats_per_kvb: 1000 },
                    btc_rpc_address: "127.0.0.1:18443".to_string(),
                    btc_rpc_user: "bitcoin".to_string(),
                    btc_rpc_pass: "bitcoin".to_string(),
                    fee_consensus: FeeConsensus::default(),
                };

                (*id, cfg)
            })
            .collect();

        let client_cfg = WalletClientConfig {
            peg_in_descriptor,
            network: Network::Regtest,
            finality_delay: FINALITY_DELAY,
            fee_consensus: FeeConsensus::default(),
        };

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
}
