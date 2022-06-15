pub use minimint_core::config::*;

use bitcoin::secp256k1::rand::{CryptoRng, RngCore};
use clap::Parser;
use hbbft::crypto::serde_impl::SerdeSecret;
use minimint_api::config::GenerateConfig;
use minimint_api::PeerId;
use minimint_ln::config::LightningModuleConfig;
use minimint_mint::config::MintConfig;
use minimint_wallet::config::WalletConfig;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use std::path::PathBuf;

#[derive(Parser)]
pub struct ServerOpts {
    pub cfg_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub identity: PeerId,
    pub hbbft_port: u16,
    pub api_port: u16,

    pub peers: BTreeMap<PeerId, Peer>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_sk: hbbft::crypto::serde_impl::SerdeSecret<hbbft::crypto::SecretKey>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_sks: hbbft::crypto::serde_impl::SerdeSecret<hbbft::crypto::SecretKeyShare>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_pk_set: hbbft::crypto::PublicKeySet,

    pub db_path: PathBuf,

    pub wallet: WalletConfig,
    pub mint: MintConfig,
    pub ln: LightningModuleConfig,

    // TODO: make consensus defined
    pub fee_consensus: FeeConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub hbbft_port: u16,
    pub api_port: u16,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_pk: hbbft::crypto::PublicKey,
}

#[derive(Debug)]
pub struct ServerConfigParams {
    pub hbbft_base_port: u16,
    pub api_base_port: u16,
    pub amount_tiers: Vec<minimint_api::Amount>,
}

impl GenerateConfig for ServerConfig {
    type Params = ServerConfigParams;
    type ClientConfig = ClientConfig;

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let netinfo = hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut rng)
            .expect("Could not generate HBBFT netinfo");

        let cfg_peers = netinfo
            .iter()
            .map(|(&id, netinf)| {
                let id_u16: u16 = id.into();
                let peer = Peer {
                    hbbft_port: params.hbbft_base_port + id_u16,
                    api_port: params.api_base_port + id_u16,
                    hbbft_pk: *netinf.public_key(&id).unwrap(),
                };

                (id, peer)
            })
            .collect::<BTreeMap<_, _>>();

        let (wallet_server_cfg, wallet_client_cfg) =
            WalletConfig::trusted_dealer_gen(peers, max_evil, &(), &mut rng);
        let (mint_server_cfg, mint_client_cfg) =
            MintConfig::trusted_dealer_gen(peers, max_evil, params.amount_tiers.as_ref(), &mut rng);
        let (ln_server_cfg, ln_client_cfg) =
            LightningModuleConfig::trusted_dealer_gen(peers, max_evil, &(), &mut rng);

        let fee_consensus = FeeConsensus {
            fee_coin_spend_abs: minimint_api::Amount::ZERO,
            fee_peg_in_abs: minimint_api::Amount::from_sat(500),
            fee_coin_issuance_abs: minimint_api::Amount::ZERO,
            fee_peg_out_abs: minimint_api::Amount::from_sat(500),
            fee_contract_input: minimint_api::Amount::ZERO,
            fee_contract_output: minimint_api::Amount::ZERO,
        };

        let server_config = netinfo
            .iter()
            .map(|(&id, netinf)| {
                let id_u16: u16 = id.into();
                let config = ServerConfig {
                    identity: id,
                    hbbft_port: params.hbbft_base_port + id_u16,
                    api_port: params.api_base_port + id_u16,
                    peers: cfg_peers.clone(),
                    hbbft_sk: SerdeSecret(netinf.secret_key().clone()),
                    hbbft_sks: SerdeSecret(netinf.secret_key_share().unwrap().clone()),
                    hbbft_pk_set: netinf.public_key_set().clone(),
                    db_path: format!("cfg/mint-{}.db", id).into(),
                    wallet: wallet_server_cfg[&id].clone(),
                    mint: mint_server_cfg[&id].clone(),
                    ln: ln_server_cfg[&id].clone(),
                    fee_consensus: fee_consensus.clone(),
                };
                (id, config)
            })
            .collect();

        let client_config = ClientConfig {
            api_endpoints: peers
                .iter()
                .map(|&peer| {
                    format!(
                        "http://127.0.0.1:{}",
                        params.api_base_port + u16::from(peer)
                    )
                })
                .collect(),
            mint: mint_client_cfg,
            wallet: wallet_client_cfg,
            ln: ln_client_cfg,
            fee_consensus,
        };

        (server_config, client_config)
    }
}

impl ServerConfig {
    pub fn get_hbbft_port(&self) -> u16 {
        self.hbbft_port
    }
    pub fn get_api_port(&self) -> u16 {
        self.api_port
    }

    pub fn get_incoming_count(&self) -> u16 {
        self.identity.into()
    }

    pub fn max_faulty(&self) -> usize {
        hbbft::util::max_faulty(self.peers.len())
    }
}
