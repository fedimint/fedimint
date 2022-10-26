use std::collections::{BTreeMap, HashMap};

use fedimint_api::config::{BitcoindRpcCfg, GenerateConfig};
use fedimint_api::{Amount, PeerId};
use fedimint_core::config::{ClientConfig, Node};
use fedimint_core::modules::ln::config::LightningModuleConfig;
use fedimint_core::modules::mint::config::MintConfig;
use fedimint_server::config::{gen_cert_and_key, Peer as ServerPeer, ServerConfig};
use fedimint_server::net::peers::ConnectionConfig;
use fedimint_wallet::config::WalletConfig;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use threshold_crypto::serde_impl::SerdeSecret;
use url::Url;

use crate::ui::Guardian;

pub fn configgen(
    federation_name: String,
    guardians: Vec<Guardian>,
    btc_rpc: BitcoindRpcCfg,
) -> (Vec<(Guardian, ServerConfig)>, ClientConfig) {
    let amount_tiers = (1..12)
        .map(|amount| Amount::from_sat(10 * amount))
        .collect();
    let mut rng = OsRng;
    let num_peers = guardians.len() as u16;
    let peers = (0..num_peers).map(PeerId::from).collect::<Vec<_>>();
    let params = SetupConfigParams {
        federation_name,
        guardians: guardians.clone(),
        amount_tiers,
        btc_rpc,
    };
    let (config_map, client_config) = trusted_dealer_gen(&peers, &params, &mut rng);
    let server_configs = guardians
        .into_iter()
        .enumerate()
        .map(|(index, guardian)| {
            let peer_id = PeerId::from(index as u16);
            let server_config = config_map.get(&peer_id).expect("Peer not found").clone();
            (guardian, server_config)
        })
        .collect();
    (server_configs, client_config)
}
#[derive(Debug)]
pub struct SetupConfigParams {
    pub federation_name: String,
    pub guardians: Vec<Guardian>,
    pub amount_tiers: Vec<fedimint_api::Amount>,
    pub btc_rpc: BitcoindRpcCfg,
}

fn trusted_dealer_gen(
    peers: &[PeerId],
    params: &SetupConfigParams,
    mut rng: impl RngCore + CryptoRng,
) -> (BTreeMap<PeerId, ServerConfig>, ClientConfig) {
    let hbbft_base_port = 17240;
    let api_base_port = 17340;
    let netinfo = hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut rng)
        .expect("Could not generate HBBFT netinfo");
    let epochinfo = hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut rng)
        .expect("Could not generate HBBFT epochinfo");
    let hostnames: Vec<String> = params
        .guardians
        .iter()
        .map(|peer| {
            // FIXME: regex
            let parts: Vec<&str> = peer.connection_string.split('@').collect();
            parts[1].to_string()
        })
        .collect();

    let tls_keys = peers
        .iter()
        .map(|peer| {
            let (cert, key) = gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap();
            (*peer, (cert, key))
        })
        .collect::<HashMap<_, _>>();

    let cfg_peers = netinfo
        .iter()
        .map(|(&id, _)| {
            let id_u16: u16 = id.into();
            let peer = ServerPeer {
                hbbft: ConnectionConfig {
                    address: format!(
                        "{}:{}",
                        hostnames[id_u16 as usize].clone(),
                        hbbft_base_port + id_u16
                    ),
                },
                api_addr: {
                    let s = format!(
                        "ws://{}:{}",
                        hostnames[id_u16 as usize].clone(),
                        api_base_port + id_u16
                    );
                    Url::parse(&s).expect("Could not parse URL")
                },
                tls_cert: tls_keys[&id].0.clone(),
                name: format!("peer-{}", id.to_usize()),
            };

            (id, peer)
        })
        .collect::<BTreeMap<_, _>>();

    let (wallet_server_cfg, wallet_client_cfg) =
        WalletConfig::trusted_dealer_gen(peers, &params.btc_rpc, &mut rng);
    let (mint_server_cfg, mint_client_cfg) =
        MintConfig::trusted_dealer_gen(peers, params.amount_tiers.as_ref(), &mut rng);
    let (ln_server_cfg, ln_client_cfg) =
        LightningModuleConfig::trusted_dealer_gen(peers, &(), &mut rng);

    let server_config = netinfo
        .iter()
        .map(|(&id, netinf)| {
            let id_u16: u16 = id.into();
            let epoch_keys = epochinfo
                .get(&id)
                .expect("Could not get keys from epoch info");
            let config = ServerConfig {
                federation_name: params.federation_name.clone(),
                identity: id,
                hbbft_bind_addr: format!("0.0.0.0:{}", hbbft_base_port + id_u16),
                api_bind_addr: format!("0.0.0.0:{}", api_base_port + id_u16),
                tls_cert: tls_keys[&id].0.clone(),
                tls_key: tls_keys[&id].1.clone(),
                peers: cfg_peers.clone(),
                hbbft_sks: SerdeSecret(
                    netinf
                        .secret_key_share()
                        .expect("Could not find secret share")
                        .clone(),
                ),
                hbbft_pk_set: netinf.public_key_set().clone(),
                epoch_sks: SerdeSecret(epoch_keys.secret_key_share().unwrap().clone()),
                epoch_pk_set: epoch_keys.public_key_set().clone(),
                wallet: wallet_server_cfg[&id].clone(),
                mint: mint_server_cfg[&id].clone(),
                ln: ln_server_cfg[&id].clone(),
            };
            (id, config)
        })
        .collect();

    let client_config = ClientConfig {
        federation_name: params.federation_name.clone(),
        nodes: peers
            .iter()
            .map(|&peer| {
                let index = u16::from(peer);
                let s = format!(
                    "ws://{}:{}",
                    hostnames[index as usize].clone(),
                    api_base_port
                );
                let url = Url::parse(&s).expect("Could not parse URL");
                Node {
                    url,
                    name: params.guardians[index as usize].name.clone(),
                }
            })
            .collect(),
        mint: mint_client_cfg,
        wallet: wallet_client_cfg,
        ln: ln_client_cfg,
    };

    (server_config, client_config)
}
