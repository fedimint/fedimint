use std::collections::{BTreeMap, HashMap};

use fedimint_api::config::{BitcoindRpcCfg, ClientConfig, ConfigGenParams};
use fedimint_api::module::FederationModuleConfigGen;
use fedimint_api::{Amount, PeerId};
use fedimint_core::modules::ln::LightningModuleConfigGen;
use fedimint_core::modules::mint::{MintConfigGenParams, MintConfigGenerator};
use fedimint_server::config::{
    gen_cert_and_key, Peer as ServerPeer, SerdeCert, ServerConfig, ServerConfigConsensus,
    ServerConfigLocal, ServerConfigPrivate,
};
use fedimint_server::net::peers::ConnectionConfig;
use fedimint_wallet::{WalletConfigGenParams, WalletConfigGenerator};
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
        .map(|amount| Amount::from_sats(10 * amount))
        .collect();
    let rng = OsRng;
    let num_peers = guardians.len() as u16;
    let peers = (0..num_peers).map(PeerId::from).collect::<Vec<_>>();
    let params = SetupConfigParams {
        federation_name,
        guardians: guardians.clone(),
        amount_tiers,
        btc_rpc,
    };
    let (config_map, client_config) = trusted_dealer_gen(&peers, &params, rng);
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
                name: format!("peer-{}", id.to_usize()),
            };

            (id, peer)
        })
        .collect::<BTreeMap<_, _>>();

    let module_cfg_gen_params = ConfigGenParams::new()
        .attach(WalletConfigGenParams {
            network: bitcoin::network::constants::Network::Regtest,
            bitcoin_rpc: params.btc_rpc.clone(),
            finality_delay: 10,
        })
        .attach(MintConfigGenParams {
            mint_amounts: params.amount_tiers.clone(),
        });
    let module_config_gens: Vec<(&'static str, Box<_>)> = vec![
        (
            "wallet",
            Box::new(WalletConfigGenerator) as Box<dyn FederationModuleConfigGen>,
        ),
        ("mint", Box::new(MintConfigGenerator)),
        ("ln", Box::new(LightningModuleConfigGen)),
    ];

    let module_configs: Vec<_> = module_config_gens
        .iter()
        .map(|(name, gen)| (name, gen.trusted_dealer_gen(peers, &module_cfg_gen_params)))
        .collect();

    let server_config: BTreeMap<_, _> = netinfo
        .iter()
        .map(|(&id, netinf)| {
            let id_u16: u16 = id.into();
            let epoch_keys = epochinfo
                .get(&id)
                .expect("Could not get keys from epoch info");

            let mut config = ServerConfig {
                consensus: ServerConfigConsensus {
                    federation_name: params.federation_name.clone(),
                    peer_certs: tls_keys
                        .iter()
                        .map(|(peer, cert)| (*peer, SerdeCert(cert.0.clone())))
                        .collect(),
                    hbbft_pk_set: netinf.public_key_set().clone(),
                    epoch_pk_set: epoch_keys.public_key_set().clone(),
                    modules: Default::default(),
                },
                local: ServerConfigLocal {
                    peers: cfg_peers.clone(),
                    identity: id,
                    hbbft_bind_addr: format!("0.0.0.0:{}", hbbft_base_port + id_u16),
                    api_bind_addr: format!("0.0.0.0:{}", api_base_port + id_u16),
                    tls_cert: tls_keys[&id].0.clone(),
                    modules: Default::default(),
                    max_connections: 1000,
                },
                private: ServerConfigPrivate {
                    tls_key: tls_keys[&id].1.clone(),
                    hbbft_sks: SerdeSecret(
                        netinf
                            .secret_key_share()
                            .expect("Could not find secret share")
                            .clone(),
                    ),
                    epoch_sks: SerdeSecret(epoch_keys.secret_key_share().unwrap().clone()),
                    modules: Default::default(),
                },
            };

            config.add_modules(
                module_configs
                    .iter()
                    .map(|(name, cfgs)| (name.to_string(), cfgs.0[&id].clone()))
                    .collect(),
            );

            (id, config)
        })
        .collect();

    let client_config = server_config.values().next().unwrap().to_client_config();

    (server_config, client_config)
}
