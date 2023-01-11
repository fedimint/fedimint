use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fedimint_api::cancellable::Cancellable;
use fedimint_api::module::ModuleInit;
use fedimint_api::net::peers::IMuxPeerConnections;
use fedimint_api::task::TaskGroup;
use fedimint_api::{Amount, PeerId};
use fedimint_ln::LightningModuleConfigGen;
use fedimint_mint::MintConfigGenerator;
use fedimint_server::config::{PeerServerParams, ServerConfig, ServerConfigParams};
use fedimint_server::multiplexed::PeerConnectionMultiplexer;
use fedimint_wallet::WalletConfigGenerator;
use itertools::Itertools;
use rand::rngs::OsRng;
use ring::aead::LessSafeKey;
use tokio_rustls::rustls;
use url::Url;

use crate::encrypt::*;
use crate::*;

pub fn create_cert(
    dir_out_path: PathBuf,
    p2p_url: Url,
    api_url: Url,
    guardian_name: String,
    password: Option<String>,
) -> String {
    let salt: [u8; 16] = rand::random();
    fs::write(dir_out_path.join(SALT_FILE), hex::encode(salt)).expect("write error");
    let key = get_key(password, dir_out_path.join(SALT_FILE));
    gen_tls(&dir_out_path, p2p_url, api_url, guardian_name, &key)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_dkg(
    bind_p2p: SocketAddr,
    bind_api: SocketAddr,
    dir_out_path: &Path,
    max_denomination: Amount,
    federation_name: String,
    certs: Vec<String>,
    bitcoind_rpc: String,
    network: bitcoin::network::constants::Network,
    finality_delay: u32,
    pk: rustls::PrivateKey,
    task_group: &mut TaskGroup,
) -> Cancellable<ServerConfig> {
    let peers: BTreeMap<PeerId, PeerServerParams> = certs
        .into_iter()
        .sorted()
        .enumerate()
        .map(|(idx, cert)| (PeerId::from(idx as u16), parse_peer_params(cert)))
        .collect();

    let cert_string = fs::read_to_string(dir_out_path.join(TLS_CERT)).expect("Can't read file.");

    let our_params = parse_peer_params(cert_string);
    let our_id = peers
        .iter()
        .find(|(_peer, params)| params.cert == our_params.cert)
        .map(|(peer, _)| *peer)
        .expect("could not find our cert among peers");
    let params = ServerConfigParams::gen_params(
        bind_p2p,
        bind_api,
        pk,
        our_id,
        max_denomination,
        &peers,
        federation_name,
        bitcoind_rpc,
        network,
        finality_delay,
    );
    let peer_ids: Vec<PeerId> = peers.keys().cloned().collect();
    let server_conn = fedimint_server::config::connect(
        params.fed_network.clone(),
        params.tls.clone(),
        task_group,
    )
    .await;
    let connections = PeerConnectionMultiplexer::new(server_conn).into_dyn();

    let module_config_gens = ModuleInitRegistry::from(vec![
        Arc::new(WalletConfigGenerator) as Arc<dyn ModuleInit + Send + Sync>,
        Arc::new(MintConfigGenerator),
        Arc::new(LightningModuleConfigGen),
    ]);

    let result = ServerConfig::distributed_gen(
        CODE_VERSION,
        &connections,
        &our_id,
        &peer_ids,
        &params,
        module_config_gens,
        OsRng,
        task_group,
    )
    .await
    .expect("failed to run DKG to generate configs");

    drop(connections);

    result
}

pub fn parse_peer_params(url: String) -> PeerServerParams {
    let split: Vec<&str> = url.split('@').collect();
    assert_eq!(split.len(), 4, "Cannot parse cert string");
    let p2p_url = split[0].parse().expect("could not parse URL");
    let api_url = split[1].parse().expect("could not parse URL");
    let hex_cert = hex::decode(split[3]).expect("cert was not hex encoded");
    PeerServerParams {
        cert: rustls::Certificate(hex_cert),
        p2p_url,
        api_url,
        name: split[2].to_string(),
    }
}

fn gen_tls(
    dir_out_path: &Path,
    p2p_url: Url,
    api_url: Url,
    name: String,
    key: &LessSafeKey,
) -> String {
    let (cert, pk) = fedimint_server::config::gen_cert_and_key(&name).expect("TLS gen failed");
    encrypted_write(pk.0, key, dir_out_path.join(TLS_PK));

    rustls::ServerName::try_from(name.as_str()).expect("Valid DNS name");
    // TODO Base64 encode name, hash fingerprint cert_string
    let cert_url = format!("{}@{}@{}@{}", p2p_url, api_url, name, hex::encode(cert.0));
    fs::write(dir_out_path.join(TLS_CERT), &cert_url).unwrap();
    cert_url
}
