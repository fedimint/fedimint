use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::ensure;
use fedimint_api::module::DynModuleGen;
use fedimint_api::net::peers::IMuxPeerConnections;
use fedimint_api::task::{sleep, TaskGroup};
use fedimint_api::{Amount, PeerId};
use fedimint_ln::LightningGen;
use fedimint_mint::MintGen;
use fedimint_server::config::{PeerServerParams, ServerConfig, ServerConfigParams};
use fedimint_server::multiplexed::PeerConnectionMultiplexer;
use fedimint_wallet::WalletGen;
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
) -> anyhow::Result<String> {
    let salt: [u8; 16] = rand::random();
    fs::write(dir_out_path.join(SALT_FILE), hex::encode(salt))?;
    let key = get_key(password, dir_out_path.join(SALT_FILE))?;
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
    network: bitcoin::network::constants::Network,
    finality_delay: u32,
    pk: rustls::PrivateKey,
    task_group: &mut TaskGroup,
) -> anyhow::Result<ServerConfig> {
    let mut peers = BTreeMap::<PeerId, PeerServerParams>::new();
    for (idx, cert) in certs.into_iter().sorted().enumerate() {
        peers.insert(PeerId::from(idx as u16), parse_peer_params(cert)?);
    }

    let cert_string = fs::read_to_string(dir_out_path.join(TLS_CERT))?;

    let our_params = parse_peer_params(cert_string)?;
    let our_id = peers
        .iter()
        .find(|(_peer, params)| params.cert == our_params.cert)
        .map(|(peer, _)| *peer)
        .ok_or_else(|| anyhow::Error::msg("Our id not found"))?;

    let params = ServerConfigParams::gen_params(
        bind_p2p,
        bind_api,
        pk,
        our_id,
        max_denomination,
        &peers,
        federation_name,
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
        DynModuleGen::from(WalletGen),
        DynModuleGen::from(MintGen),
        DynModuleGen::from(LightningGen),
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
    .await?;

    // When testing on localhost, it's possible to get
    // one peer that finished dkg, while other didn't.
    // TODO: We should flush the outgoing peer buffers instead
    // to make sure other peers received our messages.
    sleep(Duration::from_millis(1000)).await;

    drop(connections);

    Ok(result?)
}

pub fn parse_peer_params(url: String) -> anyhow::Result<PeerServerParams> {
    let split: Vec<&str> = url.split('@').collect();

    ensure!(split.len() == 4, "Cert string has wrong number of fields");
    let p2p_url = split[0].parse()?;
    let api_url = split[1].parse()?;
    let hex_cert = hex::decode(split[3])?;
    Ok(PeerServerParams {
        cert: rustls::Certificate(hex_cert),
        p2p_url,
        api_url,
        name: split[2].to_string(),
    })
}

fn gen_tls(
    dir_out_path: &Path,
    p2p_url: Url,
    api_url: Url,
    name: String,
    key: &LessSafeKey,
) -> anyhow::Result<String> {
    let (cert, pk) = fedimint_server::config::gen_cert_and_key(&name)?;
    encrypted_write(pk.0, key, dir_out_path.join(TLS_PK))?;

    rustls::ServerName::try_from(name.as_str())?;
    // TODO Base64 encode name, hash fingerprint cert_string
    let cert_url = format!("{}@{}@{}@{}", p2p_url, api_url, name, hex::encode(cert.0));
    fs::write(dir_out_path.join(TLS_CERT), &cert_url)?;
    Ok(cert_url)
}
