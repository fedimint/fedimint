use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, LazyLock};

use fedimint_core::PeerId;
use fedimint_core::core::ModuleKind;
use fedimint_core::module::ApiAuth;
use fedimint_core::setup_code::{PeerEndpoints, PeerSetupCode};
use fedimint_server::config::ConfigGenParams;
use fedimint_server::core::ServerModuleInitRegistry;
use fedimint_server::net::p2p_connector::gen_cert_and_key;
use tokio_rustls::rustls;

pub static API_AUTH: LazyLock<ApiAuth> = LazyLock::new(|| ApiAuth("pass".to_string()));

/// Creates the config gen params for each peer
///
/// Uses peers * 2 ports offset from `base_port`
pub fn local_config_gen_params(
    peers: &[PeerId],
    base_port: u16,
    enable_mint_fees: bool,
    registry: &ServerModuleInitRegistry,
) -> anyhow::Result<HashMap<PeerId, ConfigGenParams>> {
    let enabled_modules: BTreeSet<ModuleKind> =
        registry.iter().map(|(kind, _)| kind.clone()).collect();

    // Generate TLS cert and private key
    let tls_keys: HashMap<
        PeerId,
        (
            rustls::pki_types::CertificateDer<'static>,
            Arc<rustls::pki_types::PrivateKeyDer<'static>>,
        ),
    > = peers
        .iter()
        .map(|peer| {
            (
                *peer,
                gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap(),
            )
        })
        .collect();

    // Generate the P2P and API URL on 2 different ports for each peer
    let connections: BTreeMap<PeerId, PeerSetupCode> = peers
        .iter()
        .map(|peer| {
            let peer_port = base_port + u16::from(*peer) * 3;

            let p2p_url = format!("fedimint://127.0.0.1:{peer_port}");
            let api_url = format!("ws://127.0.0.1:{}", peer_port + 1);

            let params = PeerSetupCode {
                name: format!("peer-{}", peer.to_usize()),
                endpoints: PeerEndpoints::Tcp {
                    api_url: api_url.parse().expect("Should parse"),
                    p2p_url: p2p_url.parse().expect("Should parse"),
                    cert: tls_keys[peer].0.as_ref().to_vec(),
                },
                disable_base_fees: Some(!enable_mint_fees),
                enabled_modules: None,
            };
            (*peer, params)
        })
        .collect();

    peers
        .iter()
        .map(|peer| {
            let params = ConfigGenParams {
                identity: *peer,
                api_auth: API_AUTH.clone(),
                tls_key: Some(tls_keys[peer].1.clone()),
                iroh_api_sk: None,
                iroh_p2p_sk: None,
                peers: connections.clone(),
                meta: BTreeMap::new(),
                disable_base_fees: !enable_mint_fees,
                enabled_modules: enabled_modules.clone(),
                network: bitcoin::Network::Regtest,
            };
            Ok((*peer, params))
        })
        .collect()
}
