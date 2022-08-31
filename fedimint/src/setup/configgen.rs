use crate::config::{ServerConfig, ServerConfigParams};
use crate::setup::Peer;
use fedimint_api::config::GenerateConfig;
use fedimint_api::{Amount, PeerId};
use rand::rngs::OsRng;
use std::path::PathBuf;

pub fn configgen(cfg_path: PathBuf, setup_peers: Vec<Peer>) {
    let hbbft_base_port = 17240;
    let api_base_port = 17340;
    let amount_tiers = vec![Amount::from_sat(1), Amount::from_sat(10)];

    let mut rng = OsRng::new().unwrap();

    // Recursively create config directory if it doesn't exist
    std::fs::create_dir_all(&cfg_path).expect("Failed to create config directory");

    let num_peers = setup_peers.len() as u16;
    let peers = (0..num_peers).map(PeerId::from).collect::<Vec<_>>();
    let max_evil = hbbft::util::max_faulty(peers.len());
    println!(
        "Generating keys such that up to {} peers may fail/be evil",
        max_evil
    );
    let params = ServerConfigParams {
        hbbft_base_port,
        api_base_port,
        amount_tiers,
    };

    let (server_cfg, client_cfg) =
        ServerConfig::trusted_dealer_gen(&peers, max_evil, &params, &mut rng);

    for (id, cfg) in server_cfg {
        let mut path: PathBuf = cfg_path.clone();
        let matches: &[&str] = &setup_peers[id.to_usize()]
            .connection_string
            .split("@")
            .collect::<Vec<&str>>();
        path.push(format!("{}.json", matches[0]));

        let file = std::fs::File::create(path).expect("Could not create cfg file");
        serde_json::to_writer_pretty(file, &cfg).unwrap();
    }

    let mut client_cfg_file_path: PathBuf = cfg_path;
    client_cfg_file_path.push("client.json");
    let client_cfg_file =
        std::fs::File::create(client_cfg_file_path).expect("Could not create cfg file");

    serde_json::to_writer_pretty(client_cfg_file, &client_cfg).unwrap();
}
