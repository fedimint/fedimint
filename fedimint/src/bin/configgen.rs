use clap::Parser;
use fedimint::config::{ServerConfig, ServerConfigParams};
use fedimint_api::config::GenerateConfig;
use fedimint_api::{Amount, PeerId};
use rand::rngs::OsRng;
use std::path::PathBuf;

/// Config generator for Fedimint Federation
///
/// Running this program will generate config
/// files for federation member nodes in directory
/// specified with `out-dir`
#[derive(Parser)]
struct Options {
    /// Directory to output all the generated config files
    #[clap(long = "out-dir")]
    dir_out_path: PathBuf,

    /// Number of nodes in the federation
    #[clap(long = "num-nodes")]
    num_nodes: u16,

    /// Base hbbft port
    #[clap(long = "hbbft-base-port", default_value = "17240")]
    hbbft_base_port: u16,

    /// Base api port
    #[clap(long = "api-base-port", default_value = "17340")]
    api_base_port: u16,

    /// Available denominations of notes issues by the federation (comma separated)
    #[clap(
        long = "denominations",
        value_delimiter = ',',
        min_values = 1,
        required = true
    )]
    denominations: Vec<Amount>,

    /// Federation name
    #[clap(long = "federation-name", default_value = "Hal's trusty mint")]
    federation_name: String,
}

fn main() {
    let Options {
        dir_out_path: cfg_path,
        num_nodes: nodes,
        hbbft_base_port,
        api_base_port,
        denominations: amount_tiers,
        federation_name,
    } = Options::parse();
    let mut rng = OsRng::new().unwrap();

    // Recursively create config directory if it doesn't exist
    std::fs::create_dir_all(&cfg_path).expect("Failed to create config directory");

    let peers = (0..nodes).map(PeerId::from).collect::<Vec<_>>();
    let max_evil = hbbft::util::max_faulty(peers.len());
    println!(
        "Generating keys such that up to {} peers may fail/be evil",
        max_evil
    );
    let params = ServerConfigParams {
        hbbft_base_port,
        api_base_port,
        amount_tiers,
        federation_name,
    };

    let (server_cfg, client_cfg) =
        ServerConfig::trusted_dealer_gen(&peers, max_evil, &params, &mut rng);

    for (id, cfg) in server_cfg {
        let mut path: PathBuf = cfg_path.clone();
        path.push(format!("server-{}.json", id));

        let file = std::fs::File::create(path).expect("Could not create cfg file");
        serde_json::to_writer_pretty(file, &cfg).unwrap();
    }

    let mut client_cfg_file_path: PathBuf = cfg_path;
    client_cfg_file_path.push("client.json");
    let client_cfg_file =
        std::fs::File::create(client_cfg_file_path).expect("Could not create cfg file");

    serde_json::to_writer_pretty(client_cfg_file, &client_cfg).unwrap();
}
