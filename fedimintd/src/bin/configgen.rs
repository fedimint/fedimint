use std::path::PathBuf;

use clap::{Parser, Subcommand};
use fedimint_api::config::GenerateConfig;
use fedimint_api::{Amount, NumPeers, PeerId};
use fedimint_server::config::{ServerConfig, ServerConfigParams};
use rand::rngs::OsRng;

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Print the latest git commit hash this bin. was build with
    VersionHash,
    /// Config generator for Fedimint Federation
    ///
    /// Running this program will generate config
    /// files for federation member nodes in directory
    /// specified with `out-dir`
    Generate {
        /// Directory to output all the generated config files
        #[arg(long = "out-dir")]
        dir_out_path: PathBuf,

        /// Number of nodes in the federation
        #[arg(long = "num-nodes")]
        num_nodes: u16,

        /// Base port
        #[arg(long = "base-port", default_value = "17240")]
        base_port: u16,

        /// `bitcoind` json rpc endpoint
        #[arg(long = "bitcoind-rpc", default_value = "127.0.0.1:18443")]
        bitcoind_rpc: String,

        /// Available denominations of notes issues by the federation (comma separated)
        #[arg(
            long = "denominations",
            value_delimiter = ',',
            num_args = 1..,
            required = true
        )]
        denominations: Vec<Amount>,

        /// Federation name
        #[arg(long = "federation-name", default_value = "Hals_trusty_mint")]
        federation_name: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::VersionHash => {
            println!("{}", env!("GIT_HASH"));
        }
        Command::Generate {
            dir_out_path: cfg_path,
            num_nodes: nodes,
            base_port,
            denominations: amount_tiers,
            federation_name,
            bitcoind_rpc,
        } => {
            let mut rng = OsRng;
            // Recursively create config directory if it doesn't exist
            std::fs::create_dir_all(&cfg_path).expect("Failed to create config directory");

            let peers = (0..nodes).map(PeerId::from).collect::<Vec<_>>();
            println!(
                "Generating keys such that up to {} peers may fail/be evil",
                peers.max_evil()
            );
            let params = ServerConfigParams::gen_local(
                &peers,
                amount_tiers.to_vec(),
                base_port,
                &federation_name,
                &bitcoind_rpc,
            );

            let (server_cfg, client_cfg) =
                ServerConfig::trusted_dealer_gen(&peers, &params, &mut rng);

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
    }
}
