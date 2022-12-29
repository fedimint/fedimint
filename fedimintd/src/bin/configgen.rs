use std::path::PathBuf;
use std::{fs, sync::Arc};

use clap::{Parser, Subcommand};
use fedimint_api::{module::FederationModuleConfigGen, Amount, NumPeers, PeerId};
use fedimint_core::modules::{ln::LightningModuleConfigGen, mint::MintConfigGenerator};
use fedimint_server::config::{ModuleConfigGens, ServerConfig, ServerConfigParams};
use fedimint_wallet::WalletConfigGenerator;
use fedimintd::{plaintext_json_write, write_nonprivate_configs, CODE_VERSION, PRIVATE_CONFIG};
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

        /// Max denomination of notes issued by the federation (in millisats)
        /// default = 1 BTC
        #[arg(long = "max_denomination", default_value = "100000000000")]
        max_denomination: Amount,

        /// Federation name
        #[arg(long = "federation-name", default_value = "Hals_trusty_mint")]
        federation_name: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::VersionHash => {
            println!("{}", CODE_VERSION);
        }
        Command::Generate {
            dir_out_path: cfg_path,
            num_nodes: nodes,
            base_port,
            max_denomination,
            federation_name,
            bitcoind_rpc,
        } => {
            let rng = OsRng;
            // Recursively create config directory if it doesn't exist
            fs::create_dir_all(&cfg_path).expect("Failed to create config directory");

            let peers = (0..nodes).map(PeerId::from).collect::<Vec<_>>();
            println!(
                "Generating keys such that up to {} peers may fail/be evil",
                peers.max_evil()
            );
            let params = ServerConfigParams::gen_local(
                &peers,
                max_denomination,
                base_port,
                &federation_name,
                &bitcoind_rpc,
            );
            let module_config_gens: ModuleConfigGens = vec![
                (
                    "wallet",
                    Arc::new(WalletConfigGenerator) as Arc<dyn FederationModuleConfigGen>,
                ),
                ("mint", Arc::new(MintConfigGenerator)),
                ("ln", Arc::new(LightningModuleConfigGen)),
            ];

            let server_cfg = ServerConfig::trusted_dealer_gen(
                CODE_VERSION,
                &peers,
                &params,
                module_config_gens,
                rng,
            );

            for (id, server) in server_cfg {
                let path = cfg_path.join(id.to_string());
                fs::create_dir_all(path.clone()).expect("Could not create cfg dir");
                write_nonprivate_configs(&server, path.clone());
                plaintext_json_write(&server.private, path.join(PRIVATE_CONFIG));
            }
        }
    }
}
