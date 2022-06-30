use clap::Parser;
use minimint::config::{load_from_file, ServerConfig, ServerConfigParams};
use minimint_api::config::GenerateConfig;
use minimint_api::{Amount, PeerId};
use mint_client::ln::gateway::LightningGateway;
use mint_client::ClientAndGatewayConfig;
use rand::rngs::OsRng;
use reqwest::Url;
use std::path::PathBuf;

#[derive(Parser)]
struct Options {
    cfg_path: PathBuf,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    /// Generate federation config
    Federation {
        nodes: u16,
        hbbft_base_port: u16,
        api_base_port: u16,
        amount_tiers: Vec<Amount>,
    },

    /// Generate client config
    Client { gateway_url: Option<Url> },
}

#[tokio::main]
async fn main() {
    let opts = Options::parse();
    let mut rng = OsRng::new().unwrap();

    match opts.command {
        Command::Federation {
            nodes,
            hbbft_base_port,
            api_base_port,
            amount_tiers,
        } => {
            // Recursively create config directory if it doesn't exist
            std::fs::create_dir_all(&opts.cfg_path).expect("Failed to create config directory");

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
            };

            let (server_cfg, client_cfg) =
                ServerConfig::trusted_dealer_gen(&peers, max_evil, &params, &mut rng);

            for (id, cfg) in server_cfg {
                let mut path: PathBuf = opts.cfg_path.clone();
                path.push(format!("server-{}.json", id));

                let file = std::fs::File::create(path).expect("Could not create cfg file");
                serde_json::to_writer_pretty(file, &cfg).unwrap();
            }

            let mut client_cfg_file_path: PathBuf = opts.cfg_path;
            client_cfg_file_path.push("federation_client.json");
            let client_cfg_file =
                std::fs::File::create(client_cfg_file_path).expect("Could not create cfg file");

            serde_json::to_writer_pretty(client_cfg_file, &client_cfg).unwrap();
        }
        Command::Client { gateway_url } => {
            let gateway = if let Some(url) = gateway_url {
                let info_url = url.join("/info").unwrap();
                let config: LightningGateway = reqwest::get(info_url)
                    .await
                    .expect("Couldn't connect to gateway")
                    .json()
                    .await
                    .expect("Coudln't parse gateway response");
                Some(config)
            } else {
                None
            };

            let federation_client_cfg_path = opts.cfg_path.join("federation_client.json");
            let federation_client_cfg: minimint::config::ClientConfig =
                load_from_file(&federation_client_cfg_path);

            let client_cfg = ClientAndGatewayConfig {
                client: federation_client_cfg,
                gateway,
            };

            let client_cfg_file_path: PathBuf = opts.cfg_path.join("client.json");
            let client_cfg_file =
                std::fs::File::create(client_cfg_file_path).expect("Could not create cfg file");
            serde_json::to_writer_pretty(client_cfg_file, &client_cfg).unwrap();
        }
    }
}
