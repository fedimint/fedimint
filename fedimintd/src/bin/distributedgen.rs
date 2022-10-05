use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use fedimint_api::config::GenerateConfig;
use fedimint_api::{Amount, PeerId};
use fedimint_core::config::ClientConfig;
use fedimint_server::config::{PeerServerParams, ServerConfig, ServerConfigParams};
use itertools::Itertools;
use rand::rngs::OsRng;
use tokio_rustls::rustls;
use tracing_subscriber::EnvFilter;

const TLS_PK: &str = "tls-pk";
const TLS_CERT: &str = "tls-cert";

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the latest git commit hash this bin. was build with
    VersionHash,
    /// Creates a connection cert string that must be shared with all other peers
    CreateCert {
        /// Directory to output all the generated config files
        #[arg(long = "out-dir")]
        dir_out_path: PathBuf,

        /// Our external address
        #[arg(long = "address", default_value = "127.0.0.1")]
        address: String,

        /// Our base port, ports may be used from base_port to base_port+10
        #[arg(long = "base-port", default_value = "4000")]
        base_port: u16,

        /// Our node name, must be unique among peers
        #[arg(long = "name")]
        name: String,
    },
    /// All peers must run distributed key gen at the same time to create configs
    Run {
        /// Directory to output all the generated config files
        #[arg(long = "out-dir")]
        dir_out_path: PathBuf,

        /// Federation name, same for all peers
        #[arg(long = "federation-name", default_value = "Hal's trusty mint")]
        federation_name: String,

        /// Comma-separated list of connection certs from all peers (including ours)
        #[arg(long = "certs", value_delimiter = ',')]
        certs: Vec<String>,

        /// `bitcoind` json rpc endpoint
        #[arg(long = "bitcoind-rpc", default_value = "127.0.0.1:18443")]
        bitcoind_rpc: String,

        /// Available denominations of notes issues by the federation (comma separated)
        /// default = 1 msat - 1M sats by powers of 10
        #[arg(
        long = "denominations",
        value_delimiter = ',',
        num_args = 1..,
        default_value = "1,10,100,1000,10000,100000,1000000,10000000,100000000,1000000000"
        )]
        denominations: Vec<Amount>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let command: Command = Cli::parse().command;
    match command {
        Command::CreateCert {
            dir_out_path,
            address,
            base_port,
            name,
        } => {
            println!("{}", gen_tls(&dir_out_path, address, base_port, name));
        }
        Command::Run {
            dir_out_path,
            federation_name,
            certs,
            bitcoind_rpc,
            denominations,
        } => {
            let (server, client) = run_dkg(
                &dir_out_path,
                denominations,
                federation_name,
                certs,
                bitcoind_rpc,
            )
            .await;

            let server_path =
                dir_out_path.join(format!("server-{}.json", server.identity.to_usize()));
            let server_file = fs::File::create(server_path).expect("Could not create cfg file");
            serde_json::to_writer_pretty(server_file, &server).unwrap();

            let client_path: PathBuf = dir_out_path.join("client.json");
            let client_file = fs::File::create(client_path).expect("Could not create cfg file");
            serde_json::to_writer_pretty(client_file, &client).unwrap();
        }
        Command::VersionHash => {
            println!("{}", env!("GIT_HASH"));
        }
    }
}

async fn run_dkg(
    dir_out_path: &Path,
    denominations: Vec<Amount>,
    federation_name: String,
    certs: Vec<String>,
    bitcoind_rpc: String,
) -> (ServerConfig, ClientConfig) {
    let peers: BTreeMap<PeerId, PeerServerParams> = certs
        .into_iter()
        .sorted()
        .enumerate()
        .map(|(idx, cert)| (PeerId::from(idx as u16), parse_peer_params(cert)))
        .collect();

    let pk_string = fs::read_to_string(dir_out_path.join(TLS_PK)).expect("Can't read file.");
    let cert_string = fs::read_to_string(dir_out_path.join(TLS_CERT)).expect("Can't read file.");
    let pk = rustls::PrivateKey(hex::decode(pk_string).expect("not hex encoded"));
    let our_params = parse_peer_params(cert_string);
    let our_id = peers
        .iter()
        .find(|(_peer, params)| params.cert == our_params.cert)
        .map(|(peer, _)| *peer)
        .expect("could not find our cert among peers");
    let params = ServerConfigParams::gen_params(
        pk,
        our_id,
        denominations,
        &peers,
        federation_name,
        bitcoind_rpc,
    );
    let param_map = HashMap::from([(our_id, params.clone())]);
    let peer_ids: Vec<PeerId> = peers.keys().cloned().collect();
    let mut server_conn = fedimint_server::config::connect(params.server_dkg, params.tls).await;
    let rng = OsRng::new().unwrap();
    ServerConfig::distributed_gen(&mut server_conn, &our_id, &peer_ids, &param_map, rng)
        .await
        .expect("failed to run DKG to generate configs")
}

fn parse_peer_params(url: String) -> PeerServerParams {
    let split: Vec<&str> = url.split(':').collect();
    assert_eq!(split.len(), 4, "Cannot parse cert string");
    let base_port = split[1].parse().expect("could not parse base port");
    let hex_cert = hex::decode(split[3]).expect("cert was not hex encoded");
    PeerServerParams {
        cert: rustls::Certificate(hex_cert),
        address: split[0].to_string(),
        base_port,
        name: split[2].to_string(),
    }
}

fn gen_tls(dir_out_path: &Path, address: String, base_port: u16, name: String) -> String {
    let (cert, pk) = fedimint_server::config::gen_cert_and_key(&name).expect("TLS gen failed");

    let pk_string = hex::encode(pk.0);
    let cert_string = hex::encode(cert.0);
    rustls::ServerName::try_from(name.as_str()).expect("Valid DNS name");
    // TODO Base64 encode name, hash fingerprint cert_string
    let cert_url = format!("{}:{}:{}:{}", address, base_port, name, cert_string);

    fs::write(dir_out_path.join(TLS_PK), &pk_string).unwrap();
    fs::write(dir_out_path.join(TLS_CERT), &cert_url).unwrap();
    cert_url
}
