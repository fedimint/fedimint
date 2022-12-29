use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use fedimint_api::cancellable::Cancellable;
use fedimint_api::module::FederationModuleConfigGen;
use fedimint_api::net::peers::IMuxPeerConnections;
use fedimint_api::task::TaskGroup;
use fedimint_api::{Amount, PeerId};
use fedimint_core::modules::ln::LightningModuleConfigGen;
use fedimint_core::modules::mint::MintConfigGenerator;
use fedimint_server::config::{
    ModuleConfigGens, PeerServerParams, ServerConfig, ServerConfigParams,
};
use fedimint_server::multiplexed::PeerConnectionMultiplexer;
use fedimint_wallet::WalletConfigGenerator;
use fedimintd::encrypt::*;
use fedimintd::*;
use itertools::Itertools;
use rand::rngs::OsRng;
use ring::aead::LessSafeKey;
use tokio_rustls::rustls;
use tracing::info;
use tracing_subscriber::EnvFilter;

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

        /// Our external address to announce to peers in our connection string
        #[arg(long = "announce-address")]
        announce_address: String,

        /// Our base port, ports may be used from base_port to base_port+10
        #[arg(long = "base-port", default_value = "4000")]
        base_port: u16,

        /// Our node name, must be unique among peers
        #[arg(long = "name")]
        name: String,

        /// The password that encrypts the configs, will prompt if not passed in
        #[arg(long = "password")]
        password: Option<String>,
    },
    /// All peers must run distributed key gen at the same time to create configs
    Run {
        /// Directory to output all the generated config files
        #[arg(long = "out-dir")]
        dir_out_path: PathBuf,

        /// Federation name, same for all peers
        #[arg(long = "federation-name", default_value = "Hals_trusty_mint")]
        federation_name: String,

        /// Comma-separated list of connection certs from all peers (including ours)
        #[arg(long = "certs", value_delimiter = ',')]
        certs: Vec<String>,

        /// Address we bind to for running key gen
        #[arg(long = "bind_address", default_value = "127.0.0.1")]
        bind_address: String,

        /// `bitcoind` json rpc endpoint
        #[arg(long = "bitcoind-rpc", default_value = "127.0.0.1:18443")]
        bitcoind_rpc: String,

        /// Max denomination of notes issued by the federation (in millisats)
        /// default = 1 BTC
        #[arg(long = "max_denomination", default_value = "100000000000")]
        max_denomination: Amount,

        /// The bitcoin network that fedimint will be running on
        #[arg(long = "network", default_value = "regtest")]
        network: bitcoin::network::constants::Network,

        /// The number of confirmations a deposit transaction requires before accepted by the
        /// federation
        #[arg(long = "finalty", default_value = "10")]
        finality_delay: u32,

        /// The password that encrypts the configs, will prompt if not passed in
        #[arg(long = "password")]
        password: Option<String>,
    },

    ConfigDecrypt {
        /// Encrypted config file
        #[arg(long = "in-file")]
        in_file: PathBuf,
        /// Plaintext config file output
        #[arg(long = "out-file")]
        out_file: PathBuf,
        /// Encryption salt file, otherwise defaults to the salt file from the in_file directory
        #[arg(long = "salt-file")]
        salt_file: Option<PathBuf>,
        /// The password that encrypts the configs, will prompt if not passed in
        #[arg(long = "password")]
        password: Option<String>,
    },

    ConfigEncrypt {
        /// Plaintext config file
        #[arg(long = "in-file")]
        in_file: PathBuf,
        /// Encrypted config file output
        #[arg(long = "out-file")]
        out_file: PathBuf,
        /// Encryption salt file, otherwise defaults to the salt file from the out_file directory
        #[arg(long = "salt-file")]
        salt_file: Option<PathBuf>,
        /// The password that encrypts the configs, will prompt if not passed in
        #[arg(long = "password")]
        password: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut task_group = TaskGroup::new();

    let command: Command = Cli::parse().command;
    match command {
        Command::CreateCert {
            dir_out_path,
            announce_address,
            base_port,
            name,
            password,
        } => {
            let salt: [u8; 16] = rand::random();
            fs::write(dir_out_path.join(SALT_FILE), hex::encode(salt)).expect("write error");
            let key = get_key(password, dir_out_path.join(SALT_FILE));
            let config_str = gen_tls(&dir_out_path, announce_address, base_port, name, &key);
            println!("{}", config_str);
        }
        Command::Run {
            dir_out_path,
            federation_name,
            certs,
            bind_address,
            bitcoind_rpc,
            max_denomination,
            network,
            finality_delay,
            password,
        } => {
            let key = get_key(password, dir_out_path.join(SALT_FILE));
            let pk_bytes = encrypted_read(&key, dir_out_path.join(TLS_PK));
            let server = if let Ok(v) = run_dkg(
                bind_address,
                &dir_out_path,
                max_denomination,
                federation_name,
                certs,
                bitcoind_rpc,
                network,
                finality_delay,
                rustls::PrivateKey(pk_bytes),
                &mut task_group,
            )
            .await
            {
                v
            } else {
                info!("Canceled");
                return;
            };

            encrypted_json_write(&server.private, &key, dir_out_path.join(PRIVATE_CONFIG));
            write_nonprivate_configs(&server, dir_out_path);
        }
        Command::VersionHash => {
            println!("{}", CODE_VERSION);
        }
        Command::ConfigDecrypt {
            in_file,
            out_file,
            salt_file,
            password,
        } => {
            let salt_file = salt_file.unwrap_or_else(|| salt_file_path_from_file_path(&in_file));
            let key = get_key(password, salt_file);
            let decrypted_bytes = encrypted_read(&key, in_file);

            let mut out_file_handle =
                fs::File::create(out_file).expect("Could not create output cfg file");
            out_file_handle.write_all(&decrypted_bytes).unwrap();
        }
        Command::ConfigEncrypt {
            in_file,
            out_file,
            salt_file,
            password,
        } => {
            let mut in_file_handle =
                fs::File::open(in_file).expect("Could not create output cfg file");
            let mut plaintext_bytes = vec![];
            in_file_handle.read_to_end(&mut plaintext_bytes).unwrap();

            let salt_file = salt_file.unwrap_or_else(|| salt_file_path_from_file_path(&out_file));
            let key = get_key(password, salt_file);
            encrypted_write(plaintext_bytes, &key, out_file);
        }
    }
}

fn salt_file_path_from_file_path(file_path: &Path) -> PathBuf {
    file_path
        .parent()
        .expect("File has no parent?!")
        .join(SALT_FILE)
}

#[allow(clippy::too_many_arguments)]
async fn run_dkg(
    bind_address: String,
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
        bind_address,
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
    let server_conn =
        fedimint_server::config::connect(params.server_dkg.clone(), params.tls.clone(), task_group)
            .await;
    let connections = PeerConnectionMultiplexer::new(server_conn).into_dyn();

    let module_config_gens: ModuleConfigGens = vec![
        (
            "wallet",
            Arc::new(WalletConfigGenerator) as Arc<dyn FederationModuleConfigGen>,
        ),
        ("mint", Arc::new(MintConfigGenerator)),
        ("ln", Arc::new(LightningModuleConfigGen)),
    ];

    ServerConfig::distributed_gen(
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
    .expect("failed to run DKG to generate configs")
}

fn parse_peer_params(url: String) -> PeerServerParams {
    let split: Vec<&str> = url.split('@').collect();
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

fn gen_tls(
    dir_out_path: &Path,
    address: String,
    base_port: u16,
    name: String,
    key: &LessSafeKey,
) -> String {
    let (cert, pk) = fedimint_server::config::gen_cert_and_key(&name).expect("TLS gen failed");
    encrypted_write(pk.0, key, dir_out_path.join(TLS_PK));

    rustls::ServerName::try_from(name.as_str()).expect("Valid DNS name");
    // TODO Base64 encode name, hash fingerprint cert_string
    let cert_url = format!("{}@{}@{}@{}", address, base_port, name, hex::encode(cert.0));
    fs::write(dir_out_path.join(TLS_CERT), &cert_url).unwrap();
    cert_url
}
