use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use fedimint_api::module::ModuleInit;
use fedimint_api::task::TaskGroup;
use fedimint_api::Amount;
use fedimint_ln::LightningModuleConfigGen;
use fedimint_mint::MintConfigGenerator;
use fedimint_server::config::ModuleInitRegistry;
use fedimint_wallet::WalletConfigGenerator;
use fedimintd::distributedgen::{create_cert, run_dkg};
use fedimintd::encrypt::*;
use fedimintd::*;
use tokio_rustls::rustls;
use tracing::info;
use tracing_subscriber::EnvFilter;
use url::Url;

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
        #[arg(long = "out-dir", env = "FM_DATA_DIR")]
        dir_out_path: PathBuf,

        /// Our API address for clients to connect to us
        #[arg(long = "api-url")]
        api_url: Url,

        /// Our external address for communicating with our peers
        #[arg(long = "p2p-url")]
        p2p_url: Url,

        /// Our node name, must be unique among peers
        #[arg(long = "name")]
        name: String,

        /// The password that encrypts the configs, will prompt if not passed in
        #[arg(env = "FM_PASSWORD")]
        password: Option<String>,
    },
    /// All peers must run distributed key gen at the same time to create configs
    Run {
        /// Directory to output all the generated config files
        #[arg(long = "out-dir")]
        dir_out_path: PathBuf,

        /// Address we bind to for federation communication
        #[arg(long = "bind-p2p", default_value = "127.0.0.1:8173")]
        bind_p2p: SocketAddr,

        /// Address we bind to for exposing the API
        #[arg(long = "bind-api", default_value = "127.0.0.1:8174")]
        bind_api: SocketAddr,

        /// Federation name, same for all peers
        #[arg(long = "federation-name", default_value = "Hals_trusty_mint")]
        federation_name: String,

        /// Comma-separated list of connection certs from all peers (including ours)
        #[arg(long = "certs", value_delimiter = ',')]
        certs: Vec<String>,

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
        #[arg(env = "FM_PASSWORD")]
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
        #[arg(env = "FM_PASSWORD")]
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
        #[arg(env = "FM_PASSWORD")]
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

    let module_config_gens = ModuleInitRegistry::from(vec![
        Arc::new(WalletConfigGenerator) as Arc<dyn ModuleInit + Send + Sync>,
        Arc::new(MintConfigGenerator),
        Arc::new(LightningModuleConfigGen),
    ]);

    let mut task_group = TaskGroup::new();

    let command: Command = Cli::parse().command;
    match command {
        Command::CreateCert {
            dir_out_path,
            p2p_url,
            api_url,
            name,
            password,
        } => {
            let config_str = create_cert(dir_out_path, p2p_url, api_url, name, password);
            println!("{}", config_str);
        }
        Command::Run {
            dir_out_path,
            federation_name,
            certs,
            bind_p2p,
            bind_api,
            bitcoind_rpc,
            max_denomination,
            network,
            finality_delay,
            password,
        } => {
            let key = get_key(password, dir_out_path.join(SALT_FILE));
            let pk_bytes = encrypted_read(&key, dir_out_path.join(TLS_PK));
            let server = if let Ok(v) = run_dkg(
                bind_p2p,
                bind_api,
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
            write_nonprivate_configs(&server, dir_out_path, &module_config_gens);
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
