use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aead::{encrypted_read, encrypted_write, get_key};
use clap::{Parser, Subcommand};
use fedimint_core::config::{DkgError, ModuleGenRegistry};
use fedimint_core::module::ModuleGen;
use fedimint_core::task::{self, TaskGroup};
use fedimint_core::Amount;
use fedimint_ln::LightningGen;
use fedimint_logging::TracingSetup;
use fedimint_mint::MintGen;
use fedimint_server::config::io::{create_cert, write_server_config, CODE_VERSION, SALT_FILE};
use fedimint_server::config::{ServerConfig, ServerConfigParams};
use fedimint_wallet::WalletGen;
use tracing::info;
use url::Url;

use crate::configure_modules;

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the latest git commit hash this bin. was build with
    VersionHash,
    /// Creates a connection cert string that must be shared with all other
    /// peers
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

        /// The password that encrypts the configs
        #[arg(env = "FM_PASSWORD")]
        password: String,
    },
    /// All peers must run distributed key gen at the same time to create
    /// configs
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

        /// Comma-separated list of connection certs from all peers (including
        /// ours)
        #[arg(long = "certs", value_delimiter = ',')]
        certs: Vec<String>,

        /// Max denomination of notes issued by the federation (in millisats)
        /// default = 1 BTC
        #[arg(long = "max_denomination", default_value = "100000000000")]
        max_denomination: Amount,

        /// The bitcoin network that fedimint will be running on
        #[arg(long = "network", default_value = "regtest")]
        network: bitcoin::network::constants::Network,

        /// The number of confirmations a deposit transaction requires before
        /// accepted by the federation
        #[arg(long = "finalty", default_value = "10")]
        finality_delay: u32,

        /// The password that encrypts the configs
        #[arg(env = "FM_PASSWORD")]
        password: String,
    },

    ConfigDecrypt {
        /// Encrypted config file
        #[arg(long = "in-file")]
        in_file: PathBuf,
        /// Plaintext config file output
        #[arg(long = "out-file")]
        out_file: PathBuf,
        /// Encryption salt file, otherwise defaults to the salt file from the
        /// in_file directory
        #[arg(long = "salt-file")]
        salt_file: Option<PathBuf>,
        /// The password that encrypts the configs
        #[arg(env = "FM_PASSWORD")]
        password: String,
    },

    ConfigEncrypt {
        /// Plaintext config file
        #[arg(long = "in-file")]
        in_file: PathBuf,
        /// Encrypted config file output
        #[arg(long = "out-file")]
        out_file: PathBuf,
        /// Encryption salt file, otherwise defaults to the salt file from the
        /// out_file directory
        #[arg(long = "salt-file")]
        salt_file: Option<PathBuf>,
        /// The password that encrypts the configs
        #[arg(env = "FM_PASSWORD")]
        password: String,
    },
}

/// `distributedgen` builder
///
/// See [`super::fedimintd::Fedimintd`] for more info.
pub struct DistributedGen {
    module_gens: ModuleGenRegistry,
    opts: Cli,
}

impl DistributedGen {
    pub fn new() -> anyhow::Result<DistributedGen> {
        info!("Starting distributedgen (version: {CODE_VERSION})");

        let opts = Cli::parse();
        TracingSetup::default().init()?;

        Ok(Self {
            module_gens: ModuleGenRegistry::new(),
            opts,
        })
    }

    pub fn with_module<T>(mut self, gen: T) -> Self
    where
        T: ModuleGen + 'static + task::MaybeSend + task::MaybeSync,
    {
        self.module_gens.attach(gen);
        self
    }

    pub fn with_default_modules(self) -> Self {
        self.with_module(LightningGen)
            .with_module(MintGen)
            .with_module(WalletGen)
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let mut task_group = TaskGroup::new();

        match self.opts.command {
            Command::CreateCert {
                dir_out_path,
                p2p_url,
                api_url,
                name,
                password,
            } => {
                let config_str = create_cert(dir_out_path, p2p_url, api_url, name, &password)?;
                Ok(println!("{config_str}"))
            }
            Command::Run {
                dir_out_path,
                federation_name,
                certs,
                bind_p2p,
                bind_api,
                max_denomination,
                network,
                finality_delay,
                password,
            } => {
                let params = ServerConfigParams::parse_from_connect_strings(
                    bind_p2p,
                    bind_api,
                    &dir_out_path,
                    federation_name,
                    certs,
                    &password,
                    configure_modules(max_denomination, network, finality_delay),
                )?;
                let server = match ServerConfig::distributed_gen(
                    &params,
                    self.module_gens.clone(),
                    &mut task_group,
                )
                .await
                {
                    Ok(server) => server,
                    Err(DkgError::Cancelled(_)) => return Ok(info!("DKG cancelled")),
                    Err(DkgError::Failed(err)) => return Err(err),
                };

                write_server_config(&server, dir_out_path, &password, &self.module_gens)
            }
            Command::VersionHash => Ok(println!("{CODE_VERSION}")),
            Command::ConfigDecrypt {
                in_file,
                out_file,
                salt_file,
                password,
            } => {
                let salt_file =
                    salt_file.unwrap_or_else(|| salt_file_path_from_file_path(&in_file));
                let key = get_key(&password, salt_file)?;
                let decrypted_bytes = encrypted_read(&key, in_file)?;

                let mut out_file_handle =
                    fs::File::create(out_file).expect("Could not create output cfg file");
                out_file_handle.write_all(&decrypted_bytes)?;
                Ok(())
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

                let salt_file =
                    salt_file.unwrap_or_else(|| salt_file_path_from_file_path(&out_file));
                let key = get_key(&password, salt_file)?;
                encrypted_write(plaintext_bytes, &key, out_file)
            }
        }
    }
}

fn salt_file_path_from_file_path(file_path: &Path) -> PathBuf {
    file_path
        .parent()
        .expect("File has no parent?!")
        .join(SALT_FILE)
}
