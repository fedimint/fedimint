mod client;
mod db_locked;
pub mod envs;
mod utils;

use core::fmt;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, result};

use anyhow::format_err;
use bip39::Mnemonic;
use clap::{Args, CommandFactory, Parser, Subcommand};
use db_locked::LockedBuilder;
use fedimint_aead::{encrypted_read, encrypted_write, get_encryption_key};
use fedimint_bip39::Bip39RootSecretStrategy;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitRegistry};
use fedimint_client::module::ClientModule as _;
use fedimint_client::secret::{get_default_client_secret, RootSecretStrategy};
use fedimint_client::{AdminCreds, Client, ClientBuilder, ClientHandleArc};
use fedimint_core::admin_client::{ConfigGenConnectionsRequest, ConfigGenParamsRequest};
use fedimint_core::api::{
    DynGlobalApi, FederationApiExt, FederationError, IRawFederationApi, InviteCode, WsFederationApi,
};
use fedimint_core::config::{
    ClientConfig, FederationId, FederationIdPrefix, ServerModuleConfigGenParamsRegistry,
};
use fedimint_core::core::OperationId;
use fedimint_core::db::{Database, DatabaseValue};
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::util::{handle_version_hash_command, retry, ConstantBackoff, SafeUrl};
use fedimint_core::{fedimint_build_code_version_env, PeerId, TieredMulti};
use fedimint_ln_client::LightningClientInit;
use fedimint_logging::{TracingSetup, LOG_CLIENT};
use fedimint_meta_client::MetaClientInit;
use fedimint_mint_client::{MintClientInit, MintClientModule, OOBNotes, SpendableNote};
use fedimint_server::config::io::SALT_FILE;
use fedimint_wallet_client::api::WalletFederationApi;
use fedimint_wallet_client::{WalletClientInit, WalletClientModule};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tracing::{debug, error, info};
use utils::parse_peer_id;

use crate::client::ClientCmd;
use crate::envs::{FM_CLIENT_DIR_ENV, FM_OUR_ID_ENV, FM_PASSWORD_ENV};

/// Type of output the cli produces
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
enum CliOutput {
    VersionHash {
        hash: String,
    },

    UntypedApiOutput {
        value: Value,
    },

    WaitBlockCount {
        reached: u64,
    },

    InviteCode {
        invite_code: InviteCode,
    },

    DecodeInviteCode {
        url: SafeUrl,
        federation_id: FederationId,
    },

    JoinFederation {
        joined: String,
    },

    DecodeTransaction {
        transaction: String,
    },

    EpochCount {
        count: u64,
    },

    ConfigDecrypt,

    ConfigEncrypt,

    Raw(serde_json::Value),
}

impl fmt::Display for CliOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

/// `Result` with `CliError` as `Error`
type CliResult<E> = Result<E, CliError>;

/// `Result` with `CliError` as `Error` and `CliOutput` as `Ok`
type CliOutputResult = Result<CliOutput, CliError>;

/// Cli error
#[derive(Serialize, Error)]
#[serde(tag = "error", rename_all(serialize = "snake_case"))]
struct CliError {
    error: String,
}

/// Extension trait making turning Results/Errors into
/// [`CliError`]/[`CliOutputResult`] easier
trait CliResultExt<O, E> {
    /// Map error into `CliError` wrapping the original error message
    fn map_err_cli(self) -> Result<O, CliError>;
    /// Map error into `CliError` using custom error message `msg`
    fn map_err_cli_msg(self, msg: impl Into<String>) -> Result<O, CliError>;
}

impl<O, E> CliResultExt<O, E> for result::Result<O, E>
where
    E: Into<anyhow::Error>,
{
    fn map_err_cli(self) -> Result<O, CliError> {
        self.map_err(|e| {
            let e = e.into();
            CliError {
                error: e.to_string(),
            }
        })
    }

    fn map_err_cli_msg(self, msg: impl Into<String>) -> Result<O, CliError> {
        self.map_err(|_| CliError { error: msg.into() })
    }
}

/// Extension trait to make turning `Option`s into
/// [`CliError`]/[`CliOutputResult`] easier
trait CliOptionExt<O> {
    fn ok_or_cli_msg(self, msg: impl Into<String>) -> Result<O, CliError>;
}

impl<O> CliOptionExt<O> for Option<O> {
    fn ok_or_cli_msg(self, msg: impl Into<String>) -> Result<O, CliError> {
        self.ok_or_else(|| CliError { error: msg.into() })
    }
}

// TODO: Refactor federation API errors to just delegate to this
impl From<FederationError> for CliError {
    fn from(e: FederationError) -> Self {
        CliError {
            error: e.to_string(),
        }
    }
}

impl Debug for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliError")
            .field("error", &self.error)
            .finish()
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let json = serde_json::to_value(self).expect("CliError is valid json");
        let json_as_string =
            serde_json::to_string_pretty(&json).expect("valid json is serializable");
        write!(f, "{}", json_as_string)
    }
}

#[derive(Parser, Clone)]
#[command(version)]
struct Opts {
    /// The working directory of the client containing the config and db
    #[arg(long = "data-dir", env = FM_CLIENT_DIR_ENV)]
    data_dir: Option<PathBuf>,

    /// Peer id of the guardian
    #[arg(env = FM_OUR_ID_ENV, long, value_parser = parse_peer_id)]
    our_id: Option<PeerId>,

    /// Guardian password for authentication
    #[arg(long, env = FM_PASSWORD_ENV)]
    password: Option<String>,

    /// Activate more verbose logging, for full control use the RUST_LOG env
    /// variable
    #[arg(short = 'v', long)]
    verbose: bool,

    #[clap(subcommand)]
    command: Command,
}

impl Opts {
    fn data_dir(&self) -> CliResult<&PathBuf> {
        self.data_dir
            .as_ref()
            .ok_or_cli_msg("`--data-dir=` argument not set.")
    }

    /// Get and create if doesn't exist the data dir
    async fn data_dir_create(&self) -> CliResult<&PathBuf> {
        let dir = self.data_dir()?;

        tokio::fs::create_dir_all(&dir).await.map_err_cli()?;

        Ok(dir)
    }

    fn admin_client(&self, cfg: &ClientConfig) -> CliResult<DynGlobalApi> {
        let our_id = self.our_id.ok_or_cli_msg("Admin client needs our-id set")?;
        Self::admin_client_from_id(our_id, cfg)
    }

    fn admin_client_from_id(id: PeerId, cfg: &ClientConfig) -> CliResult<DynGlobalApi> {
        let url = cfg
            .global
            .api_endpoints
            .get(&id)
            .expect("Endpoint exists")
            .url
            .clone();
        Ok(DynGlobalApi::from_single_endpoint(id, url))
    }

    fn auth(&self) -> CliResult<ApiAuth> {
        let password = self
            .password
            .clone()
            .ok_or_cli_msg("CLI needs password set")?;
        Ok(ApiAuth(password))
    }

    async fn load_rocks_db(&self) -> CliResult<Database> {
        debug!(target: LOG_CLIENT, "Loading client database");
        let db_path = self.data_dir_create().await?.join("client.db");
        let lock_path = db_path.with_extension("db.lock");
        Ok(LockedBuilder::new(&lock_path)
            .await
            .map_err_cli_msg("could not lock database")?
            .with_db(
                fedimint_rocksdb::RocksDb::open(db_path)
                    .map_err_cli_msg("could not open database")?,
            )
            .into())
    }
}

async fn load_or_generate_mnemonic(db: &Database) -> Result<Mnemonic, CliError> {
    Ok(
        match Client::load_decodable_client_secret::<Vec<u8>>(db).await {
            Ok(entropy) => Mnemonic::from_entropy(&entropy).map_err_cli()?,
            Err(_) => {
                info!("Generating mnemonic and writing entropy to client storage");
                let mnemonic = Bip39RootSecretStrategy::<12>::random(&mut thread_rng());
                Client::store_encodable_client_secret(db, mnemonic.to_entropy())
                    .await
                    .map_err_cli()?;
                mnemonic
            }
        },
    )
}

#[derive(Subcommand, Clone)]
enum Command {
    /// Print the latest Git commit hash this bin. was built with.
    VersionHash,

    #[clap(flatten)]
    Client(client::ClientCmd),

    #[clap(subcommand)]
    Admin(AdminCmd),

    #[clap(subcommand)]
    Dev(DevCmd),

    /// Config enabling client to establish websocket connection to federation
    InviteCode {
        peer: PeerId,
    },

    /// Join a federation using it's InviteCode
    JoinFederation {
        invite_code: String,
    },

    Completion {
        shell: clap_complete::Shell,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum AdminCmd {
    /// Show the status according to the `status` endpoint
    Status,

    /// Show an audit across all modules
    Audit,

    /// Download guardian config to back it up
    GuardianConfigBackup,

    Dkg(DkgAdminArgs),
}

#[derive(Debug, Clone, Args)]
struct DkgAdminArgs {
    #[arg(long, env = "FM_WS_URL")]
    ws: SafeUrl,

    #[clap(subcommand)]
    subcommand: DkgAdminCmd,
}

impl DkgAdminArgs {
    fn ws_admin_client(&self) -> CliResult<DynGlobalApi> {
        let ws = self.ws.clone();
        Ok(DynGlobalApi::from_pre_peer_id_endpoint(ws))
    }
}

#[derive(Debug, Clone, Subcommand)]
enum DkgAdminCmd {
    // These commands are roughly in the order they should be called
    /// Allow to access the `status` endpoint in a pre-dkg phase
    WsStatus,
    SetPassword,
    GetDefaultConfigGenParams,
    SetConfigGenParams {
        /// Guardian-defined key-value pairs that will be passed to the client
        /// Must be a valid JSON object (Map<String, String>)
        #[clap(long)]
        meta_json: String,
        /// Set the params (if leader) or just the local params (if follower)
        #[clap(long)]
        modules_json: String,
    },
    SetConfigGenConnections {
        /// Our guardian name
        #[clap(long)]
        our_name: String,
        /// URL of "leader" guardian to send our connection info to
        /// Will be `None` if we are the leader
        #[clap(long)]
        leader_api_url: Option<SafeUrl>,
    },
    GetConfigGenPeers,
    ConsensusConfigGenParams,
    RunDkg,
    GetVerifyConfigHash,
    StartConsensus,
}

#[derive(Debug, Clone, Subcommand)]
enum DecodeType {
    /// Decode an invite code string into a JSON representation
    InviteCode { invite_code: InviteCode },
    /// Decode a string of ecash notes into a JSON representation
    Notes { notes: OOBNotes },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OOBNotesJson {
    federation_id_prefix: String,
    notes: TieredMulti<SpendableNote>,
}

#[derive(Debug, Clone, Subcommand)]
enum EncodeType {
    /// Encode connection info from its constituent parts
    InviteCode {
        #[clap(long)]
        url: SafeUrl,
        #[clap(long = "federation_id")]
        federation_id: FederationId,
        #[clap(long = "peer")]
        peer: PeerId,
    },

    /// Encode a JSON string of notes to an ecash string
    Notes { notes_json: String },
}

#[derive(Debug, Clone, Subcommand)]
enum DevCmd {
    /// Send direct method call to the API. If you specify --peer-id, it will
    /// just ask one server, otherwise it will try to get consensus from all
    /// servers.
    #[command(after_long_help = r#"
Examples:

  fedimint-cli dev api --peer-id 0 config '"fed114znk7uk7ppugdjuytr8venqf2tkywd65cqvg3u93um64tu5cw4yr0n3fvn7qmwvm4g48cpndgnm4gqq4waen5te0xyerwt3s9cczuvf6xyurzde597s7crdvsk2vmyarjw9gwyqjdzj"'
    "#)]
    Api {
        /// JSON-RPC method to call
        method: String,
        /// JSON-RPC parameters for the request
        ///
        /// Note: single jsonrpc argument params string, which might require
        /// double-quotes (see example above).
        #[clap(default_value = "null")]
        params: String,
        /// Which server to send request to
        #[clap(long = "peer-id")]
        peer_id: Option<u16>,
        /// Guardian password in case authenticated API endpoints are being
        /// called. Only use together with --peer-id.
        #[clap(long, requires = "peer_id")]
        password: Option<String>,
    },

    /// Wait for the fed to reach a consensus block count
    WaitBlockCount { count: u64 },

    /// Wait for all state machines to complete
    WaitComplete,

    /// Decode invite code or ecash notes string into a JSON representation
    Decode {
        #[clap(subcommand)]
        decode_type: DecodeType,
    },

    /// Encode an invite code or ecash notes into binary
    Encode {
        #[clap(subcommand)]
        encode_type: EncodeType,
    },

    /// Gets the current fedimint AlephBFT block count
    SessionCount,

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
        #[arg(env = FM_PASSWORD_ENV)]
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
        #[arg(env = FM_PASSWORD_ENV)]
        password: String,
    },

    /// Decode a transaction hex string and print it to stdout
    DecodeTransaction { hex_string: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct PayRequest {
    notes: TieredMulti<SpendableNote>,
    invoice: lightning_invoice::Bolt11Invoice,
}

pub struct FedimintCli {
    module_inits: ClientModuleInitRegistry,
    cli_args: Opts,
}

impl FedimintCli {
    /// Build a new `fedimintd` with a custom version hash
    pub fn new(version_hash: &str) -> anyhow::Result<FedimintCli> {
        assert_eq!(
            fedimint_build_code_version_env!().len(),
            version_hash.len(),
            "version_hash must have an expected length"
        );

        handle_version_hash_command(version_hash);

        let cli_args = Opts::parse();
        let base_level = if cli_args.verbose { "info" } else { "warn" };
        TracingSetup::default()
            .with_base_level(base_level)
            .init()
            .expect("tracing initializes");

        let version = env!("CARGO_PKG_VERSION");
        debug!("Starting fedimint-cli (version: {version} version_hash: {version_hash})");

        Ok(Self {
            module_inits: ClientModuleInitRegistry::new(),
            cli_args,
        })
    }

    pub fn with_module<T>(mut self, gen: T) -> Self
    where
        T: ClientModuleInit + 'static + Send + Sync,
    {
        self.module_inits.attach(gen);
        self
    }

    pub fn with_default_modules(self) -> Self {
        self.with_module(LightningClientInit)
            .with_module(MintClientInit)
            .with_module(WalletClientInit::default())
            .with_module(MetaClientInit)
    }

    pub async fn run(&mut self) {
        match self.handle_command(self.cli_args.clone()).await {
            Ok(output) => {
                // ignore if there's anyone reading the stuff we're writing out
                let _ = writeln!(std::io::stdout(), "{output}");
            }
            Err(err) => {
                error!("{}", err.error);
                let _ = writeln!(std::io::stdout(), "{err}");
                exit(1);
            }
        }
    }

    async fn make_client_builder(&self, cli: &Opts) -> CliResult<ClientBuilder> {
        let db = cli.load_rocks_db().await?;
        let mut client_builder = Client::builder(db);
        client_builder.with_module_inits(self.module_inits.clone());
        client_builder.with_primary_module(1);

        Ok(client_builder)
    }

    async fn client_join(
        &mut self,
        cli: &Opts,
        invite_code: InviteCode,
    ) -> CliResult<ClientHandleArc> {
        let client_config = ClientConfig::download_from_invite_code(&invite_code)
            .await
            .map_err_cli()?;

        let client_builder = self.make_client_builder(cli).await?;

        let mnemonic = load_or_generate_mnemonic(client_builder.db_no_decoders()).await?;

        client_builder
            .join(
                get_default_client_secret(
                    &Bip39RootSecretStrategy::<12>::to_root_secret(&mnemonic),
                    &client_config.global.calculate_federation_id(),
                ),
                client_config.clone(),
            )
            .await
            .map(Arc::new)
            .map_err_cli()
    }

    async fn client_open(&self, cli: &Opts) -> CliResult<ClientHandleArc> {
        let mut client_builder = self.make_client_builder(cli).await?;

        if let Some(our_id) = cli.our_id {
            client_builder.set_admin_creds(AdminCreds {
                peer_id: our_id,
                auth: cli.auth()?,
            });
        }

        let mnemonic = Mnemonic::from_entropy(
            &Client::load_decodable_client_secret::<Vec<u8>>(client_builder.db_no_decoders())
                .await
                .map_err_cli()?,
        )
        .map_err_cli()?;

        let config = client_builder.load_existing_config().await.map_err_cli()?;

        let federation_id = config.calculate_federation_id();

        client_builder
            .open(get_default_client_secret(
                &Bip39RootSecretStrategy::<12>::to_root_secret(&mnemonic),
                &federation_id,
            ))
            .await
            .map(Arc::new)
            .map_err_cli()
    }

    async fn client_recover(
        &mut self,
        cli: &Opts,
        mnemonic: Mnemonic,
        invite_code: InviteCode,
    ) -> CliResult<ClientHandleArc> {
        let builder = self.make_client_builder(cli).await?;

        let client_config = ClientConfig::download_from_invite_code(&invite_code)
            .await
            .map_err_cli()?;

        match Client::load_decodable_client_secret_opt::<Vec<u8>>(builder.db_no_decoders())
            .await
            .map_err_cli()?
        {
            Some(existing) => {
                if existing != mnemonic.to_entropy() {
                    Err(anyhow::anyhow!("Previously set mnemonic does not match")).map_err_cli()?;
                }
            }
            None => {
                Client::store_encodable_client_secret(
                    builder.db_no_decoders(),
                    mnemonic.to_entropy(),
                )
                .await
                .map_err_cli()?;
            }
        }

        let root_secret = get_default_client_secret(
            &Bip39RootSecretStrategy::<12>::to_root_secret(&mnemonic),
            &client_config.calculate_federation_id(),
        );
        let backup = builder
            .download_backup_from_federation(&root_secret, &client_config)
            .await
            .map_err_cli()?;
        builder
            .recover(root_secret, client_config.to_owned(), backup)
            .await
            .map(Arc::new)
            .map_err_cli()
    }

    async fn handle_command(&mut self, cli: Opts) -> CliOutputResult {
        match cli.command.clone() {
            Command::InviteCode { peer } => {
                let db = cli.load_rocks_db().await?;
                let client_config = Client::get_config_from_db(&db)
                    .await
                    .ok_or_cli_msg("client config code not found")?;

                let invite_code = client_config
                    .invite_code(&peer)
                    .ok_or_cli_msg("peer not found")?;

                Ok(CliOutput::InviteCode { invite_code })
            }
            Command::JoinFederation { invite_code } => {
                {
                    let invite_code: InviteCode = InviteCode::from_str(&invite_code)
                        .map_err_cli_msg("invalid invite code")?;

                    // Build client and store config in DB
                    let _client = self.client_join(&cli, invite_code).await?;
                }

                Ok(CliOutput::JoinFederation {
                    joined: invite_code,
                })
            }
            Command::VersionHash => Ok(CliOutput::VersionHash {
                hash: fedimint_build_code_version_env!().to_string(),
            }),
            Command::Client(ClientCmd::Restore {
                mnemonic,
                invite_code,
            }) => {
                let invite_code: InviteCode =
                    InviteCode::from_str(&invite_code).map_err_cli_msg("invalid invite code")?;
                let mnemonic = Mnemonic::from_str(&mnemonic).map_err_cli()?;
                let client = self.client_recover(&cli, mnemonic, invite_code).await?;

                // TODO: until we implement recovery for other modules we can't really wait
                // for more than this one
                debug!("Waiting for mint module recovery to finish");
                client
                    .wait_for_module_kind_recovery(MintClientModule::kind())
                    .await
                    .map_err_cli()?;

                debug!("Recovery complete");

                Ok(CliOutput::Raw(serde_json::to_value(()).unwrap()))
            }
            Command::Client(command) => {
                let client = self.client_open(&cli).await?;
                Ok(CliOutput::Raw(
                    client::handle_command(command, client)
                        .await
                        .map_err_cli()?,
                ))
            }
            Command::Admin(AdminCmd::Audit) => {
                let client = self.client_open(&cli).await?;

                let audit = cli
                    .admin_client(client.get_config())?
                    .audit(cli.auth()?)
                    .await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(audit).map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::Status) => {
                let client = self.client_open(&cli).await?;

                let status = cli.admin_client(client.get_config())?.status().await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(status).map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::GuardianConfigBackup) => {
                let client = self.client_open(&cli).await?;

                let guardian_config_backup = cli
                    .admin_client(client.get_config())?
                    .guardian_config_backup(cli.auth()?)
                    .await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(guardian_config_backup)
                        .map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::Dkg(dkg_args)) => {
                self.handle_admin_dkg_command(cli, dkg_args).await
            }
            Command::Dev(DevCmd::Api {
                method,
                params,
                peer_id,
                password: auth,
            }) => {
                //Parse params to JSON.
                //If fails, convert to JSON string.
                let params = serde_json::from_str::<Value>(&params).unwrap_or_else(|err| {
                    debug!(
                        "Failed to serialize params:{}. Converting it to JSON string",
                        err
                    );

                    serde_json::Value::String(params)
                });

                let mut params = ApiRequestErased::new(params);
                if let Some(auth) = auth {
                    params = params.with_auth(ApiAuth(auth))
                }
                let client = self.client_open(&cli).await?;

                let ws_api: Arc<_> = WsFederationApi::from_config(client.get_config()).into();
                let response: Value = match peer_id {
                    Some(peer_id) => ws_api
                        .request_raw(peer_id.into(), &method, &[params.to_json()])
                        .await
                        .map_err_cli()?,
                    None => ws_api
                        .request_current_consensus(method, params)
                        .await
                        .map_err_cli()?,
                };

                Ok(CliOutput::UntypedApiOutput { value: response })
            }
            Command::Dev(DevCmd::WaitBlockCount { count: target }) => retry(
                "wait_block_count",
                ConstantBackoff::default()
                    .with_delay(Duration::from_millis(100))
                    .with_max_times(usize::MAX),
                || async {
                    let client = self.client_open(&cli).await?;
                    let wallet = client.get_first_module::<WalletClientModule>();
                    let count = client
                        .api()
                        .with_module(wallet.id)
                        .fetch_consensus_block_count()
                        .await?;
                    if count >= target {
                        Ok(CliOutput::WaitBlockCount { reached: count })
                    } else {
                        info!(target: LOG_CLIENT, current=count, target, "Block count not reached");
                        Err(format_err!("target not reached"))
                    }
                },
            )
            .await
            .map_err_cli(),

            Command::Dev(DevCmd::WaitComplete) => {
                let client = self.client_open(&cli).await?;
                client
                    .wait_for_all_active_state_machines()
                    .await
                    .map_err_cli_msg("failed to wait for all active state machines")?;
                Ok(CliOutput::Raw(serde_json::Value::Null))
            }
            Command::Dev(DevCmd::Decode { decode_type }) => match decode_type {
                DecodeType::InviteCode { invite_code } => Ok(CliOutput::DecodeInviteCode {
                    url: invite_code.url(),
                    federation_id: invite_code.federation_id(),
                }),
                DecodeType::Notes { notes } => {
                    let notes_json = notes
                        .notes_json()
                        .map_err_cli_msg("failed to decode notes")?;
                    Ok(CliOutput::Raw(notes_json))
                }
            },
            Command::Dev(DevCmd::Encode { encode_type }) => match encode_type {
                EncodeType::InviteCode {
                    url,
                    federation_id,
                    peer,
                } => Ok(CliOutput::InviteCode {
                    invite_code: InviteCode::new(url, peer, federation_id),
                }),
                EncodeType::Notes { notes_json } => {
                    let notes = serde_json::from_str::<OOBNotesJson>(&notes_json)
                        .map_err_cli_msg("invalid JSON for notes")?;
                    let prefix =
                        FederationIdPrefix::from_str(&notes.federation_id_prefix).map_err_cli()?;
                    let notes = OOBNotes::new(prefix, notes.notes);
                    Ok(CliOutput::Raw(notes.to_string().into()))
                }
            },
            Command::Dev(DevCmd::SessionCount) => {
                let client = self.client_open(&cli).await?;
                let count = client.api().session_count().await?;
                Ok(CliOutput::EpochCount { count })
            }
            Command::Dev(DevCmd::ConfigDecrypt {
                in_file,
                out_file,
                salt_file,
                password,
            }) => {
                let salt_file = salt_file.unwrap_or_else(|| salt_from_file_path(&in_file));
                let salt = fs::read_to_string(salt_file).map_err_cli()?;
                let key = get_encryption_key(&password, &salt).map_err_cli()?;
                let decrypted_bytes = encrypted_read(&key, in_file).map_err_cli()?;

                let mut out_file_handle = fs::File::options()
                    .create_new(true)
                    .write(true)
                    .open(out_file)
                    .expect("Could not create output cfg file");
                out_file_handle.write_all(&decrypted_bytes).map_err_cli()?;
                Ok(CliOutput::ConfigDecrypt)
            }
            Command::Dev(DevCmd::ConfigEncrypt {
                in_file,
                out_file,
                salt_file,
                password,
            }) => {
                let mut in_file_handle =
                    fs::File::open(in_file).expect("Could not create output cfg file");
                let mut plaintext_bytes = vec![];
                in_file_handle.read_to_end(&mut plaintext_bytes).unwrap();

                let salt_file = salt_file.unwrap_or_else(|| salt_from_file_path(&out_file));
                let salt = fs::read_to_string(salt_file).map_err_cli()?;
                let key = get_encryption_key(&password, &salt).map_err_cli()?;
                encrypted_write(plaintext_bytes, &key, out_file).map_err_cli()?;
                Ok(CliOutput::ConfigEncrypt)
            }
            Command::Dev(DevCmd::DecodeTransaction { hex_string }) => {
                let bytes: Vec<u8> = hex::FromHex::from_hex(&hex_string)
                    .map_err_cli_msg("failed to decode transaction")?;

                let client = self.client_open(&cli).await?;
                let tx =
                    fedimint_core::transaction::Transaction::from_bytes(&bytes, client.decoders())
                        .map_err_cli_msg("failed to decode transaction")?;

                Ok(CliOutput::DecodeTransaction {
                    transaction: (format!("{tx:?}")),
                })
            }
            Command::Completion { shell } => {
                clap_complete::generate(
                    shell,
                    &mut Opts::command(),
                    "fedimint-cli",
                    &mut std::io::stdout(),
                );
                // HACK: prints true to stdout which is fine for shells
                Ok(CliOutput::Raw(serde_json::Value::Bool(true)))
            }
        }
    }

    async fn handle_admin_dkg_command(
        &self,
        cli: Opts,
        dkg_args: DkgAdminArgs,
    ) -> Result<CliOutput, CliError> {
        let client = dkg_args.ws_admin_client()?;
        match &dkg_args.subcommand {
            DkgAdminCmd::WsStatus => {
                let status = client.status().await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(status).map_err_cli_msg("invalid response")?,
                ))
            }
            DkgAdminCmd::SetPassword => {
                client.set_password(cli.auth()?).await?;
                Ok(CliOutput::Raw(Value::Null))
            }
            DkgAdminCmd::GetDefaultConfigGenParams => {
                let default_params = client.get_default_config_gen_params(cli.auth()?).await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(default_params).map_err_cli_msg("invalid response")?,
                ))
            }
            DkgAdminCmd::SetConfigGenParams {
                meta_json,
                modules_json,
            } => {
                let meta: BTreeMap<String, String> =
                    serde_json::from_str(meta_json).map_err_cli_msg("Invalid JSON")?;
                let modules: ServerModuleConfigGenParamsRegistry =
                    serde_json::from_str(modules_json).map_err_cli_msg("Invalid JSON")?;
                let params = ConfigGenParamsRequest { meta, modules };
                client.set_config_gen_params(params, cli.auth()?).await?;
                Ok(CliOutput::Raw(Value::Null))
            }
            DkgAdminCmd::SetConfigGenConnections {
                our_name,
                leader_api_url,
            } => {
                let req = ConfigGenConnectionsRequest {
                    our_name: our_name.to_owned(),
                    leader_api_url: leader_api_url.to_owned(),
                };
                client.set_config_gen_connections(req, cli.auth()?).await?;
                Ok(CliOutput::Raw(Value::Null))
            }
            DkgAdminCmd::GetConfigGenPeers => {
                let peer_server_params = client.get_config_gen_peers().await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(peer_server_params).map_err_cli_msg("invalid response")?,
                ))
            }
            DkgAdminCmd::ConsensusConfigGenParams => {
                let config_gen_params_response = client.consensus_config_gen_params().await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(config_gen_params_response)
                        .map_err_cli_msg("invalid response")?,
                ))
            }
            DkgAdminCmd::RunDkg => {
                client.run_dkg(cli.auth()?).await?;
                Ok(CliOutput::Raw(Value::Null))
            }
            DkgAdminCmd::GetVerifyConfigHash => {
                let hashes_by_peer = client.get_verify_config_hash(cli.auth()?).await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(hashes_by_peer).map_err_cli_msg("invalid response")?,
                ))
            }
            DkgAdminCmd::StartConsensus => {
                client.start_consensus(cli.auth()?).await?;
                Ok(CliOutput::Raw(Value::Null))
            }
        }
    }
}

fn salt_from_file_path(file_path: &Path) -> PathBuf {
    file_path
        .parent()
        .expect("File has no parent?!")
        .join(SALT_FILE)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LnInvoiceResponse {
    pub operation_id: OperationId,
    pub invoice: String,
}

/// Convert clap arguments to backup metadata
fn metadata_from_clap_cli(metadata: Vec<String>) -> Result<BTreeMap<String, String>, CliError> {
    let metadata: BTreeMap<String, String> = metadata
        .into_iter()
        .map(|item| {
            match &item
                .splitn(2, '=')
                .map(ToString::to_string)
                .collect::<Vec<String>>()[..]
            {
                [] => Err(format_err!("Empty metadata argument not allowed")),
                [key] => Err(format_err!("Metadata {key} is missing a value")),
                [key, val] => Ok((key.clone(), val.clone())),
                [..] => unreachable!(),
            }
        })
        .collect::<anyhow::Result<_>>()
        .map_err_cli_msg("invalid metadata")?;
    Ok(metadata)
}

#[test]
fn metadata_from_clap_cli_test() {
    for (args, expected) in [
        (
            vec!["a=b".to_string()],
            BTreeMap::from([("a".into(), "b".into())]),
        ),
        (
            vec!["a=b".to_string(), "c=d".to_string()],
            BTreeMap::from([("a".into(), "b".into()), ("c".into(), "d".into())]),
        ),
    ] {
        assert_eq!(metadata_from_clap_cli(args).unwrap(), expected);
    }
}
