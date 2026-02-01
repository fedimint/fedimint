#![deny(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::ref_option)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::large_futures)]

mod client;
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

use anyhow::{Context, format_err};
use clap::{Args, CommandFactory, Parser, Subcommand};
use client::ModuleSelector;
#[cfg(feature = "tor")]
use envs::FM_USE_TOR_ENV;
use envs::{FM_API_SECRET_ENV, FM_DB_BACKEND_ENV, FM_IROH_ENABLE_DHT_ENV, SALT_FILE};
use fedimint_aead::{encrypted_read, encrypted_write, get_encryption_key};
use fedimint_api_client::api::{DynGlobalApi, FederationApiExt, FederationError};
use fedimint_bip39::{Bip39RootSecretStrategy, Mnemonic};
use fedimint_client::module::meta::{FetchKind, LegacyMetaSource, MetaSource};
use fedimint_client::module::module::init::ClientModuleInit;
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client::secret::RootSecretStrategy;
use fedimint_client::{AdminCreds, Client, ClientBuilder, ClientHandleArc, RootSecret};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::base32::FEDIMINT_PREFIX;
use fedimint_core::config::{FederationId, FederationIdPrefix};
use fedimint_core::core::{ModuleInstanceId, OperationId};
use fedimint_core::db::{Database, DatabaseValue, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::encoding::Decodable;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::setup_code::PeerSetupCode;
use fedimint_core::transaction::Transaction;
use fedimint_core::util::{SafeUrl, backoff_util, handle_version_hash_command, retry};
use fedimint_core::{
    Amount, PeerId, TieredMulti, base32, fedimint_build_code_version_env, runtime,
};
use fedimint_eventlog::{EventLogId, EventLogTrimableId};
use fedimint_ln_client::LightningClientInit;
use fedimint_logging::{LOG_CLIENT, TracingSetup};
use fedimint_meta_client::{MetaClientInit, MetaModuleMetaSourceWithFallback};
use fedimint_mint_client::{MintClientInit, MintClientModule, OOBNotes, SpendableNote};
use fedimint_wallet_client::api::WalletFederationApi;
use fedimint_wallet_client::{WalletClientInit, WalletClientModule};
use futures::future::pending;
use itertools::Itertools;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tracing::{debug, info, warn};
use utils::parse_peer_id;

use crate::client::ClientCmd;
use crate::envs::{FM_CLIENT_DIR_ENV, FM_IROH_ENABLE_NEXT_ENV, FM_OUR_ID_ENV, FM_PASSWORD_ENV};

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

    SetupCode {
        setup_code: PeerSetupCode,
    },

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
    fn map_err_cli_msg(self, msg: impl fmt::Display + Send + Sync + 'static)
    -> Result<O, CliError>;
}

impl<O, E> CliResultExt<O, E> for result::Result<O, E>
where
    E: Into<anyhow::Error>,
{
    fn map_err_cli(self) -> Result<O, CliError> {
        self.map_err(|e| {
            let e = e.into();
            CliError {
                error: format!("{e:#}"),
            }
        })
    }

    fn map_err_cli_msg(
        self,
        msg: impl fmt::Display + Send + Sync + 'static,
    ) -> Result<O, CliError> {
        self.map_err(|e| Into::<anyhow::Error>::into(e))
            .context(msg)
            .map_err(|e| CliError {
                error: format!("{e:#}"),
            })
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
        write!(f, "{json_as_string}")
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DatabaseBackend {
    /// Use RocksDB database backend
    #[value(name = "rocksdb")]
    RocksDb,
    /// Use CursedRedb database backend (hybrid memory/redb)
    #[value(name = "cursed-redb")]
    CursedRedb,
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

    #[cfg(feature = "tor")]
    /// Activate usage of Tor as the Connector when building the Client
    #[arg(long, env = FM_USE_TOR_ENV)]
    use_tor: bool,

    // Enable using DHT name resolution in Iroh
    #[arg(long, env = FM_IROH_ENABLE_DHT_ENV)]
    iroh_enable_dht: Option<bool>,

    // Enable using (in parallel) unstable/next Iroh stack
    #[arg(long, env = FM_IROH_ENABLE_NEXT_ENV)]
    iroh_enable_next: Option<bool>,

    /// Database backend to use.
    #[arg(long, env = FM_DB_BACKEND_ENV, value_enum, default_value = "rocksdb")]
    db_backend: DatabaseBackend,

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
    fn iroh_enable_dht(&self) -> bool {
        self.iroh_enable_dht.unwrap_or(true)
    }

    fn iroh_enable_next(&self) -> bool {
        self.iroh_enable_next.unwrap_or(true)
    }

    fn use_tor(&self) -> bool {
        #[cfg(feature = "tor")]
        return self.use_tor;
        #[cfg(not(feature = "tor"))]
        false
    }

    async fn admin_client(
        &self,
        peer_urls: &BTreeMap<PeerId, SafeUrl>,
        api_secret: Option<&str>,
    ) -> CliResult<DynGlobalApi> {
        let our_id = self.our_id.ok_or_cli_msg("Admin client needs our-id set")?;

        DynGlobalApi::new_admin(
            self.make_endpoints().await.map_err(|e| CliError {
                error: e.to_string(),
            })?,
            our_id,
            peer_urls
                .get(&our_id)
                .cloned()
                .context("Our peer URL not found in config")
                .map_err_cli()?,
            api_secret,
        )
        .map_err_cli()
    }

    async fn make_endpoints(&self) -> Result<ConnectorRegistry, anyhow::Error> {
        ConnectorRegistry::build_from_client_defaults()
            .iroh_next(self.iroh_enable_next())
            .iroh_pkarr_dht(self.iroh_enable_dht())
            .ws_force_tor(self.use_tor())
            .bind()
            .await
    }

    fn auth(&self) -> CliResult<ApiAuth> {
        let password = self
            .password
            .clone()
            .ok_or_cli_msg("CLI needs password set")?;
        Ok(ApiAuth(password))
    }

    async fn load_database(&self) -> CliResult<Database> {
        debug!(target: LOG_CLIENT, "Loading client database");
        let db_path = self.data_dir_create().await?.join("client.db");
        match self.db_backend {
            DatabaseBackend::RocksDb => {
                debug!(target: LOG_CLIENT, "Using RocksDB database backend");
                Ok(fedimint_rocksdb::RocksDb::build(db_path)
                    .open()
                    .await
                    .map_err_cli_msg("could not open rocksdb database")?
                    .into())
            }
            DatabaseBackend::CursedRedb => {
                debug!(target: LOG_CLIENT, "Using CursedRedb database backend");
                Ok(fedimint_cursed_redb::MemAndRedb::new(db_path)
                    .await
                    .map_err_cli_msg("could not open cursed redb database")?
                    .into())
            }
        }
    }
}

async fn load_or_generate_mnemonic(db: &Database) -> Result<Mnemonic, CliError> {
    Ok(
        if let Ok(entropy) = Client::load_decodable_client_secret::<Vec<u8>>(db).await {
            Mnemonic::from_entropy(&entropy).map_err_cli()?
        } else {
            debug!(
                target: LOG_CLIENT,
                "Generating mnemonic and writing entropy to client storage"
            );
            let mnemonic = Bip39RootSecretStrategy::<12>::random(&mut thread_rng());
            Client::store_encodable_client_secret(db, mnemonic.to_entropy())
                .await
                .map_err_cli()?;
            mnemonic
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

    /// Join a federation using its InviteCode
    JoinFederation {
        invite_code: String,
    },

    Completion {
        shell: clap_complete::Shell,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Subcommand)]
enum AdminCmd {
    /// Show the status according to the `status` endpoint
    Status,

    /// Show an audit across all modules
    Audit,

    /// Download guardian config to back it up
    GuardianConfigBackup,

    Setup(SetupAdminArgs),
    /// Sign and announce a new API endpoint. The previous one will be
    /// invalidated
    SignApiAnnouncement {
        /// New API URL to announce
        api_url: SafeUrl,
        /// Provide the API url for the guardian directly in case the old one
        /// isn't reachable anymore
        #[clap(long)]
        override_url: Option<SafeUrl>,
    },
    /// Stop fedimintd after the specified session to do a coordinated upgrade
    Shutdown {
        /// Session index to stop after
        session_idx: u64,
    },
    /// Show statistics about client backups stored by the federation
    BackupStatistics,
    /// Change guardian password, will shut down fedimintd and require manual
    /// restart
    ChangePassword {
        /// New password to set
        new_password: String,
    },
}

#[derive(Debug, Clone, Args)]
struct SetupAdminArgs {
    endpoint: SafeUrl,

    #[clap(subcommand)]
    subcommand: SetupAdminCmd,
}

#[derive(Debug, Clone, Subcommand)]
enum SetupAdminCmd {
    Status,
    SetLocalParams {
        name: String,
        #[clap(long)]
        federation_name: Option<String>,
    },
    AddPeer {
        info: String,
    },
    StartDkg,
}

#[derive(Debug, Clone, Subcommand)]
enum DecodeType {
    /// Decode an invite code string into a JSON representation
    InviteCode { invite_code: InviteCode },
    /// Decode a string of ecash notes into a JSON representation
    #[group(required = true, multiple = false)]
    Notes {
        /// Base64 e-cash notes to be decoded
        notes: Option<OOBNotes>,
        /// File containing base64 e-cash notes to be decoded
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Decode a transaction hex string and print it to stdout
    Transaction { hex_string: String },
    /// Decode a setup code (as shared during a federation setup ceremony)
    /// string into a JSON representation
    SetupCode { setup_code: String },
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
        #[arg(env = FM_API_SECRET_ENV)]
        api_secret: Option<String>,
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

        /// Module selector (either module id or module kind)
        #[clap(long = "module")]
        module: Option<ModuleSelector>,

        /// Guardian password in case authenticated API endpoints are being
        /// called. Only use together with --peer-id.
        #[clap(long, requires = "peer_id")]
        password: Option<String>,
    },

    ApiAnnouncements,

    /// Advance the note_idx
    AdvanceNoteIdx {
        #[clap(long, default_value = "1")]
        count: usize,

        #[clap(long)]
        amount: Amount,
    },

    /// Wait for the fed to reach a consensus block count
    WaitBlockCount {
        count: u64,
    },

    /// Just start the `Client` and wait
    Wait {
        /// Limit the wait time
        seconds: Option<f32>,
    },

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
        /// `in_file` directory
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
        /// `out_file` directory
        #[arg(long = "salt-file")]
        salt_file: Option<PathBuf>,
        /// The password that encrypts the configs
        #[arg(env = FM_PASSWORD_ENV)]
        password: String,
    },

    /// Lists active and inactive state machine states of the operation
    /// chronologically
    ListOperationStates {
        operation_id: OperationId,
    },
    /// Returns the federation's meta fields. If they are set correctly via the
    /// meta module these are returned, otherwise the legacy mechanism
    /// (config+override file) is used.
    MetaFields,
    /// Gets the tagged fedimintd version for a peer
    PeerVersion {
        #[clap(long)]
        peer_id: u16,
    },
    /// Dump Client's Event Log
    ShowEventLog {
        #[arg(long)]
        pos: Option<EventLogId>,
        #[arg(long, default_value = "10")]
        limit: u64,
    },
    /// Dump Client's Trimable Event Log
    ShowEventLogTrimable {
        #[arg(long)]
        pos: Option<EventLogId>,
        #[arg(long, default_value = "10")]
        limit: u64,
    },
    /// Test the built-in event handling and tracking by printing events to
    /// console
    TestEventLogHandling,
    /// Manually submit a fedimint transaction to guardians
    ///
    /// This can be useful to check why a transaction may have been rejected
    /// when debugging client issues.
    SubmitTransaction {
        /// Hex-encoded fedimint transaction
        transaction: String,
    },
    /// Show the chain ID (bitcoin block hash at height 1) cached in the client
    /// database
    ChainId,
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
        let base_level = if cli_args.verbose { "debug" } else { "info" };
        TracingSetup::default()
            .with_base_level(base_level)
            .init()
            .expect("tracing initializes");

        let version = env!("CARGO_PKG_VERSION");
        debug!(target: LOG_CLIENT, "Starting fedimint-cli (version: {version} version_hash: {version_hash})");

        Ok(Self {
            module_inits: ClientModuleInitRegistry::new(),
            cli_args,
        })
    }

    pub fn with_module<T>(mut self, r#gen: T) -> Self
    where
        T: ClientModuleInit + 'static + Send + Sync,
    {
        self.module_inits.attach(r#gen);
        self
    }

    pub fn with_default_modules(self) -> Self {
        self.with_module(LightningClientInit::default())
            .with_module(MintClientInit)
            .with_module(WalletClientInit::default())
            .with_module(MetaClientInit)
            .with_module(fedimint_lnv2_client::LightningClientInit::default())
            .with_module(fedimint_walletv2_client::WalletClientInit)
    }

    pub async fn run(&mut self) {
        match self.handle_command(self.cli_args.clone()).await {
            Ok(output) => {
                // ignore if there's anyone reading the stuff we're writing out
                let _ = writeln!(std::io::stdout(), "{output}");
            }
            Err(err) => {
                debug!(target: LOG_CLIENT, err = %err.error.as_str(), "Command failed");
                let _ = writeln!(std::io::stdout(), "{err}");
                exit(1);
            }
        }
    }

    async fn make_client_builder(&self, cli: &Opts) -> CliResult<(ClientBuilder, Database)> {
        let mut client_builder = Client::builder()
            .await
            .map_err_cli()?
            .with_iroh_enable_dht(cli.iroh_enable_dht())
            .with_iroh_enable_next(cli.iroh_enable_next());
        client_builder.with_module_inits(self.module_inits.clone());

        let db = cli.load_database().await?;
        Ok((client_builder, db))
    }

    async fn client_join(
        &mut self,
        cli: &Opts,
        invite_code: InviteCode,
    ) -> CliResult<ClientHandleArc> {
        let (client_builder, db) = self.make_client_builder(cli).await?;

        let mnemonic = load_or_generate_mnemonic(&db).await?;

        let client = client_builder
            .preview(cli.make_endpoints().await.map_err_cli()?, &invite_code)
            .await
            .map_err_cli()?
            .join(
                db,
                RootSecret::StandardDoubleDerive(Bip39RootSecretStrategy::<12>::to_root_secret(
                    &mnemonic,
                )),
            )
            .await
            .map(Arc::new)
            .map_err_cli()?;

        print_welcome_message(&client).await;
        log_expiration_notice(&client).await;

        Ok(client)
    }

    async fn client_open(&self, cli: &Opts) -> CliResult<ClientHandleArc> {
        let (mut client_builder, db) = self.make_client_builder(cli).await?;

        if let Some(our_id) = cli.our_id {
            client_builder.set_admin_creds(AdminCreds {
                peer_id: our_id,
                auth: cli.auth()?,
            });
        }

        let mnemonic = Mnemonic::from_entropy(
            &Client::load_decodable_client_secret::<Vec<u8>>(&db)
                .await
                .map_err_cli()?,
        )
        .map_err_cli()?;

        let client = client_builder
            .open(
                cli.make_endpoints().await.map_err_cli()?,
                db,
                RootSecret::StandardDoubleDerive(Bip39RootSecretStrategy::<12>::to_root_secret(
                    &mnemonic,
                )),
            )
            .await
            .map(Arc::new)
            .map_err_cli()?;

        log_expiration_notice(&client).await;

        Ok(client)
    }

    async fn client_recover(
        &mut self,
        cli: &Opts,
        mnemonic: Mnemonic,
        invite_code: InviteCode,
    ) -> CliResult<ClientHandleArc> {
        let (builder, db) = self.make_client_builder(cli).await?;
        match Client::load_decodable_client_secret_opt::<Vec<u8>>(&db)
            .await
            .map_err_cli()?
        {
            Some(existing) => {
                if existing != mnemonic.to_entropy() {
                    Err(anyhow::anyhow!("Previously set mnemonic does not match")).map_err_cli()?;
                }
            }
            None => {
                Client::store_encodable_client_secret(&db, mnemonic.to_entropy())
                    .await
                    .map_err_cli()?;
            }
        }

        let root_secret = RootSecret::StandardDoubleDerive(
            Bip39RootSecretStrategy::<12>::to_root_secret(&mnemonic),
        );

        let preview = builder
            .preview(cli.make_endpoints().await.map_err_cli()?, &invite_code)
            .await
            .map_err_cli()?;

        let backup = preview
            .download_backup_from_federation(root_secret.clone())
            .await
            .map_err_cli()?;

        let client = preview
            .recover(db, root_secret, backup)
            .await
            .map(Arc::new)
            .map_err_cli()?;

        print_welcome_message(&client).await;
        log_expiration_notice(&client).await;

        Ok(client)
    }

    async fn handle_command(&mut self, cli: Opts) -> CliOutputResult {
        match cli.command.clone() {
            Command::InviteCode { peer } => {
                let client = self.client_open(&cli).await?;

                let invite_code = client
                    .invite_code(peer)
                    .await
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
                debug!(target: LOG_CLIENT, "Waiting for mint module recovery to finish");
                client.wait_for_all_recoveries().await.map_err_cli()?;

                debug!(target: LOG_CLIENT, "Recovery complete");

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
                    .admin_client(
                        &client.get_peer_urls().await,
                        client.api_secret().as_deref(),
                    )
                    .await?
                    .audit(cli.auth()?)
                    .await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(audit).map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::Status) => {
                let client = self.client_open(&cli).await?;

                let status = cli
                    .admin_client(
                        &client.get_peer_urls().await,
                        client.api_secret().as_deref(),
                    )
                    .await?
                    .status()
                    .await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(status).map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::GuardianConfigBackup) => {
                let client = self.client_open(&cli).await?;

                let guardian_config_backup = cli
                    .admin_client(
                        &client.get_peer_urls().await,
                        client.api_secret().as_deref(),
                    )
                    .await?
                    .guardian_config_backup(cli.auth()?)
                    .await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(guardian_config_backup)
                        .map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::Setup(dkg_args)) => self
                .handle_admin_setup_command(cli, dkg_args)
                .await
                .map(CliOutput::Raw)
                .map_err_cli_msg("Config Gen Error"),
            Command::Admin(AdminCmd::SignApiAnnouncement {
                api_url,
                override_url,
            }) => {
                let client = self.client_open(&cli).await?;

                if !["ws", "wss"].contains(&api_url.scheme()) {
                    return Err(CliError {
                        error: format!(
                            "Unsupported URL scheme {}, use ws:// or wss://",
                            api_url.scheme()
                        ),
                    });
                }

                let announcement = cli
                    .admin_client(
                        &override_url
                            .and_then(|url| Some(vec![(cli.our_id?, url)].into_iter().collect()))
                            .unwrap_or(client.get_peer_urls().await),
                        client.api_secret().as_deref(),
                    )
                    .await?
                    .sign_api_announcement(api_url, cli.auth()?)
                    .await?;

                Ok(CliOutput::Raw(
                    serde_json::to_value(announcement).map_err_cli_msg("invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::Shutdown { session_idx }) => {
                let client = self.client_open(&cli).await?;

                cli.admin_client(
                    &client.get_peer_urls().await,
                    client.api_secret().as_deref(),
                )
                .await?
                .shutdown(Some(session_idx), cli.auth()?)
                .await?;

                Ok(CliOutput::Raw(json!(null)))
            }
            Command::Admin(AdminCmd::BackupStatistics) => {
                let client = self.client_open(&cli).await?;

                let backup_statistics = cli
                    .admin_client(
                        &client.get_peer_urls().await,
                        client.api_secret().as_deref(),
                    )
                    .await?
                    .backup_statistics(cli.auth()?)
                    .await?;

                Ok(CliOutput::Raw(
                    serde_json::to_value(backup_statistics).expect("Can be encoded"),
                ))
            }
            Command::Admin(AdminCmd::ChangePassword { new_password }) => {
                let client = self.client_open(&cli).await?;

                cli.admin_client(
                    &client.get_peer_urls().await,
                    client.api_secret().as_deref(),
                )
                .await?
                .change_password(cli.auth()?, &new_password)
                .await?;

                warn!(target: LOG_CLIENT, "Password changed, please restart fedimintd manually");

                Ok(CliOutput::Raw(json!(null)))
            }
            Command::Dev(DevCmd::Api {
                method,
                params,
                peer_id,
                password: auth,
                module,
            }) => {
                //Parse params to JSON.
                //If fails, convert to JSON string.
                let params = serde_json::from_str::<Value>(&params).unwrap_or_else(|err| {
                    debug!(
                        target: LOG_CLIENT,
                        "Failed to serialize params:{}. Converting it to JSON string",
                        err
                    );

                    serde_json::Value::String(params)
                });

                let mut params = ApiRequestErased::new(params);
                if let Some(auth) = auth {
                    params = params.with_auth(ApiAuth(auth));
                }
                let client = self.client_open(&cli).await?;

                let api = client.api_clone();

                let module_api = match module {
                    Some(selector) => {
                        Some(api.with_module(selector.resolve(&client).map_err_cli()?))
                    }
                    None => None,
                };

                let response: Value = match (peer_id, module_api) {
                    (Some(peer_id), Some(module_api)) => module_api
                        .request_raw(peer_id.into(), &method, &params)
                        .await
                        .map_err_cli()?,
                    (Some(peer_id), None) => api
                        .request_raw(peer_id.into(), &method, &params)
                        .await
                        .map_err_cli()?,
                    (None, Some(module_api)) => module_api
                        .request_current_consensus(method, params)
                        .await
                        .map_err_cli()?,
                    (None, None) => api
                        .request_current_consensus(method, params)
                        .await
                        .map_err_cli()?,
                };

                Ok(CliOutput::UntypedApiOutput { value: response })
            }
            Command::Dev(DevCmd::AdvanceNoteIdx { count, amount }) => {
                let client = self.client_open(&cli).await?;

                let mint = client
                    .get_first_module::<MintClientModule>()
                    .map_err_cli_msg("can't get mint module")?;

                for _ in 0..count {
                    mint.advance_note_idx(amount)
                        .await
                        .map_err_cli_msg("failed to advance the note_idx")?;
                }

                Ok(CliOutput::Raw(serde_json::Value::Null))
            }
            Command::Dev(DevCmd::ApiAnnouncements) => {
                let client = self.client_open(&cli).await?;
                let announcements = client.get_peer_url_announcements().await;
                Ok(CliOutput::Raw(
                    serde_json::to_value(announcements).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::WaitBlockCount { count: target }) => retry(
                "wait_block_count",
                backoff_util::custom_backoff(
                    Duration::from_millis(100),
                    Duration::from_secs(5),
                    None,
                ),
                || async {
                    let client = self.client_open(&cli).await?;
                    let wallet = client.get_first_module::<WalletClientModule>()?;
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
            Command::Dev(DevCmd::Wait { seconds }) => {
                let client = self.client_open(&cli).await?;
                // Since most callers are `wait`ing for something to happen,
                // let's trigger a network call, so any background threads
                // waiting for it starts doing their job.
                client
                    .task_group()
                    .spawn_cancellable("fedimint-cli dev wait: init networking", {
                        let client = client.clone();
                        async move {
                            let _ = client.api().session_count().await;
                        }
                    });

                if let Some(secs) = seconds {
                    runtime::sleep(Duration::from_secs_f32(secs)).await;
                } else {
                    pending::<()>().await;
                }
                Ok(CliOutput::Raw(serde_json::Value::Null))
            }
            Command::Dev(DevCmd::Decode { decode_type }) => match decode_type {
                DecodeType::InviteCode { invite_code } => Ok(CliOutput::DecodeInviteCode {
                    url: invite_code.url(),
                    federation_id: invite_code.federation_id(),
                }),
                DecodeType::Notes { notes, file } => {
                    let notes = if let Some(notes) = notes {
                        notes
                    } else if let Some(file) = file {
                        let notes_str =
                            fs::read_to_string(file).map_err_cli_msg("failed to read file")?;
                        OOBNotes::from_str(&notes_str).map_err_cli_msg("failed to decode notes")?
                    } else {
                        unreachable!("Clap enforces either notes or file being set");
                    };

                    let notes_json = notes
                        .notes_json()
                        .map_err_cli_msg("failed to decode notes")?;
                    Ok(CliOutput::Raw(notes_json))
                }
                DecodeType::Transaction { hex_string } => {
                    let bytes: Vec<u8> = hex::FromHex::from_hex(&hex_string)
                        .map_err_cli_msg("failed to decode transaction")?;

                    let client = self.client_open(&cli).await?;
                    let tx = fedimint_core::transaction::Transaction::from_bytes(
                        &bytes,
                        client.decoders(),
                    )
                    .map_err_cli_msg("failed to decode transaction")?;

                    Ok(CliOutput::DecodeTransaction {
                        transaction: (format!("{tx:?}")),
                    })
                }
                DecodeType::SetupCode { setup_code } => {
                    let setup_code = base32::decode_prefixed(FEDIMINT_PREFIX, &setup_code)
                        .map_err_cli_msg("failed to decode setup code")?;

                    Ok(CliOutput::SetupCode { setup_code })
                }
            },
            Command::Dev(DevCmd::Encode { encode_type }) => match encode_type {
                EncodeType::InviteCode {
                    url,
                    federation_id,
                    peer,
                    api_secret,
                } => Ok(CliOutput::InviteCode {
                    invite_code: InviteCode::new(url, peer, federation_id, api_secret),
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
            Command::Dev(DevCmd::ListOperationStates { operation_id }) => {
                #[derive(Serialize)]
                struct ReactorLogState {
                    active: bool,
                    module_instance: ModuleInstanceId,
                    creation_time: String,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    end_time: Option<String>,
                    state: String,
                }

                let client = self.client_open(&cli).await?;

                let (active_states, inactive_states) =
                    client.executor().get_operation_states(operation_id).await;
                let all_states =
                    active_states
                        .into_iter()
                        .map(|(active_state, active_meta)| ReactorLogState {
                            active: true,
                            module_instance: active_state.module_instance_id(),
                            creation_time: crate::client::time_to_iso8601(&active_meta.created_at),
                            end_time: None,
                            state: format!("{active_state:?}",),
                        })
                        .chain(inactive_states.into_iter().map(
                            |(inactive_state, inactive_meta)| ReactorLogState {
                                active: false,
                                module_instance: inactive_state.module_instance_id(),
                                creation_time: crate::client::time_to_iso8601(
                                    &inactive_meta.created_at,
                                ),
                                end_time: Some(crate::client::time_to_iso8601(
                                    &inactive_meta.exited_at,
                                )),
                                state: format!("{inactive_state:?}",),
                            },
                        ))
                        .sorted_by(|a, b| a.creation_time.cmp(&b.creation_time))
                        .collect::<Vec<_>>();

                Ok(CliOutput::Raw(json!({
                    "states": all_states
                })))
            }
            Command::Dev(DevCmd::MetaFields) => {
                let client = self.client_open(&cli).await?;
                let source = MetaModuleMetaSourceWithFallback::<LegacyMetaSource>::default();

                let meta_fields = source
                    .fetch(
                        &client.config().await,
                        &client.api_clone(),
                        FetchKind::Initial,
                        None,
                    )
                    .await
                    .map_err_cli()?;

                Ok(CliOutput::Raw(
                    serde_json::to_value(meta_fields).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::PeerVersion { peer_id }) => {
                let client = self.client_open(&cli).await?;
                let version = client
                    .api()
                    .fedimintd_version(peer_id.into())
                    .await
                    .map_err_cli()?;

                Ok(CliOutput::Raw(json!({ "version": version })))
            }
            Command::Dev(DevCmd::ShowEventLog { pos, limit }) => {
                let client = self.client_open(&cli).await?;

                let events: Vec<_> = client
                    .get_event_log(pos, limit)
                    .await
                    .into_iter()
                    .map(|v| {
                        let id = v.id();
                        let v = v.as_raw();
                        let module_id = v.module.as_ref().map(|m| m.1);
                        let module_kind = v.module.as_ref().map(|m| m.0.clone());
                        serde_json::json!({
                            "id": id,
                            "kind": v.kind,
                            "module_kind": module_kind,
                            "module_id": module_id,
                            "ts": v.ts_usecs,
                            "payload": serde_json::from_slice(&v.payload).unwrap_or_else(|_| hex::encode(&v.payload)),
                        })
                    })
                    .collect();

                Ok(CliOutput::Raw(
                    serde_json::to_value(events).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::ShowEventLogTrimable { pos, limit }) => {
                let client = self.client_open(&cli).await?;

                let events: Vec<_> = client
                    .get_event_log_trimable(
                        pos.map(|id| EventLogTrimableId::from(u64::from(id))),
                        limit,
                    )
                    .await
                    .into_iter()
                    .map(|v| {
                        let id = v.id();
                        let v = v.as_raw();
                        let module_id = v.module.as_ref().map(|m| m.1);
                        let module_kind = v.module.as_ref().map(|m| m.0.clone());
                        serde_json::json!({
                            "id": id,
                            "kind": v.kind,
                            "module_kind": module_kind,
                            "module_id": module_id,
                            "ts": v.ts_usecs,
                            "payload": serde_json::from_slice(&v.payload).unwrap_or_else(|_| hex::encode(&v.payload)),
                        })
                    })
                    .collect();

                Ok(CliOutput::Raw(
                    serde_json::to_value(events).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::SubmitTransaction { transaction }) => {
                let client = self.client_open(&cli).await?;
                let tx = Transaction::consensus_decode_hex(&transaction, client.decoders())
                    .map_err_cli()?;
                let tx_outcome = client
                    .api()
                    .submit_transaction(tx)
                    .await
                    .try_into_inner(client.decoders())
                    .map_err_cli()?;

                Ok(CliOutput::Raw(
                    serde_json::to_value(tx_outcome.0.map_err_cli()?).expect("Can be encoded"),
                ))
            }
            Command::Dev(DevCmd::TestEventLogHandling) => {
                let client = self.client_open(&cli).await?;

                client
                    .handle_events(
                        client.built_in_application_event_log_tracker(),
                        move |_dbtx, event| {
                            Box::pin(async move {
                                info!(target: LOG_CLIENT, "{event:?}");

                                Ok(())
                            })
                        },
                    )
                    .await
                    .map_err_cli()?;
                unreachable!(
                    "handle_events exits only if client shuts down, which we don't do here"
                )
            }
            Command::Dev(DevCmd::ChainId) => {
                let client = self.client_open(&cli).await?;
                let chain_id = client
                    .db()
                    .begin_transaction_nc()
                    .await
                    .get_value(&fedimint_client::db::ChainIdKey)
                    .await
                    .ok_or_cli_msg("Chain ID not cached in client database")?;

                Ok(CliOutput::Raw(serde_json::json!({
                    "chain_id": chain_id.to_string()
                })))
            }
            Command::Completion { shell } => {
                let bin_path = PathBuf::from(
                    std::env::args_os()
                        .next()
                        .expect("Binary name is always provided if we get this far"),
                );
                let bin_name = bin_path
                    .file_name()
                    .expect("path has file name")
                    .to_string_lossy();
                clap_complete::generate(
                    shell,
                    &mut Opts::command(),
                    bin_name.as_ref(),
                    &mut std::io::stdout(),
                );
                // HACK: prints true to stdout which is fine for shells
                Ok(CliOutput::Raw(serde_json::Value::Bool(true)))
            }
        }
    }

    async fn handle_admin_setup_command(
        &self,
        cli: Opts,
        args: SetupAdminArgs,
    ) -> anyhow::Result<Value> {
        let client =
            DynGlobalApi::new_admin_setup(cli.make_endpoints().await?, args.endpoint.clone())?;

        match &args.subcommand {
            SetupAdminCmd::Status => {
                let status = client.setup_status(cli.auth()?).await?;

                Ok(serde_json::to_value(status).expect("JSON serialization failed"))
            }
            SetupAdminCmd::SetLocalParams {
                name,
                federation_name,
            } => {
                let info = client
                    .set_local_params(
                        name.clone(),
                        federation_name.clone(),
                        None,
                        None,
                        cli.auth()?,
                    )
                    .await?;

                Ok(serde_json::to_value(info).expect("JSON serialization failed"))
            }
            SetupAdminCmd::AddPeer { info } => {
                let name = client
                    .add_peer_connection_info(info.clone(), cli.auth()?)
                    .await?;

                Ok(serde_json::to_value(name).expect("JSON serialization failed"))
            }
            SetupAdminCmd::StartDkg => {
                client.start_dkg(cli.auth()?).await?;

                Ok(Value::Null)
            }
        }
    }
}

async fn log_expiration_notice(client: &Client) {
    client.get_meta_expiration_timestamp().await;
    if let Some(expiration_time) = client.get_meta_expiration_timestamp().await {
        match expiration_time.duration_since(fedimint_core::time::now()) {
            Ok(until_expiration) => {
                let days = until_expiration.as_secs() / (60 * 60 * 24);

                if 90 < days {
                    debug!(target: LOG_CLIENT, %days, "This federation will expire");
                } else if 30 < days {
                    info!(target: LOG_CLIENT, %days, "This federation will expire");
                } else {
                    warn!(target: LOG_CLIENT, %days, "This federation will expire soon");
                }
            }
            Err(_) => {
                tracing::error!(target: LOG_CLIENT, "This federation has expired and might not be safe to use");
            }
        }
    }
}
async fn print_welcome_message(client: &Client) {
    if let Some(welcome_message) = client
        .meta_service()
        .get_field::<String>(client.db(), "welcome_message")
        .await
        .and_then(|v| v.value)
    {
        eprintln!("{welcome_message}");
    }
}

fn salt_from_file_path(file_path: &Path) -> PathBuf {
    file_path
        .parent()
        .expect("File has no parent?!")
        .join(SALT_FILE)
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
