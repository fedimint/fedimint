mod client;
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

use clap::{CommandFactory, Parser, Subcommand};
use fedimint_aead::{encrypted_read, encrypted_write, get_encryption_key};
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitRegistry};
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{get_invite_code_from_db, ClientBuilder, FederationInfo};
use fedimint_core::admin_client::WsAdminClient;
use fedimint_core::api::{
    ClientConfigDownloadToken, FederationApiExt, FederationError, GlobalFederationApi,
    IFederationApi, InviteCode, WsFederationApi,
};
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::core::OperationId;
use fedimint_core::db::DatabaseValue;
use fedimint_core::encoding::Encodable;
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::query::ThresholdConsensus;
use fedimint_core::util::SafeUrl;
use fedimint_core::{task, PeerId, TieredMulti};
use fedimint_ln_client::LightningClientGen;
use fedimint_logging::TracingSetup;
use fedimint_mint_client::{MintClientExt, MintClientGen, SpendableNote};
use fedimint_server::config::io::SALT_FILE;
use fedimint_wallet_client::api::WalletFederationApi;
use fedimint_wallet_client::{WalletClientGen, WalletClientModule};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tracing::{debug, info};
use utils::{from_hex, parse_peer_id};

use crate::client::ClientCmd;

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
        download_token: String,
        id: FederationId,
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

/// Types of error the cli return
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CliErrorKind {
    NetworkError,
    IOError,
    InvalidValue,
    OSError,
    GeneralFederationError,
    AlreadySpent,
    Timeout,
    InsufficientBalance,
    SerializationError,
    GeneralFailure,
    MissingAuth,
}

/// `Result` with `CliError` as `Error`
type CliResult<E> = Result<E, CliError>;

/// `Result` with `CliError` as `Error` and `CliOutput` as `Ok`
type CliOutputResult = Result<CliOutput, CliError>;

/// Cli error
#[derive(Serialize, Error)]
#[serde(tag = "error", rename_all(serialize = "snake_case"))]
struct CliError {
    kind: CliErrorKind,
    message: String,
    #[serde(skip_serializing)]
    #[source]
    raw_error: Option<anyhow::Error>,
}

/// Extension trait making turning Results/Errors into
/// [`CliError`]/[`CliOutputResult`] easier
trait CliResultExt<O, E> {
    /// Map error into `CliError` of [`CliErrorKind::GeneralFailure`] kind, use
    /// the error message as the message
    fn map_err_cli_general(self) -> Result<O, CliError>;
    /// Map error into `CliError` of [`CliErrorKind::IOError`] kind, use the
    /// error message as the message
    fn map_err_cli_io(self) -> Result<O, CliError>;
    /// Map error into `CliError` of `kind` and use custom `msg`
    fn map_err_cli_msg(self, kind: CliErrorKind, msg: impl Into<String>) -> Result<O, CliError>;
}

impl<O, E> CliResultExt<O, E> for result::Result<O, E>
where
    E: Into<anyhow::Error>,
{
    fn map_err_cli_io(self) -> Result<O, CliError> {
        self.map_err(|e| {
            let e = e.into();
            CliError {
                kind: CliErrorKind::IOError,
                message: e.to_string(),
                raw_error: Some(e),
            }
        })
    }
    fn map_err_cli_general(self) -> Result<O, CliError> {
        self.map_err(|e| {
            let e = e.into();
            CliError {
                kind: CliErrorKind::GeneralFailure,
                message: e.to_string(),
                raw_error: Some(e),
            }
        })
    }

    fn map_err_cli_msg(self, kind: CliErrorKind, msg: impl Into<String>) -> Result<O, CliError> {
        self.map_err(|e| CliError {
            kind,
            message: msg.into(),
            raw_error: Some(e.into()),
        })
    }
}

/// Extension trait to make turning `Option`s into
/// [`CliError`]/[`CliOutputResult`] easier
trait CliOptionExt<O> {
    fn ok_or_cli_msg(self, kind: CliErrorKind, msg: impl Into<String>) -> Result<O, CliError>;
}

impl<O> CliOptionExt<O> for Option<O> {
    fn ok_or_cli_msg(self, kind: CliErrorKind, msg: impl Into<String>) -> Result<O, CliError> {
        self.ok_or_else(|| CliError {
            kind,
            message: msg.into(),
            raw_error: None,
        })
    }
}

// TODO: Refactor federation API errors to just delegate to this
impl From<FederationError> for CliError {
    fn from(e: FederationError) -> Self {
        CliError {
            kind: CliErrorKind::GeneralFederationError,
            message: "Failed API call".into(),
            raw_error: Some(e.into()),
        }
    }
}

impl Debug for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .field("raw_error", &self.raw_error)
            .finish()
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut json = serde_json::to_value(self).unwrap();
        if let Some(err) = &self.raw_error {
            json["raw_error"] = json!(*err.to_string())
        }
        write!(f, "{}", serde_json::to_string_pretty(&json).unwrap())
    }
}

#[derive(Parser)]
#[command(version)]
struct Opts {
    /// The working directory of the client containing the config and db
    #[arg(long = "data-dir", alias = "workdir", env = "FM_DATA_DIR")]
    workdir: Option<PathBuf>,

    /// Peer id of the guardian
    #[arg(env = "FM_OUR_ID", long, value_parser = parse_peer_id)]
    our_id: Option<PeerId>,

    /// Guardian password for authentication
    #[arg(long, env = "FM_PASSWORD")]
    password: Option<String>,

    #[clap(subcommand)]
    command: Command,
}

impl Opts {
    fn workdir(&self) -> CliResult<&PathBuf> {
        self.workdir
            .as_ref()
            .ok_or_cli_msg(CliErrorKind::IOError, "`--data-dir=` argument not set.")
    }

    fn admin_client(&self, cfg: &ClientConfig) -> CliResult<WsAdminClient> {
        let our_id = &self
            .our_id
            .ok_or_cli_msg(CliErrorKind::MissingAuth, "Admin client needs our-id set")?;

        let url = cfg
            .global
            .api_endpoints
            .get(our_id)
            .expect("Endpoint exists")
            .url
            .clone();
        Ok(WsAdminClient::new(url))
    }

    fn auth(&self) -> CliResult<ApiAuth> {
        let password = self
            .password
            .clone()
            .ok_or_cli_msg(CliErrorKind::MissingAuth, "CLI needs password set")?;
        Ok(ApiAuth(password))
    }

    fn load_rocks_db(&self) -> CliResult<fedimint_rocksdb::RocksDb> {
        let db_path = self.workdir()?.join("client.db");
        fedimint_rocksdb::RocksDb::open(db_path)
            .map_err_cli_msg(CliErrorKind::IOError, "could not open transaction db")
    }

    async fn build_client_ng(
        &self,
        module_inits: &ClientModuleInitRegistry,
        invite_code: Option<InviteCode>,
    ) -> CliResult<fedimint_client::ClientArc> {
        let mut client_builder = self.build_client_builder(module_inits, invite_code).await?;
        let client_secret = match client_builder
            .load_decodable_client_secret::<[u8; 64]>()
            .await
        {
            Ok(secret) => secret,
            Err(_) => {
                info!("Generating secret and writing to client storage");
                let secret = PlainRootSecretStrategy::random(&mut thread_rng());
                client_builder
                    .store_encodable_client_secret(secret)
                    .await
                    .map_err_cli_general()?;
                secret
            }
        };
        client_builder
            .build(PlainRootSecretStrategy::to_root_secret(&client_secret))
            .await
            .map_err_cli_general()
    }

    async fn build_client_builder(
        &self,
        module_inits: &ClientModuleInitRegistry,
        invite_code: Option<InviteCode>,
    ) -> CliResult<fedimint_client::ClientBuilder> {
        let db = self.load_rocks_db()?;

        let mut client_builder = ClientBuilder::default();
        client_builder.with_module_inits(module_inits.clone());
        client_builder.with_primary_module(1);
        if let Some(invite_code) = invite_code {
            client_builder.with_federation_info(
                FederationInfo::from_invite_code(invite_code)
                    .await
                    .map_err_cli_general()?,
            );
        }
        client_builder.with_database(db);

        Ok(client_builder)
    }
}

#[derive(Subcommand, Clone)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Print the latest git commit hash this bin. was build with
    VersionHash,

    #[clap(flatten)]
    Client(client::ClientCmd),

    #[clap(subcommand)]
    Admin(AdminCmd),

    #[clap(subcommand)]
    Dev(DevCmd),

    /// Config enabling client to establish websocket connection to federation
    InviteCode,

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
    },

    /// Wait for the fed to reach a consensus block count
    WaitBlockCount { count: u64 },

    /// Decode connection info into its JSON representation
    DecodeInviteCode { invite_code: InviteCode },

    /// Encode connection info from its constituent parts
    EncodeInviteCode {
        #[clap(long = "url")]
        url: SafeUrl,
        #[clap(long = "download-token", value_parser = from_hex::<ClientConfigDownloadToken>)]
        download_token: ClientConfigDownloadToken,
        #[clap(long = "id")]
        id: FederationId,
        #[clap(long = "peer-id")]
        peer_id: PeerId,
    },

    /// Gets the current fedimint AlephBFT block count
    FedimintBlockCount,

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
}

impl FedimintCli {
    pub fn new() -> anyhow::Result<FedimintCli> {
        pub const CODE_VERSION: &str = env!("FEDIMINT_BUILD_CODE_VERSION");

        let mut args = std::env::args();
        if let Some(ref arg) = args.nth(1) {
            if arg.as_str() == "version-hash" {
                println!("{CODE_VERSION}");
                std::process::exit(0);
            }
        }

        TracingSetup::default().init().expect("tracing initializes");

        debug!("Starting fedimint-cli (version: {CODE_VERSION})");

        Ok(Self {
            module_inits: ClientModuleInitRegistry::new(),
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
        self.with_module(LightningClientGen)
            .with_module(MintClientGen)
            .with_module(WalletClientGen::default())
    }

    pub async fn run(&mut self) {
        let cli = Opts::parse();
        match self.handle_command(cli).await {
            Ok(output) => {
                // ignore if there's anyone reading the stuff we're writing out
                let _ = writeln!(std::io::stdout(), "{output}");
            }
            Err(err) => {
                let _ = writeln!(std::io::stderr(), "{err}");
                exit(1);
            }
        }
    }

    async fn handle_command(&mut self, cli: Opts) -> CliOutputResult {
        match cli.command.clone() {
            Command::InviteCode => {
                let rockdb = cli.load_rocks_db()?;
                let db = fedimint_core::db::Database::new(rockdb, Default::default());
                let invite_code = get_invite_code_from_db(&db)
                    .await
                    .ok_or_cli_msg(CliErrorKind::GeneralFailure, "invite code not found")?;
                Ok(CliOutput::InviteCode { invite_code })
            }
            Command::JoinFederation { invite_code } => {
                let invite: InviteCode = InviteCode::from_str(&invite_code)
                    .map_err_cli_msg(CliErrorKind::InvalidValue, "invalid invite code")?;

                // Build client and store config in DB
                let _client = cli
                    .build_client_ng(&self.module_inits, Some(invite.clone()))
                    .await
                    .map_err_cli_msg(CliErrorKind::GeneralFailure, "failed to build client")?;

                Ok(CliOutput::JoinFederation {
                    joined: invite_code,
                })
            }
            Command::VersionHash => Ok(CliOutput::VersionHash {
                hash: env!("FEDIMINT_BUILD_CODE_VERSION").to_string(),
            }),
            Command::Client(ClientCmd::Restore { secret }) => {
                let mut client_builder = cli
                    .build_client_builder(&self.module_inits, None)
                    .await
                    .map_err_cli_general()?;
                let client_secret = match client_builder
                    .load_decodable_client_secret::<[u8; 64]>()
                    .await
                {
                    Ok(existing_secret) if existing_secret == secret => secret,
                    Ok(_) => {
                        return Err(anyhow::anyhow!(
                            "Provided secret does not match existing secret"
                        ))
                        .map_err_cli_general()
                    }
                    Err(_) => {
                        info!("Generating secret and writing to client storage");
                        let new_secret = PlainRootSecretStrategy::random(&mut thread_rng());
                        client_builder
                            .store_encodable_client_secret(new_secret)
                            .await
                            .map_err_cli_general()?;
                        new_secret
                    }
                };
                let client = client_builder
                    .build_restoring_from_backup(PlainRootSecretStrategy::to_root_secret(
                        &client_secret,
                    ))
                    .await
                    .map_err_cli_msg(CliErrorKind::GeneralFailure, "failure")?
                    .0;

                info!("Waiting for restore to complete");
                let restored_amount = client
                    .await_restore_finished()
                    .await
                    .map_err_cli_msg(CliErrorKind::GeneralFailure, "failure")?;

                debug!("Restore complete");

                Ok(CliOutput::Raw(
                    serde_json::to_value(restored_amount.msats).unwrap(),
                ))
            }
            Command::Client(command) => {
                let client = cli
                    .build_client_ng(&self.module_inits, None)
                    .await
                    .map_err_cli_msg(CliErrorKind::GeneralFailure, "failure")?;
                let config = client.get_config().clone();
                Ok(CliOutput::Raw(
                    client::handle_command(command, config, client)
                        .await
                        .map_err_cli_msg(CliErrorKind::GeneralFailure, "failure")?,
                ))
            }
            Command::Admin(AdminCmd::Audit) => {
                let user = cli
                    .build_client_ng(&self.module_inits, None)
                    .await
                    .map_err_cli_msg(CliErrorKind::GeneralFailure, "failure")?;

                let audit = cli
                    .admin_client(user.get_config())?
                    .audit(cli.auth()?)
                    .await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(audit)
                        .map_err_cli_msg(CliErrorKind::GeneralFailure, "invalid response")?,
                ))
            }
            Command::Admin(AdminCmd::Status) => {
                let user = cli
                    .build_client_ng(&self.module_inits, None)
                    .await
                    .map_err_cli_msg(CliErrorKind::GeneralFailure, "failure")?;

                let status = cli.admin_client(user.get_config())?.status().await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(status)
                        .map_err_cli_msg(CliErrorKind::GeneralFailure, "invalid response")?,
                ))
            }
            Command::Dev(DevCmd::Api {
                method,
                params,
                peer_id,
            }) => {
                let params: Value = serde_json::from_str(&params)
                    .map_err_cli_msg(CliErrorKind::InvalidValue, "Invalid JSON-RPC parameters")?;
                let params = ApiRequestErased::new(params);
                let ws_api: Arc<_> = WsFederationApi::from_config(
                    cli.build_client_ng(&self.module_inits, None)
                        .await?
                        .get_config(),
                )
                .into();
                let response: Value = match peer_id {
                    Some(peer_id) => ws_api
                        .request_raw(peer_id.into(), &method, &[params.to_json()])
                        .await
                        .map_err_cli_general()?,
                    None => ws_api
                        .request_with_strategy(
                            ThresholdConsensus::full_participation(ws_api.peers().len()),
                            method,
                            params,
                        )
                        .await
                        .map_err_cli_general()?,
                };

                Ok(CliOutput::UntypedApiOutput { value: response })
            }
            Command::Dev(DevCmd::WaitBlockCount { count: target }) => {
                task::timeout(Duration::from_secs(30), async move {
                    let client = cli.build_client_ng(&self.module_inits, None).await?;
                    loop {
                        let (_, instance) = client
                            .get_first_module::<WalletClientModule>(&fedimint_wallet_client::KIND);
                        let count = client
                            .api()
                            .with_module(instance.id)
                            .fetch_consensus_block_count()
                            .await?;
                        if count >= target {
                            break Ok(CliOutput::WaitBlockCount { reached: count });
                        }
                        task::sleep(Duration::from_millis(100)).await;
                    }
                })
                .await
                .map_err_cli_msg(CliErrorKind::Timeout, "reached timeout")?
            }
            Command::Dev(DevCmd::DecodeInviteCode { invite_code }) => {
                Ok(CliOutput::DecodeInviteCode {
                    url: invite_code.url,
                    download_token: invite_code
                        .download_token
                        .consensus_encode_to_hex()
                        .expect("encodes"),
                    id: invite_code.id,
                })
            }
            Command::Dev(DevCmd::EncodeInviteCode {
                url,
                download_token,
                id,
                peer_id,
            }) => Ok(CliOutput::InviteCode {
                invite_code: InviteCode {
                    url,
                    download_token,
                    id,
                    peer_id,
                },
            }),
            Command::Dev(DevCmd::FedimintBlockCount) => {
                let count = cli
                    .build_client_ng(&self.module_inits, None)
                    .await?
                    .api()
                    .fetch_block_count()
                    .await?;
                Ok(CliOutput::EpochCount { count })
            }
            Command::Dev(DevCmd::ConfigDecrypt {
                in_file,
                out_file,
                salt_file,
                password,
            }) => {
                let salt_file = salt_file.unwrap_or_else(|| salt_from_file_path(&in_file));
                let salt = fs::read_to_string(salt_file).map_err_cli_general()?;
                let key = get_encryption_key(&password, &salt).map_err_cli_general()?;
                let decrypted_bytes = encrypted_read(&key, in_file).map_err_cli_general()?;

                let mut out_file_handle = fs::File::options()
                    .create_new(true)
                    .write(true)
                    .open(out_file)
                    .expect("Could not create output cfg file");
                out_file_handle
                    .write_all(&decrypted_bytes)
                    .map_err_cli_general()?;
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
                let salt = fs::read_to_string(salt_file).map_err_cli_general()?;
                let key = get_encryption_key(&password, &salt).map_err_cli_general()?;
                encrypted_write(plaintext_bytes, &key, out_file).map_err_cli_general()?;
                Ok(CliOutput::ConfigEncrypt)
            }
            Command::Dev(DevCmd::DecodeTransaction { hex_string }) => {
                let bytes: Vec<u8> = bitcoin_hashes::hex::FromHex::from_hex(&hex_string)
                    .map_err_cli_msg(
                        CliErrorKind::SerializationError,
                        "failed to decode transaction",
                    )?;

                let tx = fedimint_core::transaction::Transaction::from_bytes(
                    &bytes,
                    cli.build_client_ng(&self.module_inits, None)
                        .await?
                        .decoders(),
                )
                .map_err_cli_msg(
                    CliErrorKind::SerializationError,
                    "failed to decode transaction",
                )?;

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
                [] => Err(anyhow::format_err!("Empty metadata argument not allowed")),
                [key] => Err(anyhow::format_err!("Metadata {key} is missing a value")),
                [key, val] => Ok((key.clone(), val.clone())),
                [..] => unreachable!(),
            }
        })
        .collect::<anyhow::Result<_>>()
        .map_err_cli_msg(CliErrorKind::InvalidValue, "invalid metadata")?;
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
