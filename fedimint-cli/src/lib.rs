mod ng;

use core::fmt;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::{fs, result};

use bitcoin::{secp256k1, Address, Network, Transaction};
use clap::{Parser, Subcommand};
use fedimint_aead::get_password_hash;
use fedimint_client::module::gen::{ClientModuleGen, ClientModuleGenRegistry, IClientModuleGen};
use fedimint_client::sm::OperationId;
use fedimint_client::ClientBuilder;
use fedimint_client_legacy::mint::backup::Metadata;
use fedimint_client_legacy::mint::SpendableNote;
use fedimint_client_legacy::modules::ln::contracts::ContractId;
use fedimint_client_legacy::modules::wallet::WalletClientGen;
use fedimint_client_legacy::utils::{
    from_hex, parse_bitcoin_amount, parse_ecash, parse_fedimint_amount, parse_node_pub_key,
    parse_peer_id, serialize_ecash,
};
use fedimint_client_legacy::{Client, UserClientConfig};
use fedimint_core::admin_client::WsAdminClient;
use fedimint_core::api::{
    ClientConfigDownloadToken, FederationApiExt, FederationError, GlobalFederationApi,
    IFederationApi, WsClientConnectInfo, WsFederationApi,
};
use fedimint_core::config::{load_from_file, ClientConfig, FederationId};
use fedimint_core::db::{Database, DatabaseValue};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::{SerdeEpochHistory, SignedEpochOutcome};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::query::EventuallyConsistent;
use fedimint_core::task::TaskGroup;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::{Amount, OutPoint, PeerId, TieredMulti, TransactionId};
use fedimint_ln_client::LightningClientGen;
use fedimint_logging::TracingSetup;
use fedimint_mint_client::MintClientGen;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tracing::info;
use url::Url;

/// Type of output the cli produces
#[derive(Serialize)]
#[serde(rename_all(serialize = "snake_case"))]
#[serde(untagged)]
enum CliOutput {
    VersionHash {
        hash: String,
    },

    UntypedApiOutput {
        value: Value,
    },

    PegInAddress {
        address: Address,
    },

    PegIn {
        id: TransactionId,
    },

    Reissue {
        id: OutPoint,
    },

    Validate {
        all_valid: bool,
        details: BTreeMap<Amount, usize>,
    },

    Spend {
        note: String,
    },

    PegOut {
        tx_id: bitcoin::Txid,
    },

    LnPay {
        contract_id: ContractId,
    },

    Fetch {
        issuance: Vec<OutPoint>,
    },

    Info {
        federation_id: FederationId,
        network: Network,
        meta: BTreeMap<String, String>,
        total_amount: Amount,
        total_num_notes: usize,
        details: BTreeMap<Amount, usize>,
    },

    LnInvoice {
        invoice: lightning_invoice::Invoice,
    },

    WaitInvoice {
        paid_in_tx: OutPoint,
    },

    WaitBlockHeight {
        reached: u64,
    },

    ConnectInfo {
        connect_info: WsClientConnectInfo,
    },

    DecodeConnectInfo {
        url: Url,
        download_token: String,
        id: FederationId,
    },

    JoinFederation {
        joined: String,
    },

    ListGateways {
        num_gateways: usize,
        gateways: Value,
    },

    SwitchGateway {
        new_gateway: Value,
    },

    Backup,

    DecodeTransaction {
        transaction: String,
    },

    SignalUpgrade,

    EpochCount {
        count: u64,
    },

    LastEpoch {
        hex_outcome: String,
    },

    ForceEpoch,

    Raw(serde_json::Value),
}

impl fmt::Display for CliOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

/// Types of error the cli return
#[derive(Debug, Serialize, Deserialize)]
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

    /// Location of the salt file
    #[arg(env = "FM_SALT_PATH")]
    salt_path: Option<PathBuf>,

    /// Peer id of the guardian
    #[arg(env = "FM_OUR_ID", value_parser = parse_peer_id)]
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

    async fn admin_client(&self) -> CliResult<WsAdminClient> {
        let salt_path = self.salt_path.clone().ok_or_cli_msg(
            CliErrorKind::MissingAuth,
            "Admin client needs salt-path set",
        )?;
        let password = self
            .password
            .clone()
            .ok_or_cli_msg(CliErrorKind::MissingAuth, "Admin client needs password set")?;
        let our_id = &self
            .our_id
            .ok_or_cli_msg(CliErrorKind::MissingAuth, "Admin client needs our-id set")?;
        let salt = fs::read_to_string(salt_path)
            .map_err_cli_msg(CliErrorKind::IOError, "Unable to open salt file")?;
        let auth = ApiAuth(get_password_hash(&password, &salt).map_err_cli_io()?);
        let url = self
            .load_config()?
            .0
            .api_endpoints
            .get(our_id)
            .expect("Endpoint exists")
            .url
            .clone();
        Ok(WsAdminClient::new(url, *our_id, auth))
    }

    fn load_config(&self) -> CliResult<UserClientConfig> {
        let cfg_path = self.workdir()?.join("client.json");
        load_from_file(&cfg_path).map_err_cli_msg(CliErrorKind::IOError, "could not load config")
    }

    fn load_rocks_db(&self) -> CliResult<fedimint_rocksdb::RocksDb> {
        let db_path = self.workdir()?.join("client.db");
        fedimint_rocksdb::RocksDb::open(db_path)
            .map_err_cli_msg(CliErrorKind::IOError, "could not open transaction db")
    }

    fn load_decoders(
        &self,
        cfg: &UserClientConfig,
        module_gens: &ClientModuleGenRegistry,
    ) -> ModuleDecoderRegistry {
        ModuleDecoderRegistry::new(cfg.clone().0.modules.into_iter().filter_map(
            |(id, module_cfg)| {
                let kind = module_cfg.kind().clone();
                module_gens.get(&kind).map(|module_gen| {
                    (
                        id,
                        kind,
                        IClientModuleGen::decoder(AsRef::<dyn IClientModuleGen + 'static>::as_ref(
                            module_gen,
                        )),
                    )
                })
            },
        ))
    }

    fn load_db(&self, decoders: &ModuleDecoderRegistry) -> CliResult<Database> {
        let db = self.load_rocks_db()?;
        Ok(Database::new(db, decoders.clone()))
    }

    async fn build_client(
        &self,
        module_gens: &ClientModuleGenRegistry,
    ) -> CliResult<Client<UserClientConfig>> {
        let cfg = self.load_config()?;
        let decoders = self.load_decoders(&cfg, module_gens);
        let db = self.load_db(&decoders)?;

        Ok(Client::new(
            cfg.clone(),
            decoders,
            module_gens.clone(),
            db,
            Default::default(),
        )
        .await)
    }

    async fn build_client_ng(
        &self,
        module_gens: &ClientModuleGenRegistry,
    ) -> CliResult<fedimint_client::Client> {
        let mut tg = TaskGroup::new();
        let cfg = self.load_config()?.0;
        let db = self.load_rocks_db()?;

        let mut client_builder = ClientBuilder::default();
        client_builder.with_module_gens(module_gens.clone());
        client_builder.with_primary_module(1);
        client_builder.with_config(cfg.clone());
        client_builder.with_database(db);

        client_builder.build(&mut tg).await.map_err_cli_general()
    }
}

#[derive(Subcommand, Clone)]
enum Command {
    /// Print the latest git commit hash this bin. was build with
    VersionHash,
    /// Generate a new peg-in address, funds sent to it can later be claimed
    PegInAddress,

    /// Send direct method call to the API. If you specify --peer-id, it will
    /// just ask one server, otherwise it will get consensus from all servers
    Api {
        /// JSON-RPC method to call
        method: String,
        /// JSON-RPC parameters for the request
        #[clap(default_value = "null")]
        params: String,
        /// Which server to send request to
        #[clap(long = "peer-id")]
        peer_id: Option<u16>,
    },

    /// Issue notes in exchange for a peg-in proof
    PegIn {
        #[clap(long, value_parser = from_hex::<TxOutProof>)]
        txout_proof: TxOutProof,
        #[clap(long, value_parser = from_hex::<Transaction>)]
        transaction: Transaction,
    },

    /// Reissue notes received from a third party to avoid double spends
    Reissue {
        #[clap(value_parser = parse_ecash)]
        notes: TieredMulti<SpendableNote>,
    },

    /// Validate notes without claiming them (only checks if signatures valid,
    /// does not check if nonce unspent)
    Validate {
        #[clap(value_parser = parse_ecash)]
        notes: TieredMulti<SpendableNote>,
    },

    /// Prepare notes to send to a third party as a payment
    Spend {
        #[clap(value_parser = parse_fedimint_amount)]
        amount: Amount,
    },

    /// Withdraw funds from the federation
    PegOut {
        #[clap(long)]
        address: Address,
        #[clap(long, value_parser = parse_bitcoin_amount)]
        amount: bitcoin::Amount,
    },

    /// Pay a lightning invoice via a gateway
    LnPay { bolt11: lightning_invoice::Invoice },

    /// Fetch (re-)issued notes and finalize issuance process
    Fetch,

    /// Display wallet info (holdings, tiers)
    Info,

    /// Create a lightning invoice to receive payment via gateway
    LnInvoice {
        #[clap(long, value_parser = parse_fedimint_amount)]
        amount: Amount,
        #[clap(long, default_value = "")]
        description: String,
        #[clap(long)]
        expiry_time: Option<u64>,
    },

    /// Wait for incoming invoice to be paid
    WaitInvoice { invoice: lightning_invoice::Invoice },

    /// Wait for the fed to reach a consensus block height
    WaitBlockHeight { height: u64 },

    /// Decode connection info into its JSON representation
    DecodeConnectInfo { connect_info: WsClientConnectInfo },

    /// Encode connection info from its constituent parts
    EncodeConnectInfo {
        #[clap(long = "url")]
        url: Url,
        #[clap(long = "download-token", value_parser = from_hex::<ClientConfigDownloadToken>)]
        download_token: ClientConfigDownloadToken,
        #[clap(long = "id")]
        id: FederationId,
    },

    /// Config enabling client to establish websocket connection to federation
    ConnectInfo,

    /// Join a federation using it's ConnectInfo
    JoinFederation { connect: String },

    /// List registered gateways
    ListGateways,

    /// Switch active gateway
    SwitchGateway {
        /// node public key for a gateway
        #[clap(value_parser = parse_node_pub_key)]
        pubkey: secp256k1::PublicKey,
    },

    /// Upload the (encrypted) snapshot of mint notes to federation
    Backup {
        #[clap(long = "metadata")]
        /// Backup metadata, encoded as `key=value` (use `--metadata=key=value`,
        /// possibly multiple times)
        // TODO: Can we make it `*Map<String, String>` and avoid custom parsing?
        metadata: Vec<String>,
    },

    /// Restore the previously created backup of mint notes (with `backup`
    /// command)
    Restore {
        /// The amount of nonces to look ahead when scanning epoch history (per
        /// amount tier)
        ///
        /// Larger values might make the restore initialization slower and
        /// memory usage slightly higher, but help restore all mint
        /// notes in some rare situations.
        #[clap(long, default_value = "100")]
        gap_limit: usize,
    },

    /// Wipe the notes data from the DB. Useful for testing backup & restore
    #[clap(hide = true)]
    WipeNotes,

    /// Decode a transaction hex string and print it to stdout
    DecodeTransaction { hex_string: String },

    /// Signal a consensus upgrade
    SignalUpgrade,

    /// Gets the current epoch count
    EpochCount,

    /// Gets the last epoch
    LastEpoch,

    /// Force processing an epoch
    ForceEpoch { hex_outcome: String },

    /// Show the status according to the `status` endpoint
    Status,

    #[clap(subcommand)]
    Ng(ng::ClientNg),
}

#[derive(Debug, Serialize, Deserialize)]
struct PayRequest {
    notes: TieredMulti<SpendableNote>,
    invoice: lightning_invoice::Invoice,
}

pub struct FedimintCli {
    module_gens: ClientModuleGenRegistry,
}

impl FedimintCli {
    pub fn new() -> anyhow::Result<FedimintCli> {
        pub const CODE_VERSION: &str = env!("CODE_VERSION");

        let mut args = std::env::args();
        if let Some(ref arg) = args.nth(1) {
            if arg.as_str() == "version-hash" {
                println!("{CODE_VERSION}");
                std::process::exit(0);
            }
        }

        info!("Starting fedimintd (version: {CODE_VERSION})");

        TracingSetup::default().init().expect("tracing initializes");
        Ok(Self {
            module_gens: ClientModuleGenRegistry::new(),
        })
    }

    pub fn with_module<T>(mut self, gen: T) -> Self
    where
        T: ClientModuleGen + 'static + Send + Sync,
    {
        self.module_gens.attach(gen);
        self
    }

    pub fn with_default_modules(self) -> Self {
        self.with_module(LightningClientGen)
            .with_module(MintClientGen)
            .with_module(WalletClientGen)
    }

    pub async fn run(self) {
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

    async fn handle_command(&self, cli: Opts) -> CliOutputResult {
        let mut task_group = TaskGroup::new();
        let mut rng = rand::rngs::OsRng;

        match cli.command.clone() {
            Command::JoinFederation { connect } => {
                let connect_obj: WsClientConnectInfo = WsClientConnectInfo::from_str(&connect)
                    .map_err_cli_msg(CliErrorKind::InvalidValue, "invalid connect info")?;
                let api = Arc::new(WsFederationApi::from_connect_info(&[connect_obj.clone()]))
                    as Arc<dyn IFederationApi + Send + Sync + 'static>;
                let cfg: ClientConfig = api
                    .download_client_config(&connect_obj)
                    .await
                    .map_err_cli_msg(
                        CliErrorKind::NetworkError,
                        "couldn't download config from peer",
                    )?;
                std::fs::create_dir_all(cli.workdir()?)
                    .map_err_cli_msg(CliErrorKind::IOError, "failed to create config directory")?;
                let cfg_path = cli.workdir()?.join("client.json");
                let writer = std::fs::File::options()
                    .create_new(true)
                    .write(true)
                    .open(cfg_path)
                    .map_err_cli_msg(CliErrorKind::IOError, "couldn't create config.json")?;
                serde_json::to_writer_pretty(writer, &cfg)
                    .map_err_cli_msg(CliErrorKind::IOError, "couldn't write config")?;
                Ok(CliOutput::JoinFederation { joined: connect })
            }
            Command::Api {
                method,
                params,
                peer_id,
            } => {
                let params: Value = serde_json::from_str(&params)
                    .map_err_cli_msg(CliErrorKind::InvalidValue, "Invalid JSON-RPC parameters")?;
                let params = ApiRequestErased::new(params);
                let ws_api: Arc<_> = WsFederationApi::from_config(
                    cli.build_client(&self.module_gens).await?.config().as_ref(),
                )
                .into();
                let response: Value = match peer_id {
                    Some(peer_id) => ws_api
                        .request_raw(peer_id.into(), &method, &[params.to_json()])
                        .await
                        .map_err_cli_general()?,
                    None => ws_api
                        .request_with_strategy(
                            EventuallyConsistent::new(ws_api.peers().len()),
                            method,
                            params,
                        )
                        .await
                        .map_err_cli_general()?,
                };

                Ok(CliOutput::UntypedApiOutput { value: response })
            }
            Command::VersionHash => Ok(CliOutput::VersionHash {
                hash: env!("CODE_VERSION").to_string(),
            }),
            Command::PegInAddress => {
                let peg_in_address = cli
                    .build_client(&self.module_gens)
                    .await?
                    .get_new_pegin_address(rng)
                    .await;
                Ok(CliOutput::PegInAddress {
                    address: (peg_in_address),
                })
            }
            Command::PegIn {
                txout_proof,
                transaction,
            } => cli
                .build_client(&self.module_gens)
                .await?
                .peg_in(txout_proof, transaction, &mut rng)
                .await
                .map(|v| CliOutput::PegIn { id: (v) })
                .map_err_cli_msg(
                    CliErrorKind::GeneralFederationError,
                    "peg-in failed (no further information)",
                ),

            Command::Reissue { notes } => cli
                .build_client(&self.module_gens)
                .await?
                .reissue(notes, &mut rng)
                .await
                .map(|v| CliOutput::Reissue { id: (v) })
                .map_err_cli_msg(
                    CliErrorKind::GeneralFederationError,
                    "could not reissue notes (no further information)",
                ),
            Command::Validate { notes } => {
                let validate_result = cli
                    .build_client(&self.module_gens)
                    .await?
                    .validate_note_signatures(&notes)
                    .await;
                let details_vec = notes
                    .iter()
                    .map(|(amount, notes)| (amount.to_owned(), notes.len()))
                    .collect();

                match validate_result {
                    Ok(()) => Ok(CliOutput::Validate {
                        all_valid: true,
                        details: (details_vec),
                    }),
                    Err(_) => Ok(CliOutput::Validate {
                        all_valid: false,
                        details: (details_vec),
                    }),
                }
            }
            Command::Spend { amount } => cli
                .build_client(&self.module_gens)
                .await?
                .spend_ecash(amount, rng)
                .await
                .map(|v| CliOutput::Spend {
                    note: (serialize_ecash(&v)),
                })
                .map_err_cli_msg(
                    CliErrorKind::GeneralFederationError,
                    "failed to execute spend (no further information)",
                ),
            Command::Fetch => cli
                .build_client(&self.module_gens)
                .await?
                .fetch_all_notes()
                .await
                .map(|issuance| CliOutput::Fetch { issuance })
                .map_err_cli_msg(
                    CliErrorKind::GeneralFederationError,
                    "failed to fetch notes",
                ),
            Command::Info => {
                let client = cli.build_client(&self.module_gens).await?;
                let summary = client.summary().await;

                Ok(CliOutput::Info {
                    federation_id: client.config().as_ref().federation_id,
                    network: client.wallet_client().config.network,
                    meta: client.config().0.meta,
                    total_amount: summary.total_amount(),
                    total_num_notes: summary.count_items(),
                    details: summary.iter().collect(),
                })
            }
            Command::PegOut { address, amount } => {
                let client = cli.build_client(&self.module_gens).await?;
                let peg_out = client
                    .new_peg_out_with_fees(amount, address)
                    .await
                    .map_err_cli_msg(
                        CliErrorKind::GeneralFederationError,
                        "failed to request peg-out",
                    )?;
                let out_point = client.peg_out(peg_out, &mut rng).await.map_err_cli_msg(
                    CliErrorKind::GeneralFederationError,
                    "failed to commit peg-out",
                )?;
                client
                    .wallet_client()
                    .await_peg_out_outcome(out_point)
                    .await
                    .map(|tx_id| CliOutput::PegOut { tx_id })
                    .map_err_cli_msg(
                        CliErrorKind::GeneralFederationError,
                        "invalid peg-out outcome",
                    )
            }
            Command::LnPay { bolt11 } => {
                let client = cli.build_client(&self.module_gens).await?;
                let (contract_id, outpoint) = client
                    .fund_outgoing_ln_contract(bolt11, &mut rng)
                    .await
                    .map_err_cli_msg(
                        CliErrorKind::GeneralFederationError,
                        "Failure creating outgoing LN contract",
                    )?;
                client
                    .await_outgoing_contract_acceptance(outpoint)
                    .await
                    .map_err_cli_msg(CliErrorKind::Timeout, "contract wasn't accepted in time")?;
                client
                    .await_outgoing_contract_execution(contract_id, &mut rng)
                    .await
                    .map(|_| CliOutput::LnPay {
                        contract_id: (contract_id),
                    })
                    .map_err_cli_msg(
                        CliErrorKind::GeneralFederationError,
                        "gateway failed to execute contract",
                    )
            }
            Command::LnInvoice {
                amount,
                description,
                expiry_time,
            } => cli
                .build_client(&self.module_gens)
                .await?
                .generate_confirmed_invoice(amount, description, &mut rng, expiry_time)
                .await
                .map(|confirmed_invoice| CliOutput::LnInvoice {
                    invoice: (confirmed_invoice.invoice),
                })
                .map_err_cli_msg(
                    CliErrorKind::GeneralFederationError,
                    "couldn't create invoice",
                ),
            Command::WaitInvoice { invoice } => {
                let contract_id = (*invoice.payment_hash()).into();
                cli.build_client(&self.module_gens)
                    .await?
                    .claim_incoming_contract(contract_id, &mut rng)
                    .await
                    .map(|outpoint| CliOutput::WaitInvoice {
                        paid_in_tx: (outpoint),
                    })
                    .map_err_cli_msg(CliErrorKind::Timeout, "invoice did not get paid in time")
            }
            Command::WaitBlockHeight { height } => cli
                .build_client(&self.module_gens)
                .await?
                .await_consensus_block_height(height)
                .await
                .map(|_| CliOutput::WaitBlockHeight { reached: (height) })
                .map_err_cli_msg(CliErrorKind::Timeout, "timeout reached"),
            Command::ConnectInfo => {
                let path = cli.workdir()?.join("client-connect");
                let string = fs::read_to_string(path).map_err_cli_msg(
                    CliErrorKind::GeneralFederationError,
                    "cannot read connect string",
                )?;

                let connect_info = WsClientConnectInfo::from_str(&string).map_err_cli_msg(
                    CliErrorKind::GeneralFederationError,
                    "cannot parse connect string",
                )?;

                Ok(CliOutput::ConnectInfo { connect_info })
            }
            Command::DecodeConnectInfo { connect_info } => Ok(CliOutput::DecodeConnectInfo {
                url: connect_info.url,
                download_token: connect_info
                    .download_token
                    .consensus_encode_to_hex()
                    .expect("encodes"),
                id: connect_info.id,
            }),
            Command::EncodeConnectInfo {
                url,
                download_token,
                id,
            } => Ok(CliOutput::ConnectInfo {
                connect_info: WsClientConnectInfo {
                    url,
                    download_token,
                    id,
                },
            }),
            Command::ListGateways {} => {
                let client = cli.build_client(&self.module_gens).await?;
                let gateways = client.fetch_registered_gateways().await.map_err_cli_msg(
                    CliErrorKind::GeneralFederationError,
                    "failed to fetch gateways",
                )?;
                if gateways.is_empty() {
                    return Err(CliError {
                        kind: CliErrorKind::GeneralFederationError,
                        message: "no gateways found".into(),
                        raw_error: None,
                    });
                }

                let mut gateways_json = json!(&gateways);
                let active_gateway = client.fetch_active_gateway().await.map_err_cli_msg(
                    CliErrorKind::GeneralFederationError,
                    "could not determine active gateway",
                )?;
                gateways_json
                    .as_array_mut()
                    .expect("gateways_json is not an array")
                    .iter_mut()
                    .for_each(|gateway| {
                        if gateway["node_pub_key"] == json!(active_gateway.node_pub_key) {
                            gateway["active"] = json!(true);
                        } else {
                            gateway["active"] = json!(false);
                        }
                    });
                Ok(CliOutput::ListGateways {
                    num_gateways: (gateways.len()),
                    gateways: (gateways_json),
                })
            }
            Command::SwitchGateway { pubkey } => {
                let gateway = cli
                    .build_client(&self.module_gens)
                    .await?
                    .switch_active_gateway(Some(pubkey))
                    .await
                    .map_err_cli_msg(
                        CliErrorKind::GeneralFederationError,
                        "failed to switch active gateway",
                    )?;
                let mut gateway_json = json!(&gateway);
                gateway_json["active"] = json!(true);
                Ok(CliOutput::SwitchGateway {
                    new_gateway: (gateway_json),
                })
            }
            Command::Backup { metadata } => {
                let metadata = metadata_from_clap_cli(metadata)?;

                cli.build_client(&self.module_gens)
                    .await?
                    .mint_client()
                    .back_up_ecash_to_federation(Metadata::from_json_serialized(metadata))
                    .await
                    .map(|_| CliOutput::Backup)
                    .map_err_cli_msg(CliErrorKind::GeneralFederationError, "failed")
            }
            Command::Restore { gap_limit } => cli
                .build_client(&self.module_gens)
                .await?
                .mint_client()
                .restore_ecash_from_federation(gap_limit, &mut task_group)
                .await
                .map(|_| CliOutput::Backup)
                .map_err_cli_msg(CliErrorKind::GeneralFederationError, "failed"),
            Command::WipeNotes => cli
                .build_client(&self.module_gens)
                .await?
                .mint_client()
                .wipe_notes()
                .await
                .map(|_| CliOutput::Backup)
                .map_err_cli_msg(CliErrorKind::GeneralFederationError, "failed"),

            Command::DecodeTransaction { hex_string } => {
                let bytes: Vec<u8> = bitcoin_hashes::hex::FromHex::from_hex(&hex_string)
                    .map_err_cli_msg(
                        CliErrorKind::SerializationError,
                        "failed to decode transaction",
                    )?;

                let tx = fedimint_core::transaction::Transaction::from_bytes(
                    &bytes,
                    cli.build_client(&self.module_gens).await?.decoders(),
                )
                .map_err_cli_msg(
                    CliErrorKind::SerializationError,
                    "failed to decode transaction",
                )?;

                Ok(CliOutput::DecodeTransaction {
                    transaction: (format!("{tx:?}")),
                })
            }
            Command::SignalUpgrade => {
                cli.admin_client().await?.signal_upgrade().await?;
                Ok(CliOutput::SignalUpgrade)
            }
            Command::EpochCount => {
                let count = cli
                    .build_client(&self.module_gens)
                    .await?
                    .context()
                    .api
                    .fetch_epoch_count()
                    .await?;
                Ok(CliOutput::EpochCount { count })
            }
            Command::LastEpoch => {
                let cfg = cli.load_config()?;
                let decoders = cli.load_decoders(&cfg, &self.module_gens);
                let client = cli.admin_client().await?;
                let last_epoch = client
                    .fetch_last_epoch_history(cfg.0.epoch_pk, &decoders)
                    .await?;

                let hex_outcome = last_epoch.consensus_encode_to_hex().map_err_cli_io()?;
                Ok(CliOutput::LastEpoch { hex_outcome })
            }
            Command::ForceEpoch { hex_outcome } => {
                let cfg = cli.load_config()?;
                let decoders = cli.load_decoders(&cfg, &self.module_gens);
                let outcome: SignedEpochOutcome = Decodable::consensus_decode_hex(
                    &hex_outcome,
                    &decoders,
                )
                .map_err_cli_msg(CliErrorKind::SerializationError, "failed to decode outcome")?;
                let client = cli.admin_client().await?;
                client
                    .force_process_epoch(SerdeEpochHistory::from(&outcome))
                    .await?;
                Ok(CliOutput::ForceEpoch)
            }
            Command::Ng(command) => {
                let config = cli.load_config()?.0;
                let client = cli
                    .build_client_ng(&self.module_gens)
                    .await
                    .map_err_cli_msg(CliErrorKind::GeneralFailure, "failure")?;
                Ok(CliOutput::Raw(
                    ng::handle_ng_command(command, config, client)
                        .await
                        .map_err_cli_msg(CliErrorKind::GeneralFailure, "failure")?,
                ))
            }
            Command::Status => {
                let status = cli.admin_client().await?.status().await?;
                Ok(CliOutput::Raw(
                    serde_json::to_value(status)
                        .map_err_cli_msg(CliErrorKind::GeneralFailure, "invalid response")?,
                ))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
