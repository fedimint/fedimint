use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId, TieredMulti};
use fedimint_eventlog::EventLogId;
use fedimint_mint_client::{OOBNotes, SpendableNote};
use serde::{Deserialize, Serialize};

use crate::client::{ClientCmd, ModuleSelector};
#[cfg(feature = "tor")]
use crate::envs::FM_USE_TOR_ENV;
use crate::envs::{
    FM_API_SECRET_ENV, FM_CLIENT_DIR_ENV, FM_DB_BACKEND_ENV, FM_FEDERATION_SECRET_HEX_ENV,
    FM_IROH_ENABLE_DHT_ENV, FM_IROH_ENABLE_NEXT_ENV, FM_OUR_ID_ENV, FM_PASSWORD_API_ENV,
};
use crate::utils::parse_peer_id;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum DatabaseBackend {
    /// Use RocksDB database backend
    #[value(name = "rocksdb")]
    RocksDb,
    /// Use CursedRedb database backend (hybrid memory/redb)
    #[value(name = "cursed-redb")]
    CursedRedb,
}

#[derive(Parser, Clone)]
#[command(version)]
pub(crate) struct Opts {
    /// The working directory of the client containing the config and db
    #[arg(long = "data-dir", env = FM_CLIENT_DIR_ENV)]
    pub data_dir: Option<PathBuf>,

    /// Peer id of the guardian
    #[arg(env = FM_OUR_ID_ENV, long, value_parser = parse_peer_id)]
    pub our_id: Option<PeerId>,

    /// Guardian password for authentication
    #[arg(long, env = FM_PASSWORD_API_ENV)]
    pub password: Option<String>,

    /// Federation secret as consensus-encoded hex.
    #[arg(long, env = FM_FEDERATION_SECRET_HEX_ENV)]
    pub federation_secret_hex: Option<String>,

    #[cfg(feature = "tor")]
    /// Activate usage of Tor as the Connector when building the Client
    #[arg(long, env = FM_USE_TOR_ENV)]
    pub use_tor: bool,

    // Enable using DHT name resolution in Iroh
    #[arg(long, env = FM_IROH_ENABLE_DHT_ENV)]
    pub iroh_enable_dht: Option<bool>,

    // Enable using (in parallel) unstable/next Iroh stack
    #[arg(long, env = FM_IROH_ENABLE_NEXT_ENV)]
    pub iroh_enable_next: Option<bool>,

    /// Database backend to use.
    #[arg(long, env = FM_DB_BACKEND_ENV, value_enum, default_value = "rocksdb")]
    pub db_backend: DatabaseBackend,

    /// Activate more verbose logging, for full control use the RUST_LOG env
    /// variable
    #[arg(short = 'v', long)]
    pub verbose: bool,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Clone)]
pub(crate) enum Command {
    /// Print the latest Git commit hash this bin. was built with.
    VersionHash,

    #[clap(flatten)]
    Client(ClientCmd),

    #[clap(subcommand)]
    Admin(AdminCmd),

    #[clap(subcommand)]
    Dev(DevCmd),

    /// Config enabling client to establish websocket connection to federation
    InviteCode {
        peer: PeerId,
    },

    /// Join a federation using its InviteCode
    #[clap(alias = "join-federation")]
    Join {
        invite_code: String,
    },

    Completion {
        shell: clap_complete::Shell,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum AdminCmd {
    /// Store admin credentials (peer_id and password) in the client database.
    ///
    /// This allows subsequent admin commands to be run without specifying
    /// `--our-id` and `--password` each time.
    ///
    /// The command will verify the credentials by making an authenticated
    /// API call before storing them.
    Auth {
        /// Guardian's peer ID
        #[arg(long, env = FM_OUR_ID_ENV)]
        peer_id: u16,
        /// Guardian password for authentication
        #[arg(long, env = FM_PASSWORD_API_ENV)]
        password: String,
        /// Skip interactive endpoint verification
        #[arg(long)]
        no_verify: bool,
        /// Force overwrite existing stored credentials
        #[arg(long)]
        force: bool,
    },

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
    /// Sign guardian metadata
    SignGuardianMetadata {
        /// API URLs (can be specified multiple times or comma-separated)
        #[clap(long, value_delimiter = ',')]
        api_urls: Vec<SafeUrl>,
        /// Pkarr ID (z32 format)
        #[clap(long)]
        pkarr_id: String,
    },
    /// Stop fedimintd after the specified session to do a coordinated upgrade
    Shutdown {
        /// Session index to stop after
        session_idx: u64,
    },
    /// Show statistics about client backups stored by the federation
    BackupStatistics,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct SetupAdminArgs {
    pub endpoint: SafeUrl,

    #[clap(subcommand)]
    pub subcommand: SetupAdminCmd,
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum SetupAdminCmd {
    Status,
    SetLocalParams {
        name: String,
        #[clap(long)]
        federation_name: Option<String>,
        #[clap(long)]
        federation_size: Option<u32>,
    },
    AddPeer {
        info: String,
    },
    StartDkg,
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum DecodeType {
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
pub(crate) struct OOBNotesJson {
    pub federation_id_prefix: String,
    pub notes: TieredMulti<SpendableNote>,
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum EncodeType {
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
pub(crate) enum DevCmd {
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

    GuardianMetadata,

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

    /// Returns the client config
    Config,

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
        #[arg(env = FM_PASSWORD_API_ENV)]
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
        #[arg(env = FM_PASSWORD_API_ENV)]
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
    /// Trigger a panic to verify backtrace handling
    Panic,
    /// Visualize client internals for debugging
    Visualize {
        #[clap(subcommand)]
        visualize_type: VisualizeCmd,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum VisualizeCmd {
    /// Show every e-cash note with creation/spending provenance
    Notes {
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show transactions with inputs and outputs
    Transactions {
        /// Show a specific operation (by full ID)
        operation_id: Option<OperationId>,
        /// How many most-recent operations to show (ignored if operation_id is
        /// given)
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show operations with their state machines
    Operations {
        /// Show a specific operation (by full ID)
        operation_id: Option<OperationId>,
        /// How many most-recent operations to show (ignored if operation_id is
        /// given)
        #[arg(long)]
        limit: Option<usize>,
    },
}
