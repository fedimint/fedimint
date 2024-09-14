#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::large_futures)]

mod metrics;

use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use bitcoin::Network;
use clap::{ArgGroup, Parser};
use fedimint_core::db::Database;
use fedimint_core::envs::{
    FM_ENABLE_MODULE_LNV1_ENV, FM_ENABLE_MODULE_LNV2_ENV, FM_IROH_DNS_ENV, FM_IROH_RELAY_ENV,
    FM_USE_UNKNOWN_MODULE_ENV, is_env_var_set, is_env_var_set_opt,
};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::rustls::install_crypto_provider;
use fedimint_core::task::TaskGroup;
use fedimint_core::timing;
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl, handle_version_hash_command};
use fedimint_ln_server::LightningInit;
use fedimint_logging::{LOG_CORE, LOG_SERVER, TracingSetup};
use fedimint_meta_server::MetaInit;
use fedimint_mint_server::MintInit;
use fedimint_rocksdb::RocksDb;
use fedimint_server::config::ConfigGenSettings;
use fedimint_server::config::io::DB_FILE;
use fedimint_server::core::ServerModuleInitRegistry;
use fedimint_server::net::api::ApiSecrets;
use fedimint_server_bitcoin_rpc::BitcoindClientWithFallback;
use fedimint_server_bitcoin_rpc::bitcoind::BitcoindClient;
use fedimint_server_bitcoin_rpc::esplora::EsploraClient;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use fedimint_unknown_server::UnknownInit;
use fedimint_wallet_server::WalletInit;
use fedimintd_envs::{
    FM_API_URL_ENV, FM_BIND_API_ENV, FM_BIND_METRICS_ENV, FM_BIND_P2P_ENV,
    FM_BIND_TOKIO_CONSOLE_ENV, FM_BIND_UI_ENV, FM_BITCOIN_NETWORK_ENV, FM_BITCOIND_PASSWORD_ENV,
    FM_BITCOIND_URL_ENV, FM_BITCOIND_URL_PASSWORD_FILE_ENV, FM_BITCOIND_USERNAME_ENV,
    FM_DATA_DIR_ENV, FM_DB_CHECKPOINT_RETENTION_ENV, FM_DISABLE_META_MODULE_ENV,
    FM_ENABLE_IROH_ENV, FM_ESPLORA_URL_ENV, FM_FORCE_API_SECRETS_ENV,
    FM_IROH_API_MAX_CONNECTIONS_ENV, FM_IROH_API_MAX_REQUESTS_PER_CONNECTION_ENV, FM_P2P_URL_ENV,
};
use futures::FutureExt as _;
use tracing::{debug, error, info};

use crate::metrics::APP_START_TS;

/// Time we will wait before forcefully shutting down tasks
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(version)]
#[command(
    group(
        ArgGroup::new("bitcoind_password_auth")
           .args(["bitcoind_password", "bitcoind_url_password_file"])
           .multiple(false)
    ),
    group(
        ArgGroup::new("bitcoind_auth")
            .args(["bitcoind_url"])
            .requires("bitcoind_password_auth")
            .requires_all(["bitcoind_username", "bitcoind_url"])
    ),
    group(
        ArgGroup::new("bitcoin_rpc")
            .required(true)
            .multiple(true)
            .args(["bitcoind_url", "esplora_url"])
    )
)]
struct ServerOpts {
    /// Path to folder containing federation config files
    #[arg(long = "data-dir", env = FM_DATA_DIR_ENV)]
    data_dir: PathBuf,

    /// The bitcoin network of the federation
    #[arg(long, env = FM_BITCOIN_NETWORK_ENV, default_value = "regtest")]
    bitcoin_network: Network,

    /// The username to use when connecting to bitcoind
    #[arg(long, env = FM_BITCOIND_USERNAME_ENV)]
    bitcoind_username: Option<String>,

    /// The password to use when connecting to bitcoind
    #[arg(long, env = FM_BITCOIND_PASSWORD_ENV)]
    bitcoind_password: Option<String>,

    /// Bitcoind RPC URL, e.g. <http://127.0.0.1:8332>
    /// This should not include authentication parameters, they should be
    /// included in `FM_BITCOIND_USERNAME` and `FM_BITCOIND_PASSWORD`
    #[arg(long, env = FM_BITCOIND_URL_ENV)]
    bitcoind_url: Option<SafeUrl>,

    /// If set, the password part of `--bitcoind-url` will be set/replaced with
    /// the content of this file.
    ///
    /// This is useful for setups that provide secret material via ramdisk
    /// e.g. SOPS, age, etc.
    ///
    /// Note this is not meant to handle bitcoind's cookie file.
    #[arg(long, env = FM_BITCOIND_URL_PASSWORD_FILE_ENV)]
    bitcoind_url_password_file: Option<PathBuf>,

    /// Esplora HTTP base URL, e.g. <https://mempool.space/api>
    #[arg(long, env = FM_ESPLORA_URL_ENV)]
    esplora_url: Option<SafeUrl>,

    /// Address we bind to for p2p consensus communication
    ///
    /// Should be `0.0.0.0:8173` most of the time, as p2p connectivity is public
    /// and direct, and the port should be open it in the firewall.
    #[arg(long, env = FM_BIND_P2P_ENV, default_value = "0.0.0.0:8173")]
    bind_p2p: SocketAddr,

    /// Address we bind to for the API
    ///
    /// Should be `0.0.0.0:8174` most of the time, as api connectivity is public
    /// and direct, and the port should be open it in the firewall.
    #[arg(long, env = FM_BIND_API_ENV, default_value = "0.0.0.0:8174")]
    bind_api: SocketAddr,

    /// Address we bind to for exposing the Web UI
    ///
    /// Built-in web UI is exposed as an HTTP port, and typically should
    /// have TLS terminated by Nginx/Traefik/etc. and forwarded to the locally
    /// bind port.
    #[arg(long, env = FM_BIND_UI_ENV, default_value = "127.0.0.1:8175")]
    bind_ui: SocketAddr,

    /// Our external address for communicating with our peers
    ///
    /// `fedimint://<fqdn>:8173` for TCP/TLS p2p connectivity (legacy/standard).
    ///
    /// Ignored when Iroh stack is used. (newer/experimental)
    #[arg(long, env = FM_P2P_URL_ENV)]
    p2p_url: Option<SafeUrl>,

    /// Our API address for clients to connect to us
    ///
    /// Typically `wss://<fqdn>/ws/` for TCP/TLS connectivity (legacy/standard)
    ///
    /// Ignored when Iroh stack is used. (newer/experimental)
    #[arg(long, env = FM_API_URL_ENV)]
    api_url: Option<SafeUrl>,

    #[arg(long, env = FM_ENABLE_IROH_ENV)]
    enable_iroh: bool,

    /// Optional URL of the Iroh DNS server
    #[arg(long, env = FM_IROH_DNS_ENV, requires = "enable_iroh")]
    iroh_dns: Option<SafeUrl>,

    /// Optional URLs of the Iroh relays to use for registering
    #[arg(long, env = FM_IROH_RELAY_ENV, requires = "enable_iroh")]
    iroh_relays: Vec<SafeUrl>,

    /// Number of checkpoints from the current session to retain on disk
    #[arg(long, env = FM_DB_CHECKPOINT_RETENTION_ENV, default_value = "1")]
    db_checkpoint_retention: u64,

    /// Enable tokio console logging
    #[arg(long, env = FM_BIND_TOKIO_CONSOLE_ENV)]
    bind_tokio_console: Option<SocketAddr>,

    /// Enable jaeger for tokio console logging
    #[arg(long, default_value = "false")]
    with_jaeger: bool,

    /// Enable prometheus metrics
    #[arg(long, env = FM_BIND_METRICS_ENV, default_value = "127.0.0.1:8176")]
    bind_metrics: Option<SocketAddr>,

    /// Comma separated list of API secrets.
    ///
    /// Setting it will enforce API authentication and make the Federation
    /// "private".
    ///
    /// The first secret in the list is the "active" one that the peer will use
    /// itself to connect to other peers. Any further one is accepted by
    /// this peer, e.g. for the purposes of smooth rotation of secret
    /// between users.
    ///
    /// Note that the value provided here will override any other settings
    /// that the user might want to set via UI at runtime, etc.
    /// In the future, managing secrets might be possible via Admin UI
    /// and defaults will be provided via `FM_DEFAULT_API_SECRETS`.
    #[arg(long, env = FM_FORCE_API_SECRETS_ENV, default_value = "")]
    force_api_secrets: ApiSecrets,

    /// Maximum number of concurrent Iroh API connections
    #[arg(long = "iroh-api-max-connections", env = FM_IROH_API_MAX_CONNECTIONS_ENV, default_value = "1000")]
    iroh_api_max_connections: usize,

    /// Maximum number of parallel requests per Iroh API connection
    #[arg(long = "iroh-api-max-requests-per-connection", env = FM_IROH_API_MAX_REQUESTS_PER_CONNECTION_ENV, default_value = "50")]
    iroh_api_max_requests_per_connection: usize,
}

impl ServerOpts {
    pub async fn get_bitcoind_url_and_password(&self) -> anyhow::Result<(SafeUrl, String)> {
        let url = self
            .bitcoind_url
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No bitcoind url set"))?;
        if let Some(password_file) = self.bitcoind_url_password_file.as_ref() {
            let password = tokio::fs::read_to_string(password_file)
                .await
                .context("Failed to read the password")?
                .trim()
                .to_owned();
            Ok((url, password))
        } else {
            let password = self
                .bitcoind_password
                .clone()
                .expect("FM_BITCOIND_URL is set but FM_BITCOIND_PASSWORD is not");
            Ok((url, password))
        }
    }
}

/// Block the thread and run a Fedimintd server
///
/// # Arguments
///
/// * `module_init_registry` - The registry of available modules.
///
/// * `code_version_hash` - The git hash of the code that the `fedimintd` binary
///   is being built from. This is used mostly for information purposes
///   (`fedimintd version-hash`). See `fedimint-build` crate for easy way to
///   obtain it.
///
/// * `code_version_vendor_suffix` - An optional suffix that will be appended to
///   the internal fedimint release version, to distinguish binaries built by
///   different vendors, usually with a different set of modules. Currently DKG
///   will enforce that the combined `code_version` is the same between all
///   peers.
#[allow(clippy::too_many_lines)]
pub async fn run(
    module_init_registry: ServerModuleInitRegistry,
    code_version_hash: &str,
    code_version_vendor_suffix: Option<&str>,
) -> anyhow::Result<Infallible> {
    assert_eq!(
        env!("FEDIMINT_BUILD_CODE_VERSION").len(),
        code_version_hash.len(),
        "version_hash must have an expected length"
    );

    handle_version_hash_command(code_version_hash);

    let fedimint_version = env!("CARGO_PKG_VERSION");

    APP_START_TS
        .with_label_values(&[fedimint_version, code_version_hash])
        .set(fedimint_core::time::duration_since_epoch().as_secs() as i64);

    let server_opts = ServerOpts::parse();

    let mut tracing_builder = TracingSetup::default();

    tracing_builder
        .tokio_console_bind(server_opts.bind_tokio_console)
        .with_jaeger(server_opts.with_jaeger);

    tracing_builder.init().unwrap();

    info!("Starting fedimintd (version: {fedimint_version} version_hash: {code_version_hash})");

    let code_version_str = code_version_vendor_suffix.map_or_else(
        || fedimint_version.to_string(),
        |suffix| format!("{fedimint_version}+{suffix}"),
    );

    let timing_total_runtime = timing::TimeReporter::new("total-runtime").info();

    let root_task_group = TaskGroup::new();

    if let Some(bind_metrics) = server_opts.bind_metrics.as_ref() {
        info!(
            target: LOG_SERVER,
            url = %format!("http://{}/metrics", bind_metrics),
            "Initializing metrics server",
        );
        fedimint_metrics::spawn_api_server(*bind_metrics, root_task_group.clone()).await?;
    }

    let settings = ConfigGenSettings {
        p2p_bind: server_opts.bind_p2p,
        api_bind: server_opts.bind_api,
        ui_bind: server_opts.bind_ui,
        p2p_url: server_opts.p2p_url.clone(),
        api_url: server_opts.api_url.clone(),
        enable_iroh: server_opts.enable_iroh,
        iroh_dns: server_opts.iroh_dns.clone(),
        iroh_relays: server_opts.iroh_relays.clone(),
        network: server_opts.bitcoin_network,
        available_modules: module_init_registry.kinds(),
    };

    let db = Database::new(
        RocksDb::build(server_opts.data_dir.join(DB_FILE))
            .open()
            .await
            .unwrap(),
        ModuleRegistry::default(),
    );

    let dyn_server_bitcoin_rpc = match (
        server_opts.bitcoind_url.as_ref(),
        server_opts.esplora_url.as_ref(),
    ) {
        (Some(_), None) => {
            let bitcoind_username = server_opts
                .bitcoind_username
                .clone()
                .expect("FM_BITCOIND_URL is set but FM_BITCOIND_USERNAME is not");
            let (bitcoind_url, bitcoind_password) = server_opts
                .get_bitcoind_url_and_password()
                .await
                .expect("Failed to get bitcoind url");
            BitcoindClient::new(bitcoind_username, bitcoind_password, &bitcoind_url)
                .unwrap()
                .into_dyn()
        }
        (None, Some(url)) => EsploraClient::new(url).unwrap().into_dyn(),
        (Some(_), Some(esplora_url)) => {
            let bitcoind_username = server_opts
                .bitcoind_username
                .clone()
                .expect("FM_BITCOIND_URL is set but FM_BITCOIND_USERNAME is not");
            let (bitcoind_url, bitcoind_password) = server_opts
                .get_bitcoind_url_and_password()
                .await
                .expect("Failed to get bitcoind url");
            BitcoindClientWithFallback::new(
                bitcoind_username,
                bitcoind_password,
                &bitcoind_url,
                esplora_url,
            )
            .unwrap()
            .into_dyn()
        }
        _ => unreachable!("ArgGroup already enforced XOR relation"),
    };

    root_task_group.install_kill_handler();

    install_crypto_provider().await;

    let task_group = root_task_group.clone();
    root_task_group.spawn_cancellable("main", async move {
        fedimint_server::run(
            server_opts.data_dir,
            server_opts.force_api_secrets,
            settings,
            db,
            code_version_str,
            module_init_registry,
            task_group,
            dyn_server_bitcoin_rpc,
            Box::new(fedimint_server_ui::setup::router),
            Box::new(fedimint_server_ui::dashboard::router),
            server_opts.db_checkpoint_retention,
            fedimint_server::ConnectionLimits::new(
                server_opts.iroh_api_max_connections,
                server_opts.iroh_api_max_requests_per_connection,
            ),
        )
        .await
        .unwrap_or_else(|err| panic!("Main task returned error: {}", err.fmt_compact_anyhow()));
    });

    let shutdown_future = root_task_group
        .make_handle()
        .make_shutdown_rx()
        .then(|()| async {
            info!(target: LOG_CORE, "Shutdown called");
        });

    shutdown_future.await;

    debug!(target: LOG_CORE, "Terminating main task");

    if let Err(err) = root_task_group.join_all(Some(SHUTDOWN_TIMEOUT)).await {
        error!(target: LOG_CORE, err = %err.fmt_compact_anyhow(), "Error while shutting down task group");
    }

    debug!(target: LOG_CORE, "Shutdown complete");

    fedimint_logging::shutdown();

    drop(timing_total_runtime);

    std::process::exit(-1);
}

pub fn default_modules() -> ServerModuleInitRegistry {
    let mut server_gens = ServerModuleInitRegistry::new();

    server_gens.attach(MintInit);
    server_gens.attach(WalletInit);

    if is_env_var_set_opt(FM_ENABLE_MODULE_LNV1_ENV).unwrap_or(true) {
        server_gens.attach(LightningInit);
    }

    if is_env_var_set_opt(FM_ENABLE_MODULE_LNV2_ENV).unwrap_or(true) {
        server_gens.attach(fedimint_lnv2_server::LightningInit);
    }

    server_gens.attach(fedimint_walletv2_server::WalletInit);

    if !is_env_var_set(FM_DISABLE_META_MODULE_ENV) {
        server_gens.attach(MetaInit);
    }

    if is_env_var_set(FM_USE_UNKNOWN_MODULE_ENV) {
        server_gens.attach(UnknownInit);
    }

    server_gens
}
