#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::large_futures)]

pub mod envs;
mod metrics;

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use bitcoin::Network;
use clap::{ArgGroup, Parser};
use fedimint_core::config::{EmptyGenParams, ServerModuleConfigGenParamsRegistry};
use fedimint_core::db::Database;
use fedimint_core::envs::{
    BitcoinRpcConfig, FM_ENABLE_MODULE_LNV2_ENV, FM_USE_UNKNOWN_MODULE_ENV, is_env_var_set,
};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::{SafeUrl, handle_version_hash_command};
use fedimint_core::{crit, timing};
use fedimint_ln_common::config::{
    LightningGenParams, LightningGenParamsConsensus, LightningGenParamsLocal,
};
use fedimint_ln_server::LightningInit;
use fedimint_logging::{LOG_CORE, LOG_SERVER, TracingSetup};
use fedimint_meta_server::{MetaGenParams, MetaInit};
use fedimint_mint_server::MintInit;
use fedimint_mint_server::common::config::{MintGenParams, MintGenParamsConsensus};
use fedimint_rocksdb::RocksDb;
use fedimint_server::config::ConfigGenSettings;
use fedimint_server::config::io::DB_FILE;
use fedimint_server::core::{ServerModuleInit, ServerModuleInitRegistry};
use fedimint_server::net::api::ApiSecrets;
use fedimint_server_bitcoin_rpc::bitcoind::BitcoindClient;
use fedimint_server_bitcoin_rpc::esplora::EsploraClient;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use fedimint_unknown_common::config::UnknownGenParams;
use fedimint_unknown_server::UnknownInit;
use fedimint_wallet_server::WalletInit;
use fedimint_wallet_server::common::config::{
    WalletGenParams, WalletGenParamsConsensus, WalletGenParamsLocal,
};
use tracing::{debug, error, info};

use crate::envs::{
    FM_API_URL_ENV, FM_BIND_API_ENV, FM_BIND_METRCIS_ENV, FM_BIND_P2P_ENV,
    FM_BIND_TOKIO_CONSOLE_ENV, FM_BIND_UI_ENV, FM_BITCOIN_NETWORK_ENV, FM_BITCOIND_URL_ENV,
    FM_DATA_DIR_ENV, FM_DB_CHECKPOINT_RETENTION_ENV, FM_DISABLE_META_MODULE_ENV,
    FM_ENABLE_IROH_ENV, FM_ESPLORA_URL_ENV, FM_FORCE_API_SECRETS_ENV, FM_P2P_URL_ENV,
    FM_PORT_ESPLORA_ENV,
};
use crate::metrics::APP_START_TS;

/// Time we will wait before forcefully shutting down tasks
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(version)]
#[command(
    group(
        ArgGroup::new("bitcoin_rpc")
            .required(true)
            .multiple(false)
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

    /// Bitcoind RPC URL, e.g. <http://user:pass@127.0.0.1:8332>
    #[arg(long, env = FM_BITCOIND_URL_ENV)]
    bitcoind_url: Option<SafeUrl>,

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
    #[arg(long, env = "FM_IROH_DNS", requires = "enable_iroh")]
    iroh_dns: Option<SafeUrl>,

    /// Optional URL of the Iroh relays
    #[arg(long, env = "FM_IROH_RELAY", requires = "enable_iroh")]
    iroh_relay: Option<SafeUrl>,

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
    #[arg(long, env = FM_BIND_METRCIS_ENV)]
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
}

/// Block the thread and run a Fedimintd server
///
/// # Arguments
///
/// * `modules_fn` - A function to initialize the modules.
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
pub async fn run(
    modules_fn: fn(
        Network,
    ) -> (
        ServerModuleInitRegistry,
        ServerModuleConfigGenParamsRegistry,
    ),
    code_version_hash: &str,
    code_version_vendor_suffix: Option<&str>,
) -> ! {
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

    let (server_gens, server_gen_params) = modules_fn(server_opts.bitcoin_network);

    let timing_total_runtime = timing::TimeReporter::new("total-runtime").info();

    let root_task_group = TaskGroup::new();

    if let Some(bind_metrics) = server_opts.bind_metrics.as_ref() {
        root_task_group.spawn_cancellable(
            "metrics-server",
            fedimint_metrics::run_api_server(*bind_metrics, root_task_group.clone()),
        );
    }

    let settings = ConfigGenSettings {
        p2p_bind: server_opts.bind_p2p,
        api_bind: server_opts.bind_api,
        ui_bind: server_opts.bind_ui,
        p2p_url: server_opts.p2p_url,
        api_url: server_opts.api_url,
        enable_iroh: server_opts.enable_iroh,
        iroh_dns: server_opts.iroh_dns,
        iroh_relay: server_opts.iroh_relay,
        modules: server_gen_params.clone(),
        registry: server_gens.clone(),
    };

    let db = Database::new(
        RocksDb::open(server_opts.data_dir.join(DB_FILE))
            .await
            .unwrap(),
        ModuleRegistry::default(),
    );

    let dyn_server_bitcoin_rpc = match (
        server_opts.bitcoind_url.as_ref(),
        server_opts.esplora_url.as_ref(),
    ) {
        (Some(url), None) => BitcoindClient::new(url).unwrap().into_dyn(),
        (None, Some(url)) => EsploraClient::new(url).unwrap().into_dyn(),
        _ => unreachable!("ArgGroup already enforced XOR relation"),
    };

    root_task_group.install_kill_handler();

    fedimint_server::run(
        server_opts.data_dir,
        server_opts.force_api_secrets,
        settings,
        db,
        code_version_str,
        server_gens,
        root_task_group.clone(),
        dyn_server_bitcoin_rpc,
        Box::new(fedimint_server_ui::setup::router),
        Box::new(fedimint_server_ui::dashboard::router),
        server_opts.db_checkpoint_retention,
    )
    .await
    .inspect_err(|e| crit!(target: LOG_SERVER, ?e, "Main task returned error"))
    .ok();

    info!(target: LOG_CORE, "Awaiting shutdown of root task group");

    root_task_group
        .join_all(Some(SHUTDOWN_TIMEOUT))
        .await
        .inspect_err(|e| error!(target: LOG_CORE, ?e, "Error while shutting down task group"))
        .ok();

    debug!(target: LOG_CORE, "Shutdown complete");

    fedimint_logging::shutdown();

    drop(timing_total_runtime);

    // Should we ever shut down without an error code?
    std::process::exit(-1);
}

pub fn default_modules(
    network: Network,
) -> (
    ServerModuleInitRegistry,
    ServerModuleConfigGenParamsRegistry,
) {
    let mut server_gens = ServerModuleInitRegistry::new();
    let mut server_gen_params = ServerModuleConfigGenParamsRegistry::default();

    let bitcoin_rpc_config = BitcoinRpcConfig {
        kind: "bitcoind".to_string(),
        url: "http://unused_dummy.xyz".parse().unwrap(),
    };

    server_gens.attach(LightningInit);
    server_gen_params.attach_config_gen_params(
        LightningInit::kind(),
        LightningGenParams {
            local: LightningGenParamsLocal {
                bitcoin_rpc: bitcoin_rpc_config.clone(),
            },
            consensus: LightningGenParamsConsensus { network },
        },
    );

    server_gens.attach(MintInit);
    server_gen_params.attach_config_gen_params(
        MintInit::kind(),
        MintGenParams {
            local: EmptyGenParams::default(),
            consensus: MintGenParamsConsensus::new(
                2,
                // TODO: wait for clients to support the relative fees and set them to
                // non-zero in 0.6
                fedimint_mint_common::config::FeeConsensus::zero(),
            ),
        },
    );

    server_gens.attach(WalletInit);
    server_gen_params.attach_config_gen_params(
        WalletInit::kind(),
        WalletGenParams {
            local: WalletGenParamsLocal {
                bitcoin_rpc: bitcoin_rpc_config.clone(),
            },
            consensus: WalletGenParamsConsensus {
                network,
                finality_delay: 10,
                client_default_bitcoin_rpc: default_esplora_server(network),
                fee_consensus: fedimint_wallet_server::common::config::FeeConsensus::default(),
            },
        },
    );

    let enable_lnv2 = std::env::var_os(FM_ENABLE_MODULE_LNV2_ENV).is_none()
        || is_env_var_set(FM_ENABLE_MODULE_LNV2_ENV);

    if enable_lnv2 {
        server_gens.attach(fedimint_lnv2_server::LightningInit);
        server_gen_params.attach_config_gen_params(
            fedimint_lnv2_server::LightningInit::kind(),
            fedimint_lnv2_common::config::LightningGenParams {
                local: fedimint_lnv2_common::config::LightningGenParamsLocal {
                    bitcoin_rpc: bitcoin_rpc_config.clone(),
                },
                consensus: fedimint_lnv2_common::config::LightningGenParamsConsensus {
                    // TODO: actually make the relative fee configurable
                    fee_consensus: fedimint_lnv2_common::config::FeeConsensus::new(100).unwrap(),
                    network,
                },
            },
        );
    }

    if !is_env_var_set(FM_DISABLE_META_MODULE_ENV) {
        server_gens.attach(MetaInit);
        server_gen_params.attach_config_gen_params(MetaInit::kind(), MetaGenParams::default());
    };

    if is_env_var_set(FM_USE_UNKNOWN_MODULE_ENV) {
        server_gens.attach(UnknownInit);
        server_gen_params
            .attach_config_gen_params(UnknownInit::kind(), UnknownGenParams::default());
    }

    (server_gens, server_gen_params)
}

pub fn default_esplora_server(network: Network) -> BitcoinRpcConfig {
    BitcoinRpcConfig {
        kind: "esplora".to_string(),
        url: match network {
            Network::Bitcoin => SafeUrl::parse("https://mempool.space/api/"),
            Network::Testnet => SafeUrl::parse("https://mempool.space/testnet/api/"),
            Network::Testnet4 => SafeUrl::parse("https://mempool.space/testnet4/api/"),
            Network::Signet => SafeUrl::parse("https://mutinynet.com/api/"),
            Network::Regtest => SafeUrl::parse(&format!(
                "http://127.0.0.1:{}/",
                std::env::var(FM_PORT_ESPLORA_ENV).unwrap_or(String::from("50002"))
            )),
            _ => panic!("Failed to parse default esplora server"),
        }
        .expect("Failed to parse default esplora server"),
    }
}
