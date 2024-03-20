mod metrics;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::format_err;
use clap::Parser;
use fedimint_core::admin_client::ConfigGenParamsRequest;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::config::{
    ModuleInitParams, ServerModuleConfigGenParamsRegistry, ServerModuleInitRegistry,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::db::Database;
use fedimint_core::envs::{is_env_var_set, FM_USE_UNKNOWN_MODULE_ENV};
use fedimint_core::module::ServerModuleInit;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::timing;
use fedimint_core::util::{handle_version_hash_command, write_overwrite, SafeUrl};
use fedimint_ln_common::config::{
    LightningGenParams, LightningGenParamsConsensus, LightningGenParamsLocal,
};
use fedimint_ln_server::LightningInit;
use fedimint_logging::TracingSetup;
use fedimint_meta_server::{MetaGenParams, MetaInit};
use fedimint_mint_server::common::config::{MintGenParams, MintGenParamsConsensus};
use fedimint_mint_server::MintInit;
use fedimint_server::config::api::ConfigGenSettings;
use fedimint_server::config::io::{DB_FILE, PLAINTEXT_PASSWORD};
use fedimint_server::FedimintServer;
use fedimint_unknown_common::config::UnknownGenParams;
use fedimint_unknown_server::UnknownInit;
use fedimint_wallet_server::common::config::{
    WalletGenParams, WalletGenParamsConsensus, WalletGenParamsLocal,
};
use fedimint_wallet_server::WalletInit;
use futures::FutureExt;
use tokio::select;
use tracing::{debug, error, info, warn};

use crate::default_esplora_server;
use crate::envs::FM_DISABLE_META_MODULE_ENV;
use crate::fedimintd::metrics::APP_START_TS;

/// Time we will wait before forcefully shutting down tasks
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

pub const FM_EXTRA_DKG_META_VAR: &str = "FM_EXTRA_DKG_META";

#[derive(Parser)]
#[command(version)]
pub struct ServerOpts {
    /// Path to folder containing federation config files
    #[arg(long = "data-dir", env = "FM_DATA_DIR")]
    pub data_dir: PathBuf,
    /// Password to encrypt sensitive config files
    // TODO: should probably never send password to the server directly, rather send the hash via
    // the API
    #[arg(long, env = "FM_PASSWORD")]
    pub password: Option<String>,
    /// Enable tokio console logging
    #[arg(long, env = "FM_TOKIO_CONSOLE_BIND")]
    pub tokio_console_bind: Option<SocketAddr>,
    /// Enable telemetry logging
    #[arg(long, default_value = "false")]
    pub with_telemetry: bool,

    /// Address we bind to for federation communication
    #[arg(long, env = "FM_BIND_P2P", default_value = "127.0.0.1:8173")]
    bind_p2p: SocketAddr,
    /// Our external address for communicating with our peers
    #[arg(long, env = "FM_P2P_URL", default_value = "fedimint://127.0.0.1:8173")]
    p2p_url: SafeUrl,
    /// Address we bind to for exposing the API
    #[arg(long, env = "FM_BIND_API", default_value = "127.0.0.1:8174")]
    bind_api: SocketAddr,
    /// Our API address for clients to connect to us
    #[arg(long, env = "FM_API_URL", default_value = "ws://127.0.0.1:8174")]
    api_url: SafeUrl,
    /// The bitcoin network that fedimint will be running on
    #[arg(long, env = "FM_BITCOIN_NETWORK", default_value = "regtest")]
    network: bitcoin::network::constants::Network,
    /// The bitcoin network that fedimint will be running on
    #[arg(long, env = "FM_FINALITY_DELAY", default_value = "10")]
    finality_delay: u32,

    #[arg(long, env = "FM_BIND_METRICS_API")]
    bind_metrics_api: Option<SocketAddr>,

    /// List of default meta values to use during config generation (format:
    /// `key1=value1,key2=value,...`)
    #[arg(long, env = FM_EXTRA_DKG_META_VAR, value_parser = parse_map, default_value="")]
    extra_dkg_meta: BTreeMap<String, String>,
}

fn parse_map(s: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();

    if s.is_empty() {
        return Ok(map);
    }

    for pair in s.split(',') {
        let parts: Vec<&str> = pair.split('=').collect();
        if parts.len() == 2 {
            map.insert(parts[0].to_string(), parts[1].to_string());
        } else {
            return Err(format_err!("Invalid pair in map: {}", pair));
        }
    }
    Ok(map)
}

/// `fedimintd` builder
///
/// Fedimint supports third party modules. Right now (and for forseable feature)
/// modules needs to be combined with rest of the code at the compilation time.
///
/// To make this easier, [`Fedimintd`] builder is exposed, allowing
/// building `fedimintd` with custom set of modules.
///
///
/// Example:
///
/// ```
/// use fedimint_ln_server::LightningInit;
/// use fedimint_mint_server::MintInit;
/// use fedimint_wallet_server::WalletInit;
/// use fedimintd::Fedimintd;
///
/// // Note: not called `main` to avoid rustdoc executing it
/// // #[tokio::main]
/// async fn main_() -> anyhow::Result<()> {
///     Fedimintd::new(env!("FEDIMINT_BUILD_CODE_VERSION"))?
///         // use `.with_default_modules()` to avoid having
///         // to import these manually
///         .with_module_kind(WalletInit)
///         .with_module_kind(MintInit)
///         .with_module_kind(LightningInit)
///         .run()
///         .await
/// }
/// ```
pub struct Fedimintd {
    server_gens: ServerModuleInitRegistry,
    server_gen_params: ServerModuleConfigGenParamsRegistry,
    version_hash: String,
    opts: ServerOpts,
    bitcoind_rpc: BitcoinRpcConfig,
}

impl Fedimintd {
    /// Start a new custom `fedimintd`
    ///
    /// Like [`Self::new`] but with an ability to customize version strings.
    pub fn new(version_hash: &str) -> anyhow::Result<Fedimintd> {
        assert_eq!(
            env!("FEDIMINT_BUILD_CODE_VERSION").len(),
            version_hash.len(),
            "version_hash must have an expected length"
        );

        handle_version_hash_command(version_hash);

        let version = env!("CARGO_PKG_VERSION");
        info!("Starting fedimintd (version: {version} version_hash: {version_hash})");

        APP_START_TS
            .with_label_values(&[version, version_hash])
            .set(fedimint_core::time::duration_since_epoch().as_secs() as i64);

        let opts: ServerOpts = ServerOpts::parse();
        TracingSetup::default()
            .tokio_console_bind(opts.tokio_console_bind)
            .with_jaeger(opts.with_telemetry)
            .init()
            .unwrap();

        let bitcoind_rpc = BitcoinRpcConfig::from_env_vars()?;

        Ok(Self {
            opts,
            bitcoind_rpc,
            server_gens: ServerModuleInitRegistry::new(),
            server_gen_params: ServerModuleConfigGenParamsRegistry::default(),
            version_hash: version_hash.to_owned(),
        })
    }

    /// Attach a server module kind to the Fedimintd instance
    ///
    /// This makes `fedimintd` support additional module types (aka. kinds)
    pub fn with_module_kind<T>(mut self, gen: T) -> Self
    where
        T: ServerModuleInit + 'static + Send + Sync,
    {
        self.server_gens.attach(gen);
        self
    }

    /// Get the version hash this `fedimintd` will report for diagnostic
    /// purposes
    pub fn version_hash(&self) -> &str {
        &self.version_hash
    }

    /// Attach additional module instance with parameters
    ///
    /// Note: The `kind` needs to be added with [`Self::with_module_kind`] if
    /// it's not the default one.
    pub fn with_module_instance<P>(mut self, kind: ModuleKind, params: P) -> Self
    where
        P: ModuleInitParams,
    {
        self.server_gen_params
            .attach_config_gen_params(kind, params);
        self
    }

    /// Attach default server modules to Fedimintd instance
    pub fn with_default_modules(self) -> Self {
        let network = self.opts.network;

        let bitcoind_rpc = self.bitcoind_rpc.clone();
        let finality_delay = self.opts.finality_delay;
        let s = self
            .with_module_kind(LightningInit)
            .with_module_instance(
                LightningInit::kind(),
                LightningGenParams {
                    local: LightningGenParamsLocal {
                        bitcoin_rpc: bitcoind_rpc.clone(),
                    },
                    consensus: LightningGenParamsConsensus { network },
                },
            )
            .with_module_kind(MintInit)
            .with_module_instance(
                MintInit::kind(),
                MintGenParams {
                    local: Default::default(),
                    consensus: MintGenParamsConsensus::new(
                        2,
                        fedimint_mint_server::common::config::FeeConsensus::default(),
                    ),
                },
            )
            .with_module_kind(WalletInit)
            .with_module_instance(
                WalletInit::kind(),
                WalletGenParams {
                    local: WalletGenParamsLocal {
                        bitcoin_rpc: bitcoind_rpc.clone(),
                    },
                    consensus: WalletGenParamsConsensus {
                        network,
                        // TODO this is not very elegant, but I'm planning to get rid of it in a
                        // next commit anyway
                        finality_delay,
                        client_default_bitcoin_rpc: default_esplora_server(network),
                    },
                },
            );

        let s = if !is_env_var_set(FM_DISABLE_META_MODULE_ENV) {
            s.with_module_kind(MetaInit)
                .with_module_instance(MetaInit::kind(), MetaGenParams::default())
        } else {
            s
        };

        if is_env_var_set(FM_USE_UNKNOWN_MODULE_ENV) {
            s.with_module_kind(UnknownInit)
                .with_module_instance(UnknownInit::kind(), UnknownGenParams::default())
        } else {
            s
        }
    }

    /// Block thread and run a Fedimintd server
    pub async fn run(self) -> ! {
        let root_task_group = TaskGroup::new();
        root_task_group.install_kill_handler();

        let timing_total_runtime = timing::TimeReporter::new("total-runtime").info();

        // DO NOT REMOVE, or spawn_local tasks won't run anymore
        let local_task_set = tokio::task::LocalSet::new();
        let _guard = local_task_set.enter();

        let task_group = root_task_group.clone();
        root_task_group
            .spawn_local("main", move |_task_handle| async move {
                match run(
                    self.opts,
                    task_group.clone(),
                    self.server_gens,
                    self.server_gen_params,
                    self.version_hash,
                )
                .await
                {
                    Ok(()) => {}
                    Err(error) => {
                        error!(?error, "Main task returned error, shutting down");
                        task_group.shutdown();
                    }
                }
            })
            .await;

        let shutdown_future =
            root_task_group
                .make_handle()
                .make_shutdown_rx()
                .await
                .then(|_| async {
                    let shutdown_seconds = SHUTDOWN_TIMEOUT.as_secs();
                    info!("Shutdown called, waiting {shutdown_seconds}s for main task to finish");
                    sleep(SHUTDOWN_TIMEOUT).await;
                });

        select! {
            _ = shutdown_future => {
                debug!("Terminating main task");
            }
            _ = local_task_set => {
                warn!("local_task_set finished before shutdown was called");
            }
        }

        if let Err(err) = root_task_group.join_all(Some(SHUTDOWN_TIMEOUT)).await {
            error!(?err, "Error while shutting down task group");
        }

        info!("Shutdown complete");

        #[cfg(feature = "telemetry")]
        opentelemetry::global::shutdown_tracer_provider();

        drop(timing_total_runtime);

        // Should we ever shut down without an error code?
        std::process::exit(-1);
    }
}

async fn run(
    opts: ServerOpts,
    task_group: TaskGroup,
    module_inits: ServerModuleInitRegistry,
    module_inits_params: ServerModuleConfigGenParamsRegistry,
    version_hash: String,
) -> anyhow::Result<()> {
    let module_kinds = module_inits_params
        .iter_modules()
        .map(|(id, kind, _)| (id, kind));
    let decoders = module_inits.available_decoders(module_kinds.into_iter())?;
    let db = Database::new(
        fedimint_rocksdb::RocksDb::open(opts.data_dir.join(DB_FILE))?,
        decoders.clone(),
    );

    // TODO: Fedimintd should use the config gen API
    // on each run we want to pass the currently passed password, so we need to
    // overwrite
    if let Some(password) = opts.password {
        write_overwrite(opts.data_dir.join(PLAINTEXT_PASSWORD), password)?;
    };
    let default_params = ConfigGenParamsRequest {
        meta: opts.extra_dkg_meta.clone(),
        modules: module_inits_params,
    };
    let mut api = FedimintServer {
        data_dir: opts.data_dir,
        settings: ConfigGenSettings {
            download_token_limit: None,
            p2p_bind: opts.bind_p2p,
            api_bind: opts.bind_api,
            p2p_url: opts.p2p_url,
            api_url: opts.api_url,
            default_params,
            max_connections: fedimint_server::config::max_connections(),
            registry: module_inits,
        },
        db,
        version_hash,
    };
    if let Some(bind_metrics_api) = opts.bind_metrics_api.as_ref() {
        let (api_result, metrics_api_result) = futures::join!(
            api.run(task_group.clone()),
            spawn_metrics_server(bind_metrics_api, task_group)
        );
        api_result?;
        metrics_api_result?;
    } else {
        api.run(task_group).await?;
    }
    Ok(())
}

async fn spawn_metrics_server(
    bind_address: &SocketAddr,
    mut task_group: TaskGroup,
) -> anyhow::Result<()> {
    let rx = fedimint_metrics::run_api_server(bind_address, &mut task_group).await?;
    info!("Metrics API listening on {bind_address}");
    rx.await;
    Ok(())
}
