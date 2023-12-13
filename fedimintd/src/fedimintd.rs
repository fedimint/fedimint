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
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::Database;
use fedimint_core::module::ServerModuleInit;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::timing;
use fedimint_core::util::{write_overwrite, SafeUrl};
use fedimint_ln_server::LightningInit;
use fedimint_logging::TracingSetup;
use fedimint_mint_server::MintInit;
use fedimint_server::config::api::ConfigGenSettings;
use fedimint_server::config::io::{DB_FILE, PLAINTEXT_PASSWORD, PRIVATE_EXT};
use fedimint_server::FedimintServer;
use fedimint_wallet_server::WalletInit;
use futures::FutureExt;
use tokio::select;
use tracing::{debug, error, info, warn};

use crate::attach_default_module_init_params;

/// Time we will wait before forcefully shutting down tasks
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

pub const FM_EXTRA_DKG_META_VAR: &str = "FM_EXTRA_DKG_META";

#[derive(Parser)]
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
/// use fedimintd::fedimintd::Fedimintd;
///
/// // Note: not called `main` to avoid rustdoc executing it
/// // #[tokio::main]
/// async fn main_() -> anyhow::Result<()> {
///     Fedimintd::new(env!("FEDIMINT_BUILD_CODE_VERSION"))?
///         // use `.with_default_modules()` to avoid having
///         // to import these manually
///         .with_module(WalletInit)
///         .with_module(MintInit)
///         .with_module(LightningInit)
///         .run()
///         .await
/// }
/// ```
pub struct Fedimintd {
    pub server_gens: ServerModuleInitRegistry,
    pub server_gen_params: ServerModuleConfigGenParamsRegistry,
    pub version_hash: String,
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

        let mut args = std::env::args();
        if let Some(ref arg) = args.nth(1) {
            if arg.as_str() == "version-hash" {
                println!("{}", version_hash);
                std::process::exit(0);
            }
        }

        info!("Starting fedimintd (version_hash: {})", version_hash);

        Ok(Self {
            server_gens: ServerModuleInitRegistry::new(),
            server_gen_params: ServerModuleConfigGenParamsRegistry::default(),
            version_hash: version_hash.to_owned(),
        })
    }

    pub fn with_module<T>(mut self, gen: T) -> Self
    where
        T: ServerModuleInit + 'static + Send + Sync,
    {
        self.server_gens.attach(gen);
        self
    }

    pub fn with_extra_module_inits_params<P>(
        mut self,
        id: ModuleInstanceId,
        kind: ModuleKind,
        params: P,
    ) -> Self
    where
        P: ModuleInitParams,
    {
        self.server_gen_params
            .attach_config_gen_params(id, kind, params);
        self
    }

    pub fn with_default_modules(self) -> Self {
        self.with_module(LightningInit)
            .with_module(MintInit)
            .with_module(WalletInit)
    }

    pub async fn run(self) -> ! {
        let opts: ServerOpts = ServerOpts::parse();
        TracingSetup::default()
            .tokio_console_bind(opts.tokio_console_bind)
            .with_jaeger(opts.with_telemetry)
            .init()
            .unwrap();

        let mut root_task_group = TaskGroup::new();
        root_task_group.install_kill_handler();

        let timing_total_runtime = timing::TimeReporter::new("total-runtime").info();

        // DO NOT REMOVE, or spawn_local tasks won't run anymore
        let local_task_set = tokio::task::LocalSet::new();
        let _guard = local_task_set.enter();

        let task_group = root_task_group.clone();
        root_task_group
            .spawn_local("main", move |_task_handle| async move {
                match run(
                    opts,
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
    mut module_inits_params: ServerModuleConfigGenParamsRegistry,
    version_hash: String,
) -> anyhow::Result<()> {
    attach_default_module_init_params(
        BitcoinRpcConfig::from_env_vars()?,
        &mut module_inits_params,
        opts.network,
        opts.finality_delay,
    );

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
        let password_path = opts
            .data_dir
            .join(PLAINTEXT_PASSWORD)
            .with_extension(PRIVATE_EXT);
        write_overwrite(password_path, password)?;
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
