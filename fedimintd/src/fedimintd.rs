mod metrics;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{format_err, Context};
use clap::{Parser, Subcommand};
use fedimint_core::admin_client::ConfigGenParamsRequest;
use fedimint_core::config::{
    ModuleInitParams, ServerModuleConfigGenParamsRegistry, ServerModuleInitRegistry,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::db::Database;
use fedimint_core::envs::{is_env_var_set, BitcoinRpcConfig, FM_USE_UNKNOWN_MODULE_ENV};
use fedimint_core::module::{ServerApiVersionsSummary, ServerDbVersionsSummary, ServerModuleInit};
use fedimint_core::task::TaskGroup;
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
use fedimint_server::config::ServerConfig;
use fedimint_server::net::api::ApiSecrets;
use fedimint_unknown_common::config::UnknownGenParams;
use fedimint_unknown_server::UnknownInit;
use fedimint_wallet_server::common::config::{
    WalletGenParams, WalletGenParamsConsensus, WalletGenParamsLocal,
};
use fedimint_wallet_server::WalletInit;
use futures::FutureExt;
use tracing::{debug, error, info};

use crate::default_esplora_server;
use crate::envs::{
    FM_API_URL_ENV, FM_BIND_API_ENV, FM_BIND_METRICS_API_ENV, FM_BIND_P2P_ENV,
    FM_BITCOIN_NETWORK_ENV, FM_DATA_DIR_ENV, FM_DISABLE_META_MODULE_ENV, FM_EXTRA_DKG_META_ENV,
    FM_FINALITY_DELAY_ENV, FM_FORCE_API_SECRETS_ENV, FM_P2P_URL_ENV, FM_PASSWORD_ENV,
    FM_TOKIO_CONSOLE_BIND_ENV,
};
use crate::fedimintd::metrics::APP_START_TS;

/// Time we will wait before forcefully shutting down tasks
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(version)]
pub struct ServerOpts {
    /// Path to folder containing federation config files
    #[arg(long = "data-dir", env = FM_DATA_DIR_ENV)]
    pub data_dir: Option<PathBuf>,
    /// Password to encrypt sensitive config files
    // TODO: should probably never send password to the server directly, rather send the hash via
    // the API
    #[arg(long, env = FM_PASSWORD_ENV)]
    pub password: Option<String>,
    /// Enable tokio console logging
    #[arg(long, env = FM_TOKIO_CONSOLE_BIND_ENV)]
    pub tokio_console_bind: Option<SocketAddr>,
    /// Enable telemetry logging
    #[arg(long, default_value = "false")]
    pub with_telemetry: bool,

    /// Address we bind to for federation communication
    #[arg(long, env = FM_BIND_P2P_ENV, default_value = "127.0.0.1:8173")]
    bind_p2p: SocketAddr,
    /// Our external address for communicating with our peers
    #[arg(long, env = FM_P2P_URL_ENV, default_value = "fedimint://127.0.0.1:8173")]
    p2p_url: SafeUrl,
    /// Address we bind to for exposing the API
    #[arg(long, env = FM_BIND_API_ENV, default_value = "127.0.0.1:8174")]
    bind_api: SocketAddr,
    /// Our API address for clients to connect to us
    #[arg(long, env = FM_API_URL_ENV, default_value = "ws://127.0.0.1:8174")]
    api_url: SafeUrl,
    /// The bitcoin network that fedimint will be running on
    #[arg(long, env = FM_BITCOIN_NETWORK_ENV, default_value = "regtest")]
    network: bitcoin::network::constants::Network,
    /// The number of blocks the federation stays behind the blockchain tip
    #[arg(long, env = FM_FINALITY_DELAY_ENV, default_value = "10")]
    finality_delay: u32,

    #[arg(long, env = FM_BIND_METRICS_API_ENV)]
    bind_metrics_api: Option<SocketAddr>,

    /// List of default meta values to use during config generation (format:
    /// `key1=value1,key2=value,...`)
    #[arg(long, env = FM_EXTRA_DKG_META_ENV, value_parser = parse_map, default_value="")]
    extra_dkg_meta: BTreeMap<String, String>,

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

    #[clap(subcommand)]
    subcommand: Option<ServerSubcommand>,
}

#[derive(Subcommand)]
enum ServerSubcommand {
    /// Development-related commands
    #[clap(subcommand)]
    Dev(DevSubcommand),
}

#[derive(Subcommand)]
enum DevSubcommand {
    /// List supported server API versions and exit
    ListApiVersions,
    /// List supported server database versions and exit
    ListDbVersions,
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
///     Fedimintd::new(env!("FEDIMINT_BUILD_CODE_VERSION"), Some("vendor-xyz-1"))?
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
    code_version_hash: String,
    code_version_str: String,
    opts: ServerOpts,
    bitcoind_rpc: BitcoinRpcConfig,
}

impl Fedimintd {
    /// Build a new `fedimintd`
    ///
    /// `code_version_hash` should be the git hash of the code, the
    /// `fedimintd` binary is bing built from. This is used mostly for
    /// information purposes (`fedimintd version-hash`). See
    /// `fedimint-build` crate for easy way to obtain it.
    ///
    /// `code_version_vendor_suffix` is an optional suffix that will be appended
    /// to the internal fedimint release version, to distinguish binaries
    /// built by different vendors, usually  with a different set of modules.
    /// Currently DKG will enforce that the combined `code_version` is the same
    /// between all peers.
    pub fn new(
        code_version_hash: &str,
        code_version_vendor_suffix: Option<&str>,
    ) -> anyhow::Result<Fedimintd> {
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

        let opts: ServerOpts = ServerOpts::parse();

        TracingSetup::default()
            .tokio_console_bind(opts.tokio_console_bind)
            .with_jaeger(opts.with_telemetry)
            .init()
            .unwrap();

        info!("Starting fedimintd (version: {fedimint_version} version_hash: {code_version_hash})");

        let bitcoind_rpc = BitcoinRpcConfig::get_defaults_from_env_vars()?;

        Ok(Self {
            opts,
            bitcoind_rpc,
            server_gens: ServerModuleInitRegistry::new(),
            server_gen_params: ServerModuleConfigGenParamsRegistry::default(),
            code_version_hash: code_version_hash.to_owned(),
            code_version_str: code_version_vendor_suffix.map_or_else(
                || fedimint_version.to_string(),
                |suffix| format!("{fedimint_version}.{suffix}"),
            ),
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
        &self.code_version_hash
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
                        fee_consensus: Default::default(),
                    },
                },
            );

        let s = if is_env_var_set(FM_DISABLE_META_MODULE_ENV) {
            s
        } else {
            s.with_module_kind(MetaInit)
                .with_module_instance(MetaInit::kind(), MetaGenParams::default())
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
        // handle optional subcommand
        if let Some(subcommand) = &self.opts.subcommand {
            match subcommand {
                ServerSubcommand::Dev(DevSubcommand::ListApiVersions) => {
                    let api_versions = self.get_server_api_versions();
                    let api_versions = serde_json::to_string_pretty(&api_versions)
                        .expect("API versions struct is serializable");
                    println!("{api_versions}");
                    std::process::exit(0);
                }
                ServerSubcommand::Dev(DevSubcommand::ListDbVersions) => {
                    let db_versions = self.get_server_db_versions();
                    let db_versions = serde_json::to_string_pretty(&db_versions)
                        .expect("API versions struct is serializable");
                    println!("{db_versions}");
                    std::process::exit(0);
                }
            }
        }

        let root_task_group = TaskGroup::new();
        root_task_group.install_kill_handler();

        let timing_total_runtime = timing::TimeReporter::new("total-runtime").info();

        let task_group = root_task_group.clone();
        root_task_group.spawn_cancellable("main", async move {
            match run(
                self.opts,
                &task_group,
                self.server_gens,
                self.server_gen_params,
                self.code_version_str,
            )
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    error!(?error, "Main task returned error, shutting down");
                    task_group.shutdown();
                }
            }
        });

        let shutdown_future = root_task_group
            .make_handle()
            .make_shutdown_rx()
            .then(|()| async {
                info!("Shutdown called");
            });

        shutdown_future.await;
        debug!("Terminating main task");

        if let Err(err) = root_task_group.join_all(Some(SHUTDOWN_TIMEOUT)).await {
            error!(?err, "Error while shutting down task group");
        }

        info!("Shutdown complete");

        fedimint_logging::shutdown();

        drop(timing_total_runtime);

        // Should we ever shut down without an error code?
        std::process::exit(-1);
    }

    fn get_server_api_versions(&self) -> ServerApiVersionsSummary {
        ServerApiVersionsSummary {
            core: ServerConfig::supported_api_versions().api,
            modules: self
                .server_gens
                .kinds()
                .into_iter()
                .map(|module_kind| {
                    self.server_gens
                        .get(&module_kind)
                        .expect("module is present")
                })
                .map(|module_init| {
                    (
                        module_init.module_kind(),
                        module_init.supported_api_versions().api,
                    )
                })
                .collect(),
        }
    }

    fn get_server_db_versions(&self) -> ServerDbVersionsSummary {
        ServerDbVersionsSummary {
            modules: self
                .server_gens
                .kinds()
                .into_iter()
                .map(|module_kind| {
                    self.server_gens
                        .get(&module_kind)
                        .expect("module is present")
                })
                .map(|module_init| (module_init.module_kind(), module_init.database_version()))
                .collect(),
        }
    }
}

async fn run(
    opts: ServerOpts,
    task_group: &TaskGroup,
    module_inits: ServerModuleInitRegistry,
    module_inits_params: ServerModuleConfigGenParamsRegistry,
    code_version_str: String,
) -> anyhow::Result<()> {
    if let Some(socket_addr) = opts.bind_metrics_api.as_ref() {
        task_group.spawn_cancellable("metrics-server", {
            let task_group = task_group.clone();
            let socket_addr = *socket_addr;
            async move { fedimint_metrics::run_api_server(socket_addr, task_group).await }
        });
    }

    let data_dir = opts.data_dir.context("data-dir option is not present")?;

    // TODO: Fedimintd should use the config gen API
    // on each run we want to pass the currently passed password, so we need to
    // overwrite
    if let Some(password) = opts.password {
        write_overwrite(data_dir.join(PLAINTEXT_PASSWORD), password)?;
    };
    let default_params = ConfigGenParamsRequest {
        meta: opts.extra_dkg_meta.clone(),
        modules: module_inits_params.clone(),
    };
    // TODO: meh, move, refactor
    let settings = ConfigGenSettings {
        download_token_limit: None,
        p2p_bind: opts.bind_p2p,
        api_bind: opts.bind_api,
        p2p_url: opts.p2p_url,
        api_url: opts.api_url,
        default_params,
        max_connections: fedimint_server::config::max_connections(),
        registry: module_inits.clone(),
    };

    let db = Database::new(
        fedimint_rocksdb::RocksDb::open(data_dir.join(DB_FILE))?,
        Default::default(),
    );

    fedimint_server::run(
        data_dir,
        opts.force_api_secrets,
        settings,
        db,
        code_version_str,
        &module_inits,
        task_group.clone(),
    )
    .await?;

    Ok(())
}
