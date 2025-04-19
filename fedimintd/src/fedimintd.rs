mod metrics;

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use bitcoin::Network;
use clap::{ArgGroup, Parser};
use fedimint_core::config::{
    EmptyGenParams, ModuleInitParams, ServerModuleConfigGenParamsRegistry,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::db::Database;
use fedimint_core::envs::{
    BitcoinRpcConfig, FM_ENABLE_MODULE_LNV2_ENV, FM_USE_UNKNOWN_MODULE_ENV, is_env_var_set,
};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl, handle_version_hash_command};
use fedimint_core::{crit, timing};
use fedimint_ln_common::config::{
    LightningGenParams, LightningGenParamsConsensus, LightningGenParamsLocal,
};
use fedimint_ln_server::LightningInit;
use fedimint_logging::{LOG_CORE, LOG_SERVER, TracingSetup};
use fedimint_meta_server::{MetaGenParams, MetaInit};
use fedimint_mint_server::MintInit;
use fedimint_mint_server::common::config::{MintGenParams, MintGenParamsConsensus};
use fedimint_server::config::io::DB_FILE;
use fedimint_server::config::{ConfigGenSettings, NetworkingStack};
use fedimint_server::core::{ServerModuleInit, ServerModuleInitRegistry};
use fedimint_server::envs::FM_FORCE_IROH_ENV;
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
use futures::FutureExt;
use tracing::{debug, error, info};

use crate::default_esplora_server;
use crate::envs::{
    FM_API_URL_ENV, FM_BIND_API_ENV, FM_BIND_METRICS_API_ENV, FM_BIND_P2P_ENV, FM_BIND_UI_ENV,
    FM_BITCOIN_NETWORK_ENV, FM_BITCOIND_URL_ENV, FM_DATA_DIR_ENV, FM_DISABLE_META_MODULE_ENV,
    FM_ESPLORA_URL_ENV, FM_FORCE_API_SECRETS_ENV, FM_P2P_URL_ENV, FM_TOKIO_CONSOLE_BIND_ENV,
};
use crate::fedimintd::metrics::APP_START_TS;

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

    /// Enable tokio console logging
    #[arg(long, env = FM_TOKIO_CONSOLE_BIND_ENV)]
    tokio_console_bind: Option<SocketAddr>,
    /// Enable telemetry logging
    #[arg(long, default_value = "false")]
    with_telemetry: bool,

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

    #[arg(long, env = FM_BIND_METRICS_API_ENV)]
    bind_metrics_api: Option<SocketAddr>,

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

/// `fedimintd` builder
///
/// Fedimint supports third party modules. Right now (and for forseable feature)
/// modules needs to be combined with the rest of the code at compilation time.
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
}

impl Fedimintd {
    /// Builds a new `fedimintd`
    ///
    /// # Arguments
    ///
    /// * `code_version_hash` - The git hash of the code that the `fedimintd`
    ///   binary is being built from. This is used mostly for information
    ///   purposes (`fedimintd version-hash`). See `fedimint-build` crate for
    ///   easy way to obtain it.
    ///
    /// * `code_version_vendor_suffix` - An optional suffix that will be
    ///   appended to the internal fedimint release version, to distinguish
    ///   binaries built by different vendors, usually with a different set of
    ///   modules. Currently DKG will enforce that the combined `code_version`
    ///   is the same between all peers.
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

        let opts = ServerOpts::parse();

        let mut tracing_builder = TracingSetup::default();

        #[cfg(feature = "telemetry")]
        {
            tracing_builder
                .tokio_console_bind(opts.tokio_console_bind)
                .with_jaeger(opts.with_telemetry);
        }

        tracing_builder.init().unwrap();

        info!("Starting fedimintd (version: {fedimint_version} version_hash: {code_version_hash})");

        Ok(Self {
            opts,
            server_gens: ServerModuleInitRegistry::new(),
            server_gen_params: ServerModuleConfigGenParamsRegistry::default(),
            code_version_hash: code_version_hash.to_owned(),
            code_version_str: code_version_vendor_suffix.map_or_else(
                || fedimint_version.to_string(),
                |suffix| format!("{fedimint_version}+{suffix}"),
            ),
        })
    }

    /// Attach a server module kind to the Fedimintd instance
    ///
    /// This makes `fedimintd` support additional module types (aka. kinds)
    pub fn with_module_kind<T>(mut self, r#gen: T) -> Self
    where
        T: ServerModuleInit + 'static + Send + Sync,
    {
        self.server_gens.attach(r#gen);
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
    pub fn with_default_modules(self) -> anyhow::Result<Self> {
        let network = self.opts.bitcoin_network;

        let bitcoin_rpc_config = match (
            self.opts.bitcoind_url.as_ref(),
            self.opts.esplora_url.as_ref(),
        ) {
            (Some(url), None) => BitcoinRpcConfig {
                kind: "bitcoind".to_string(),
                url: url.clone(),
            },
            (None, Some(url)) => BitcoinRpcConfig {
                kind: "esplora".to_string(),
                url: url.clone(),
            },
            _ => unreachable!("ArgGroup already enforced XOR relation"),
        };

        let s = self
            .with_module_kind(LightningInit)
            .with_module_instance(
                LightningInit::kind(),
                LightningGenParams {
                    local: LightningGenParamsLocal {
                        bitcoin_rpc: bitcoin_rpc_config.clone(),
                    },
                    consensus: LightningGenParamsConsensus { network },
                },
            )
            .with_module_kind(MintInit)
            .with_module_instance(
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
            )
            .with_module_kind(WalletInit)
            .with_module_instance(
                WalletInit::kind(),
                WalletGenParams {
                    local: WalletGenParamsLocal {
                        bitcoin_rpc: bitcoin_rpc_config.clone(),
                    },
                    consensus: WalletGenParamsConsensus {
                        network,
                        finality_delay: 10,
                        client_default_bitcoin_rpc: default_esplora_server(network),
                        fee_consensus:
                            fedimint_wallet_server::common::config::FeeConsensus::default(),
                    },
                },
            );

        let enable_lnv2 = std::env::var_os(FM_ENABLE_MODULE_LNV2_ENV).is_none()
            || is_env_var_set(FM_ENABLE_MODULE_LNV2_ENV);

        let s = if enable_lnv2 {
            s.with_module_kind(fedimint_lnv2_server::LightningInit)
                .with_module_instance(
                    fedimint_lnv2_server::LightningInit::kind(),
                    fedimint_lnv2_common::config::LightningGenParams {
                        local: fedimint_lnv2_common::config::LightningGenParamsLocal {
                            bitcoin_rpc: bitcoin_rpc_config.clone(),
                        },
                        consensus: fedimint_lnv2_common::config::LightningGenParamsConsensus {
                            // TODO: actually make the relative fee configurable
                            fee_consensus: fedimint_lnv2_common::config::FeeConsensus::new(100)?,
                            network,
                        },
                    },
                )
        } else {
            s
        };

        let s = if is_env_var_set(FM_DISABLE_META_MODULE_ENV) {
            s
        } else {
            s.with_module_kind(MetaInit)
                .with_module_instance(MetaInit::kind(), MetaGenParams::default())
        };

        let s = if is_env_var_set(FM_USE_UNKNOWN_MODULE_ENV) {
            s.with_module_kind(UnknownInit)
                .with_module_instance(UnknownInit::kind(), UnknownGenParams::default())
        } else {
            s
        };

        Ok(s)
    }

    /// Block thread and run a Fedimintd server
    pub async fn run(self) -> ! {
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
                    crit!(target: LOG_SERVER, err = %error.fmt_compact_anyhow(), "Main task returned error, shutting down");
                    task_group.shutdown();
                }
            }
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
            error!(target: LOG_CORE, ?err, "Error while shutting down task group");
        }

        debug!(target: LOG_CORE, "Shutdown complete");

        fedimint_logging::shutdown();

        drop(timing_total_runtime);

        // Should we ever shut down without an error code?
        std::process::exit(-1);
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
        task_group.spawn_cancellable(
            "metrics-server",
            fedimint_metrics::run_api_server(*socket_addr, task_group.clone()),
        );
    }

    // TODO: meh, move, refactor
    let settings = ConfigGenSettings {
        p2p_bind: opts.bind_p2p,
        api_bind: opts.bind_api,
        ui_bind: opts.bind_ui,
        p2p_url: opts.p2p_url,
        api_url: opts.api_url,
        modules: module_inits_params.clone(),
        registry: module_inits.clone(),
        networking: if is_env_var_set(FM_FORCE_IROH_ENV) {
            NetworkingStack::Iroh
        } else {
            NetworkingStack::default()
        },
    };

    let db = Database::new(
        fedimint_rocksdb::RocksDb::open(opts.data_dir.join(DB_FILE)).await?,
        ModuleRegistry::default(),
    );

    let dyn_server_bitcoin_rpc = match (opts.bitcoind_url.as_ref(), opts.esplora_url.as_ref()) {
        (Some(url), None) => BitcoindClient::new(url)?.into_dyn(),
        (None, Some(url)) => EsploraClient::new(url)?.into_dyn(),
        _ => unreachable!("ArgGroup already enforced XOR relation"),
    };

    Box::pin(fedimint_server::run(
        opts.data_dir,
        opts.force_api_secrets,
        settings,
        db,
        code_version_str,
        &module_inits,
        task_group.clone(),
        dyn_server_bitcoin_rpc,
        Some(Box::new(fedimint_server_ui::dashboard::start)),
        Some(Box::new(fedimint_server_ui::setup::start)),
    ))
    .await
}
