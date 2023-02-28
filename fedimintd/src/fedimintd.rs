use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use fedimint_core::config::{
    ModuleGenParams, ServerModuleGenParamsRegistry, ServerModuleGenRegistry,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::db::Database;
use fedimint_core::module::ServerModuleGen;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_ln_server::LightningGen;
use fedimint_logging::TracingSetup;
use fedimint_mint_server::MintGen;
use fedimint_server::config::io::{
    read_server_config, CODE_VERSION, DB_FILE, JSON_EXT, LOCAL_CONFIG,
};
use fedimint_server::FedimintServer;
use fedimint_wallet_server::WalletGen;
use futures::FutureExt;
use tokio::select;
use tracing::{debug, error, info, warn};

use crate::ui::{run_ui, UiMessage};

/// Time we will wait before forcefully shutting down tasks
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
pub struct ServerOpts {
    /// Path to folder containing federation config files
    pub data_dir: PathBuf,
    /// Password to encrypt sensitive config files
    // TODO: should probably never send password to the server directly, rather send the hash via
    // the API
    #[arg(env = "FM_PASSWORD")]
    pub password: String,
    /// Port to run admin UI on
    #[arg(long = "listen-ui", env = "FM_LISTEN_UI")]
    pub listen_ui: Option<SocketAddr>,
    /// After an upgrade the epoch must be passed in
    #[arg(env = "FM_UPGRADE_EPOCH")]
    pub upgrade_epoch: Option<u64>,
    /// Enable tokio console logging
    #[arg(long = "tokio-console-bind", env = "FM_TOKIO_CONSOLE_BIND")]
    pub tokio_console_bind: Option<SocketAddr>,
    /// Enable telemetry logging
    #[arg(long, default_value = "false")]
    pub with_telemetry: bool,
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
/// use fedimint_ln_server::LightningGen;
/// use fedimint_mint_server::MintGen;
/// use fedimint_wallet_server::WalletGen;
/// use fedimintd::fedimintd::Fedimintd;
///
/// // Note: not called `main` to avoid rustdoc executing it
/// // #[tokio::main]
/// async fn main_() -> anyhow::Result<()> {
///     Fedimintd::new()?
///         // use `.with_default_modules()` to avoid having
///         // to import these manually
///         .with_module(WalletGen)
///         .with_module(MintGen)
///         .with_module(LightningGen)
///         .run()
///         .await
/// }
/// ```
pub struct Fedimintd {
    module_gens: ServerModuleGenRegistry,
    module_gens_params: ServerModuleGenParamsRegistry,
    opts: ServerOpts,
}

impl Fedimintd {
    pub fn new() -> anyhow::Result<Fedimintd> {
        let mut args = std::env::args();
        if let Some(ref arg) = args.nth(1) {
            if arg.as_str() == "version-hash" {
                println!("{CODE_VERSION}");
                std::process::exit(0);
            }
        }

        info!("Starting fedimintd (version: {CODE_VERSION})");

        let opts: ServerOpts = ServerOpts::parse();
        TracingSetup::default()
            .tokio_console_bind(opts.tokio_console_bind)
            .with_jaeger(opts.with_telemetry)
            .init()?;

        Ok(Self {
            module_gens: ServerModuleGenRegistry::new(),
            module_gens_params: ServerModuleGenParamsRegistry::new(),
            opts,
        })
    }

    pub fn with_module<T>(mut self, gen: T) -> Self
    where
        T: ServerModuleGen + 'static + Send + Sync,
    {
        self.module_gens.attach(gen);
        self
    }

    pub fn with_extra_module_gens_params<P>(mut self, kind: ModuleKind, params: P) -> Self
    where
        P: ModuleGenParams,
    {
        self.module_gens_params
            .attach_config_gen_params(kind, params);
        self
    }

    pub fn with_default_modules(self) -> Self {
        self.with_module(LightningGen)
            .with_module(MintGen)
            .with_module(WalletGen)
    }

    pub async fn run(self) -> ! {
        let mut root_task_group = TaskGroup::new();
        root_task_group.install_kill_handler();

        // DO NOT REMOVE, or spawn_local tasks won't run anymore
        let local_task_set = tokio::task::LocalSet::new();
        let _guard = local_task_set.enter();

        let task_group = root_task_group.clone();
        root_task_group
            .spawn_local("main", move |_task_handle| async move {
                match run(
                    self.opts,
                    task_group.clone(),
                    self.module_gens,
                    self.module_gens_params,
                )
                .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        error!(?e, "Main task returned error, shutting down");
                        task_group.shutdown().await;
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

        // Should we ever shut down without an error code?
        std::process::exit(-1);
    }
}

async fn run(
    opts: ServerOpts,
    mut task_group: TaskGroup,
    module_gens: ServerModuleGenRegistry,
    module_gens_params: ServerModuleGenParamsRegistry,
) -> anyhow::Result<()> {
    let (ui_sender, mut ui_receiver) = tokio::sync::mpsc::channel(1);

    info!("Starting pre-check");

    // Run admin UI if a socket address was given for it
    if let Some(listen_ui) = opts.listen_ui {
        let module_gens = module_gens.clone();
        // Spawn admin UI
        let data_dir = opts.data_dir.clone();
        let ui_task_group = task_group.make_subgroup().await;
        let password = opts.password.clone();
        task_group
            .spawn("admin-ui", move |_| async move {
                run_ui(
                    data_dir,
                    ui_sender,
                    listen_ui,
                    password,
                    ui_task_group,
                    module_gens,
                    module_gens_params,
                )
                .await;
            })
            .await;

        // If federation configs (e.g. local.json) missing, wait for admin UI to report
        // DKG completion
        let local_cfg_path = opts.data_dir.join(LOCAL_CONFIG).with_extension(JSON_EXT);
        if !std::path::Path::new(&local_cfg_path).exists() {
            loop {
                if let UiMessage::DkgSuccess = ui_receiver
                    .recv()
                    .await
                    .expect("failed to receive setup message")
                {
                    break;
                }
            }
        }
    }

    info!("Starting consensus");

    let cfg = read_server_config(&opts.password, opts.data_dir.clone())?;
    let decoders = module_gens.decoders(cfg.iter_module_instances())?;
    let db = Database::new(
        fedimint_rocksdb::RocksDb::open(opts.data_dir.join(DB_FILE))?,
        decoders.clone(),
    );

    FedimintServer::run(cfg, db, module_gens, opts.upgrade_epoch, &mut task_group).await
}
