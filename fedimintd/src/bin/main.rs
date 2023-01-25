use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use fedimint_api::config::ModuleGenRegistry;
use fedimint_api::db::Database;
use fedimint_api::module::DynModuleGen;
use fedimint_api::task::{sleep, TaskGroup};
use fedimint_ln::LightningGen;
use fedimint_mint::MintGen;
use fedimint_server::consensus::FedimintConsensus;
use fedimint_server::FedimintServer;
use fedimint_wallet::WalletGen;
use fedimintd::encrypt::*;
use fedimintd::ui::run_ui;
use fedimintd::ui::UiMessage;
use fedimintd::*;
use futures::FutureExt;
use tokio::select;
use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

use crate::{JSON_EXT, LOCAL_CONFIG};

/// Time we will wait before forcefully shutting down tasks
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
pub struct ServerOpts {
    /// Path to folder containing federation config files
    pub data_dir: PathBuf,
    /// Password to encrypt sensitive config files
    #[arg(env = "FM_PASSWORD")]
    pub password: Option<String>,
    /// Port to run admin UI on
    #[arg(long = "listen-ui", env = "FM_LISTEN_UI")]
    pub listen_ui: Option<SocketAddr>,
    #[cfg(feature = "telemetry")]
    #[clap(long)]
    pub with_telemetry: bool,
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args();
    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", CODE_VERSION);
            return;
        }
    }

    let opts: ServerOpts = ServerOpts::parse();
    let fmt_layer = tracing_subscriber::fmt::layer();
    let filter_layer = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer);

    let telemetry_layer = || -> Option<Box<dyn Layer<_> + Send + Sync + 'static>> {
        #[cfg(feature = "telemetry")]
        if opts.with_telemetry {
            let tracer = opentelemetry_jaeger::new_pipeline()
                .with_service_name("fedimint")
                .install_simple()
                .unwrap();

            return Some(tracing_opentelemetry::layer().with_tracer(tracer).boxed());
        }
        None
    };

    if let Some(layer) = telemetry_layer() {
        registry.with(layer).init();
    } else {
        registry.init();
    }

    let mut root_task_group = TaskGroup::new();
    root_task_group.install_kill_handler();

    // DO NOT REMOVE, or spawn_local tasks won't run anymore
    let local_task_set = tokio::task::LocalSet::new();
    let _guard = local_task_set.enter();

    let task_group = root_task_group.clone();
    root_task_group
        .spawn_local("main", move |_task_handle| async move {
            match run(opts, task_group.clone()).await {
                Ok(()) => {}
                Err(e) => {
                    error!(?e, "Main task returned error, shutting down");
                    task_group.shutdown().await;
                }
            }
        })
        .await;

    let shutdown_future = root_task_group
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

async fn run(opts: ServerOpts, mut task_group: TaskGroup) -> anyhow::Result<()> {
    let (ui_sender, mut ui_receiver) = tokio::sync::mpsc::channel(1);

    let module_inits = ModuleGenRegistry::from(vec![
        DynModuleGen::from(WalletGen),
        DynModuleGen::from(MintGen),
        DynModuleGen::from(LightningGen),
    ]);

    info!("Starting pre-check");

    // Run admin UI if a socket address was given for it
    if let Some(listen_ui) = opts.listen_ui {
        // Make sure password is set
        let password = match opts.password.clone() {
            Some(password) => password,
            None => {
                eprintln!("fedimintd admin UI requires FM_PASSWORD environment variable to be set");
                std::process::exit(1);
            }
        };

        // Spawn admin UI
        let data_dir = opts.data_dir.clone();
        let ui_task_group = task_group.make_subgroup().await;
        let module_gens = module_inits.clone();
        task_group
            .spawn("admin-ui", move |_| async move {
                run_ui(
                    data_dir,
                    ui_sender,
                    listen_ui,
                    password,
                    ui_task_group,
                    module_gens,
                )
                .await;
            })
            .await;

        // If federation configs (e.g. local.json) missing, wait for admin UI to report DKG completion
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

    let salt_path = opts.data_dir.join(SALT_FILE);
    let key = get_key(opts.password, salt_path)?;
    let cfg = read_server_configs(&key, opts.data_dir.clone())?;

    let decoders = module_inits.decoders(cfg.iter_module_instances())?;

    let db = Database::new(
        fedimint_rocksdb::RocksDb::open(opts.data_dir.join(DB_FILE))?,
        decoders.clone(),
    );

    let (consensus, tx_receiver) =
        FedimintConsensus::new(cfg.clone(), db, module_inits, &mut task_group).await?;

    FedimintServer::run(cfg, consensus, tx_receiver, decoders, &mut task_group).await?;

    Ok(())
}
