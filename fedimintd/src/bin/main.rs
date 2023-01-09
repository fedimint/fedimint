use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use fedimint_api::db::Database;
use fedimint_api::module::ModuleInit;
use fedimint_api::task::TaskGroup;
use fedimint_ln::LightningModuleConfigGen;
use fedimint_mint::MintConfigGenerator;
use fedimint_server::config::ModuleInitRegistry;
use fedimint_server::consensus::FedimintConsensus;
use fedimint_server::FedimintServer;
use fedimint_wallet::WalletConfigGenerator;
use fedimintd::encrypt::*;
use fedimintd::ui::run_ui;
use fedimintd::ui::UiMessage;
use fedimintd::*;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

use crate::{JSON_EXT, LOCAL_CONFIG};

#[derive(Parser)]
pub struct ServerOpts {
    /// Path to folder containing federation config files
    pub cfg_path: PathBuf,
    /// Password to encrypt sensitive config files
    #[arg(env = "FM_PASSWORD")]
    pub password: Option<String>,
    /// Port to run admin UI on
    #[arg(long = "ui-bind", default_value = None)]
    pub ui_bind: Option<SocketAddr>,
    #[cfg(feature = "telemetry")]
    #[clap(long)]
    pub with_telemetry: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args();
    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", CODE_VERSION);
            return Ok(());
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

    let mut task_group = TaskGroup::new();
    let (ui_sender, mut ui_receiver) = tokio::sync::mpsc::channel(1);

    // Run admin UI if a socket address was given for it
    if let Some(ui_bind) = opts.ui_bind {
        // Make sure password is set
        let password = match opts.password.clone() {
            Some(password) => password,
            None => {
                eprintln!("fedimintd admin UI requires FM_PASSWORD environment variable to be set");
                std::process::exit(1);
            }
        };

        // Spawn admin UI
        let cfg_path = opts.cfg_path.clone();
        let ui_task_group = task_group.make_subgroup().await;
        task_group
            .spawn("admin-ui", move |_| async move {
                run_ui(cfg_path, ui_sender, ui_bind, password, ui_task_group).await;
            })
            .await;

        // If federation configs (e.g. local.json) missing, wait for admin UI to report DKG completion
        let local_cfg_path = opts.cfg_path.join(LOCAL_CONFIG).with_extension(JSON_EXT);
        if !std::path::Path::new(&local_cfg_path).exists() {
            loop {
                if let UiMessage::DKGSuccess = ui_receiver
                    .recv()
                    .await
                    .expect("failed to receive setup message")
                {
                    break;
                }
            }
        }
    }

    let salt_path = opts.cfg_path.join(SALT_FILE);
    let key = get_key(opts.password, salt_path);
    let cfg = read_server_configs(&key, opts.cfg_path.clone());

    let db: Database = fedimint_rocksdb::RocksDb::open(opts.cfg_path.join(DB_FILE))
        .expect("Error opening DB")
        .into();

    let local_task_set = tokio::task::LocalSet::new();
    let _guard = local_task_set.enter();

    task_group.install_kill_handler();

    let module_inits = ModuleInitRegistry::from([
        (
            "wallet",
            Arc::new(WalletConfigGenerator) as Arc<dyn ModuleInit + Send + Sync>,
        ),
        ("mint", Arc::new(MintConfigGenerator)),
        ("ln", Arc::new(LightningModuleConfigGen)),
    ]);

    let decoders = module_inits.decoders();

    let consensus = FedimintConsensus::new(cfg.clone(), db, module_inits, &mut task_group).await?;

    FedimintServer::run(cfg, consensus, decoders, &mut task_group).await?;

    local_task_set.await;
    task_group.join_all().await?;

    #[cfg(feature = "telemetry")]
    opentelemetry::global::shutdown_tracer_provider();

    Ok(())
}
