#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::ref_option)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::trivially_copy_pass_by_ref)]

//! Server side fedimint module traits

extern crate fedimint_core;
pub mod db;

use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use anyhow::Context;
use config::ServerConfig;
use config::io::{PLAINTEXT_PASSWORD, read_server_config};
use fedimint_aead::random_salt;
use fedimint_core::config::P2PMessage;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::net::peers::DynP2PConnections;
use fedimint_core::task::{TaskGroup, TaskHandle};
use fedimint_core::util::write_new;
use fedimint_logging::{LOG_CONSENSUS, LOG_CORE};
pub use fedimint_server_core as core;
use fedimint_server_core::ServerModuleInitRegistry;
use fedimint_server_core::bitcoin_rpc::DynServerBitcoinRpc;
use fedimint_server_core::dashboard_ui::DynDashboardApi;
use fedimint_server_core::setup_ui::{DynSetupApi, ISetupApi};
use jsonrpsee::RpcModule;
use net::api::ApiSecrets;
use net::p2p::P2PStatusReceivers;
use net::p2p_connector::IrohConnector;
use tracing::{info, warn};

use crate::config::ConfigGenSettings;
use crate::config::io::{SALT_FILE, write_server_config};
use crate::config::setup::SetupApi;
use crate::db::{ServerInfo, ServerInfoKey};
use crate::fedimint_core::net::peers::IP2PConnections;
use crate::metrics::initialize_gauge_metrics;
use crate::net::api::announcement::start_api_announcement_service;
use crate::net::p2p::{ReconnectP2PConnections, p2p_status_channels};
use crate::net::p2p_connector::{IP2PConnector, TlsTcpConnector};

pub mod envs;
pub mod metrics;

/// The actual implementation of consensus
pub mod consensus;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Fedimint toplevel config
pub mod config;

/// A function/closure type for handling dashboard UI
pub type DashboardUiHandler = Box<
    dyn Fn(DynDashboardApi, SocketAddr, TaskHandle) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync
        + 'static,
>;

/// A function/closure type for handling setup UI
pub type SetupUiHandler = Box<
    dyn Fn(DynSetupApi, SocketAddr, TaskHandle) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync
        + 'static,
>;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    data_dir: PathBuf,
    force_api_secrets: ApiSecrets,
    settings: ConfigGenSettings,
    db: Database,
    code_version_str: String,
    module_init_registry: &ServerModuleInitRegistry,
    task_group: TaskGroup,
    bitcoin_rpc: DynServerBitcoinRpc,
    dashboard_ui_handler: Option<DashboardUiHandler>,
    setup_ui_handler: Option<SetupUiHandler>,
) -> anyhow::Result<()> {
    let (cfg, connections, p2p_status_receivers) = match get_config(&data_dir)? {
        Some(cfg) => {
            let connector = if cfg.consensus.iroh_endpoints.is_empty() {
                TlsTcpConnector::new(
                    cfg.tls_config(),
                    settings.p2p_bind,
                    cfg.local.p2p_endpoints.clone(),
                    cfg.local.identity,
                )
                .await
                .into_dyn()
            } else {
                IrohConnector::new(
                    cfg.private.iroh_p2p_sk.clone().unwrap(),
                    settings.p2p_bind,
                    cfg.consensus
                        .iroh_endpoints
                        .iter()
                        .map(|(peer, endpoints)| (*peer, endpoints.p2p_pk))
                        .collect(),
                )
                .await?
                .into_dyn()
            };

            let (p2p_status_senders, p2p_status_receivers) = p2p_status_channels(connector.peers());

            let connections = ReconnectP2PConnections::new(
                cfg.local.identity,
                connector,
                &task_group,
                p2p_status_senders,
            )
            .into_dyn();

            (cfg, connections, p2p_status_receivers)
        }
        None => {
            Box::pin(run_config_gen(
                data_dir.clone(),
                settings.clone(),
                db.clone(),
                &task_group,
                code_version_str.clone(),
                force_api_secrets.clone(),
                setup_ui_handler,
            ))
            .await?
        }
    };

    let decoders = module_init_registry.decoders_strict(
        cfg.consensus
            .modules
            .iter()
            .map(|(id, config)| (*id, &config.kind)),
    )?;

    let db = db.with_decoders(decoders);

    initialize_gauge_metrics(&task_group, &db).await;

    start_api_announcement_service(&db, &task_group, &cfg, force_api_secrets.get_active()).await?;

    info!(target: LOG_CONSENSUS, "Starting consensus...");

    Box::pin(consensus::run(
        connections,
        p2p_status_receivers,
        settings.api_bind,
        cfg,
        db,
        module_init_registry.clone(),
        &task_group,
        force_api_secrets,
        data_dir,
        code_version_str,
        bitcoin_rpc,
        settings.ui_bind,
        dashboard_ui_handler,
    ))
    .await?;

    info!(target: LOG_CONSENSUS, "Shutting down tasks...");

    task_group.shutdown();

    Ok(())
}

async fn update_server_info_version_dbtx(
    dbtx: &mut DatabaseTransaction<'_>,
    code_version_str: &str,
) {
    let mut server_info = dbtx.get_value(&ServerInfoKey).await.unwrap_or(ServerInfo {
        init_version: code_version_str.to_string(),
        last_version: code_version_str.to_string(),
    });
    server_info.last_version = code_version_str.to_string();
    dbtx.insert_entry(&ServerInfoKey, &server_info).await;
}

pub fn get_config(data_dir: &Path) -> anyhow::Result<Option<ServerConfig>> {
    // Attempt get the config with local password, otherwise start config gen
    let path = data_dir.join(PLAINTEXT_PASSWORD);
    if let Ok(password_untrimmed) = fs::read_to_string(&path) {
        // We definitely don't want leading/trailing newlines, and user
        // editing the file manually will probably get a free newline added
        // by the text editor.
        let password = password_untrimmed.trim_matches('\n');
        // In the future we also don't want to support any leading/trailing newlines
        let password_fully_trimmed = password.trim();
        if password_fully_trimmed != password {
            warn!(
                target: LOG_CORE,
                path = %path.display(),
                "Password in the password file contains leading/trailing whitespaces. This will an error in the future."
            );
        }
        return Ok(Some(read_server_config(password, data_dir)?));
    }

    Ok(None)
}

pub async fn run_config_gen(
    data_dir: PathBuf,
    settings: ConfigGenSettings,
    db: Database,
    task_group: &TaskGroup,
    code_version_str: String,
    api_secrets: ApiSecrets,
    setup_ui_handler: Option<SetupUiHandler>,
) -> anyhow::Result<(
    ServerConfig,
    DynP2PConnections<P2PMessage>,
    P2PStatusReceivers,
)> {
    info!(target: LOG_CONSENSUS, "Starting config gen");

    initialize_gauge_metrics(task_group, &db).await;

    let (cgp_sender, mut cgp_receiver) = tokio::sync::mpsc::channel(1);

    let config_gen = SetupApi::new(settings.clone(), db.clone(), cgp_sender);

    let mut rpc_module = RpcModule::new(config_gen.clone());

    net::api::attach_endpoints(&mut rpc_module, config::setup::server_endpoints(), None);

    let api_handler = net::api::spawn(
        "setup",
        // config gen always uses ws api
        settings.api_bind,
        rpc_module,
        10,
        api_secrets.clone(),
    )
    .await;

    let ui_task_group = TaskGroup::new();

    if let Some(setup_ui_handler) = setup_ui_handler {
        ui_task_group.spawn("web-ui", move |handle| {
            setup_ui_handler(config_gen.clone().into_dyn(), settings.ui_bind, handle)
        });

        info!(target: LOG_CONSENSUS, "Setup UI running at http://{} 🚀", settings.ui_bind);
    }

    let cg_params = cgp_receiver
        .recv()
        .await
        .expect("Config gen params receiver closed unexpectedly");

    api_handler
        .stop()
        .expect("Config api should still be running");

    api_handler.stopped().await;

    ui_task_group
        .shutdown_join_all(None)
        .await
        .context("Failed to shutdown UI server after config gen")?;

    let connector = if cg_params.iroh_endpoints().is_empty() {
        TlsTcpConnector::new(
            cg_params.tls_config(),
            settings.p2p_bind,
            cg_params.p2p_urls(),
            cg_params.identity,
        )
        .await
        .into_dyn()
    } else {
        IrohConnector::new(
            cg_params.iroh_p2p_sk.clone().unwrap(),
            settings.p2p_bind,
            cg_params
                .iroh_endpoints()
                .iter()
                .map(|(peer, endpoints)| (*peer, endpoints.p2p_pk))
                .collect(),
        )
        .await?
        .into_dyn()
    };

    let (p2p_status_senders, p2p_status_receivers) = p2p_status_channels(connector.peers());

    let connections = ReconnectP2PConnections::new(
        cg_params.identity,
        connector,
        task_group,
        p2p_status_senders,
    )
    .into_dyn();

    let cfg = ServerConfig::distributed_gen(
        settings.modules,
        &cg_params,
        settings.registry.clone(),
        code_version_str.clone(),
        connections.clone(),
        p2p_status_receivers.clone(),
    )
    .await?;

    assert_ne!(
        cfg.consensus.iroh_endpoints.is_empty(),
        cfg.consensus.api_endpoints.is_empty(),
    );

    // TODO: Make writing password optional
    write_new(data_dir.join(PLAINTEXT_PASSWORD), &cfg.private.api_auth.0)?;
    write_new(data_dir.join(SALT_FILE), random_salt())?;
    write_server_config(
        &cfg,
        &data_dir,
        &cfg.private.api_auth.0,
        &settings.registry,
        api_secrets.get_active(),
    )?;

    Ok((cfg, connections, p2p_status_receivers))
}
