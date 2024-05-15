#![allow(where_clauses_object_safety)] // https://github.com/dtolnay/async-trait/issues/228
extern crate fedimint_core;

use std::fs;
use std::path::{Path, PathBuf};

use config::io::{read_server_config, PLAINTEXT_PASSWORD};
use config::ServerConfig;
use fedimint_aead::random_salt;
use fedimint_core::config::ServerModuleInitRegistry;
use fedimint_core::db::Database;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::write_new;
use fedimint_logging::LOG_CONSENSUS;
use tracing::info;

use crate::config::api::{ConfigGenApi, ConfigGenSettings};
use crate::config::io::{write_server_config, SALT_FILE};
use crate::metrics::initialize_gauge_metrics;
use crate::net::api::RpcHandlerCtx;
use crate::net::connect::TlsTcpConnector;

pub mod envs;
pub mod metrics;

pub mod atomic_broadcast;

/// The actual implementation of consensus
pub mod consensus;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Fedimint toplevel config
pub mod config;

/// Implementation of multiplexed peer connections
pub mod multiplexed;

pub async fn run(
    data_dir: PathBuf,
    settings: ConfigGenSettings,
    db: Database,
    version_hash: String,
    module_init_registry: &ServerModuleInitRegistry,
    task_group: TaskGroup,
) -> anyhow::Result<()> {
    let cfg = match get_config(&data_dir).await? {
        Some(cfg) => cfg,
        None => {
            run_config_gen(
                data_dir,
                settings,
                db.clone(),
                version_hash,
                task_group.make_subgroup(),
            )
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

    initialize_gauge_metrics(&db).await;

    consensus::run(cfg, db, module_init_registry.clone(), &task_group).await?;

    info!(target: LOG_CONSENSUS, "Shutting down tasks");

    task_group.shutdown();

    Ok(())
}

pub async fn get_config(data_dir: &Path) -> anyhow::Result<Option<ServerConfig>> {
    // Attempt get the config with local password, otherwise start config gen
    if let Ok(password) = fs::read_to_string(data_dir.join(PLAINTEXT_PASSWORD)) {
        return Ok(Some(read_server_config(&password, data_dir.to_owned())?));
    }

    Ok(None)
}

pub async fn run_config_gen(
    data_dir: PathBuf,
    settings: ConfigGenSettings,
    db: Database,
    version_hash: String,
    mut task_group: TaskGroup,
) -> anyhow::Result<ServerConfig> {
    info!(target: LOG_CONSENSUS, "Starting config gen");

    initialize_gauge_metrics(&db).await;

    let (cfg_sender, mut cfg_receiver) = tokio::sync::mpsc::channel(1);

    let config_gen = ConfigGenApi::new(
        settings.clone(),
        db.clone(),
        cfg_sender,
        &mut task_group,
        version_hash.clone(),
    );

    let mut rpc_module = RpcHandlerCtx::new_module(config_gen);

    net::api::attach_endpoints(&mut rpc_module, config::api::server_endpoints(), None);

    let api_handler = net::api::spawn("config-gen", &settings.api_bind, rpc_module, 10).await;

    let cfg = cfg_receiver.recv().await.expect("should not close");

    api_handler
        .stop()
        .expect("Config api should still be running");

    api_handler.stopped().await;

    // TODO: Make writing password optional
    write_new(data_dir.join(PLAINTEXT_PASSWORD), &cfg.private.api_auth.0)?;
    write_new(data_dir.join(SALT_FILE), random_salt())?;
    write_server_config(
        &cfg,
        data_dir.clone(),
        &cfg.private.api_auth.0,
        &settings.registry,
    )?;

    Ok(cfg)
}
