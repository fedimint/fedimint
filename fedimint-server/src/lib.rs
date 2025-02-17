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
mod db;

use std::fs;
use std::path::{Path, PathBuf};

use config::io::{read_server_config, PLAINTEXT_PASSWORD};
use config::ServerConfig;
use fedimint_aead::random_salt;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::write_new;
use fedimint_logging::{LOG_CONSENSUS, LOG_CORE};
pub use fedimint_server_core as core;
use fedimint_server_core::ServerModuleInitRegistry;
use net::api::ApiSecrets;
use tracing::{info, warn};

use crate::config::api::ConfigGenApi;
use crate::config::io::{write_server_config, SALT_FILE};
use crate::config::ConfigGenSettings;
use crate::db::{ServerInfo, ServerInfoKey};
use crate::metrics::initialize_gauge_metrics;
use crate::net::api::announcement::start_api_announcement_service;
use crate::net::api::RpcHandlerCtx;

pub mod envs;
pub mod metrics;

/// The actual implementation of consensus
pub mod consensus;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Fedimint toplevel config
pub mod config;

pub async fn run(
    data_dir: PathBuf,
    force_api_secrets: ApiSecrets,
    settings: ConfigGenSettings,
    db: Database,
    code_version_str: String,
    module_init_registry: &ServerModuleInitRegistry,
    task_group: TaskGroup,
) -> anyhow::Result<()> {
    let cfg = match get_config(&data_dir)? {
        Some(cfg) => cfg,
        None => {
            run_config_gen(
                data_dir.clone(),
                settings.clone(),
                db.clone(),
                code_version_str.clone(),
                force_api_secrets.clone(),
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

    start_api_announcement_service(&db, &task_group, &cfg, force_api_secrets.get_active()).await;

    consensus::run(
        settings.p2p_bind,
        settings.api_bind,
        cfg,
        db,
        module_init_registry.clone(),
        &task_group,
        force_api_secrets,
        data_dir,
        code_version_str,
    )
    .await?;

    info!(target: LOG_CONSENSUS, "Shutting down tasks");

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
    code_version_str: String,
    force_api_secrets: ApiSecrets,
) -> anyhow::Result<ServerConfig> {
    info!(target: LOG_CONSENSUS, "Starting config gen");

    initialize_gauge_metrics(&db).await;

    let (cfg_sender, mut cfg_receiver) = tokio::sync::mpsc::channel(1);

    let config_gen = ConfigGenApi::new(settings.clone(), db.clone(), cfg_sender);

    let mut rpc_module = RpcHandlerCtx::new_module(config_gen);

    net::api::attach_endpoints(&mut rpc_module, config::api::server_endpoints(), None);

    let api_handler = net::api::spawn(
        "config-gen",
        settings.api_bind,
        rpc_module,
        10,
        force_api_secrets.clone(),
    )
    .await;

    let cfg = cfg_receiver.recv().await.expect("should not close");

    api_handler
        .stop()
        .expect("Config api should still be running");

    api_handler.stopped().await;

    let cfg = ServerConfig::distributed_gen(
        settings.p2p_bind,
        &cfg,
        settings.registry.clone(),
        code_version_str.clone(),
    )
    .await?;

    // TODO: Make writing password optional
    write_new(data_dir.join(PLAINTEXT_PASSWORD), &cfg.private.api_auth.0)?;
    write_new(data_dir.join(SALT_FILE), random_salt())?;
    write_server_config(
        &cfg,
        &data_dir,
        &cfg.private.api_auth.0,
        &settings.registry,
        force_api_secrets.get_active(),
    )?;

    Ok(cfg)
}
