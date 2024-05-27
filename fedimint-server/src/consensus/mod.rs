#![allow(clippy::let_unit_value)]

pub mod aleph_bft;
pub mod api;
pub mod db;
pub mod debug_fmt;
pub mod engine;
pub mod transaction;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use async_channel::Sender;
use db::{get_global_database_migrations, GLOBAL_DATABASE_VERSION};
use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::config::ServerModuleInitRegistry;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{apply_migrations, apply_migrations_server, Database};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::NumPeers;
use fedimint_logging::{LOG_CONSENSUS, LOG_CORE};
use jsonrpsee::server::ServerHandle;
use tokio::sync::watch;
use tracing::info;
use tracing::log::warn;

use crate::config::{ServerConfig, ServerConfigLocal};
use crate::consensus::aleph_bft::keychain::Keychain;
use crate::consensus::api::ConsensusApi;
use crate::consensus::engine::ConsensusEngine;
use crate::net;
use crate::net::api::{ApiSecrets, RpcHandlerCtx};

/// How many txs can be stored in memory before blocking the API
const TRANSACTION_BUFFER: usize = 1000;

pub async fn run(
    cfg: ServerConfig,
    db: Database,
    module_init_registry: ServerModuleInitRegistry,
    task_group: &TaskGroup,
    force_api_secrets: ApiSecrets,
) -> anyhow::Result<()> {
    cfg.validate_config(&cfg.local.identity, &module_init_registry)?;

    apply_migrations_server(
        &db,
        "fedimint-server".to_string(),
        GLOBAL_DATABASE_VERSION,
        get_global_database_migrations(),
    )
    .await?;

    let mut modules = BTreeMap::new();

    for (module_id, module_cfg) in &cfg.consensus.modules {
        match module_init_registry.get(&module_cfg.kind) {
            Some(module_init) => {
                info!(target: LOG_CORE, "Initialise module {module_id}");

                apply_migrations(
                    &db,
                    module_init.module_kind().to_string(),
                    module_init.database_version(),
                    module_init.get_database_migrations(),
                    Some(*module_id),
                )
                .await?;

                let module = module_init
                    .init(
                        NumPeers::from(cfg.consensus.api_endpoints.len()),
                        cfg.get_module_config(*module_id)?,
                        db.with_prefix_module_id(*module_id),
                        task_group,
                        cfg.local.identity,
                    )
                    .await?;

                modules.insert(*module_id, (module_cfg.kind.clone(), module));
            }
            None => bail!("Detected configuration for unsupported module id: {module_id}"),
        };
    }

    let module_registry = ModuleRegistry::from(modules);

    let client_cfg = cfg.consensus.to_client_config(&module_init_registry)?;

    let (submission_sender, submission_receiver) = async_channel::bounded(TRANSACTION_BUFFER);
    let (shutdown_sender, shutdown_receiver) = watch::channel(None);
    let connection_status_channels = Default::default();
    let last_ci_by_peer = Default::default();

    let consensus_api = ConsensusApi {
        cfg: cfg.clone(),
        db: db.clone(),
        modules: module_registry.clone(),
        client_cfg: client_cfg.clone(),
        submission_sender: submission_sender.clone(),
        shutdown_sender,
        supported_api_versions: ServerConfig::supported_api_versions_summary(
            &cfg.consensus.modules,
            &module_init_registry,
        ),
        last_ci_by_peer: Arc::clone(&last_ci_by_peer),
        connection_status_channels: Arc::clone(&connection_status_channels),
        force_api_secret: force_api_secrets.get_active(),
    };

    info!(target: LOG_CONSENSUS, "Starting Consensus Api");

    let api_handler =
        start_consensus_api(&cfg.local, consensus_api, force_api_secrets.clone()).await;

    info!(target: LOG_CONSENSUS, "Starting Submission of Module CI proposals");

    for (module_id, kind, module) in module_registry.iter_modules() {
        submit_module_ci_proposals(
            task_group,
            db.clone(),
            module_id,
            kind.clone(),
            module.clone(),
            submission_sender.clone(),
        );
    }

    info!(target: LOG_CONSENSUS, "Starting Consensus Engine");

    ConsensusEngine {
        db,
        keychain: Keychain::new(&cfg),
        federation_api: DynGlobalApi::from_config(&client_cfg, force_api_secrets.get_active()),
        self_id_str: cfg.local.identity.to_string(),
        peer_id_str: (0..cfg.consensus.api_endpoints.len())
            .map(|x| x.to_string())
            .collect(),
        cfg: cfg.clone(),
        connection_status_channels,
        submission_receiver,
        shutdown_receiver,
        last_ci_by_peer,
        modules: module_registry,
        task_group: task_group.clone(),
    }
    .run()
    .await?;

    api_handler
        .stop()
        .expect("Consensus api should still be running");

    api_handler.stopped().await;

    Ok(())
}

async fn start_consensus_api(
    cfg: &ServerConfigLocal,
    api: ConsensusApi,
    force_api_secrets: ApiSecrets,
) -> ServerHandle {
    let mut rpc_module = RpcHandlerCtx::new_module(api.clone());

    net::api::attach_endpoints(&mut rpc_module, api::server_endpoints(), None);

    for (id, _, module) in api.modules.iter_modules() {
        net::api::attach_endpoints(&mut rpc_module, module.api_endpoints(), Some(id));
    }

    net::api::spawn(
        "consensus",
        &cfg.api_bind,
        rpc_module,
        cfg.max_connections,
        force_api_secrets,
    )
    .await
}

const CONSENSUS_PROPOSAL_TIMEOUT: Duration = Duration::from_secs(30);

fn submit_module_ci_proposals(
    task_group: &TaskGroup,
    db: Database,
    module_id: ModuleInstanceId,
    kind: ModuleKind,
    module: DynServerModule,
    submission_sender: Sender<ConsensusItem>,
) {
    let mut interval = tokio::time::interval(if is_running_in_test_env() {
        Duration::from_millis(100)
    } else {
        Duration::from_secs(1)
    });

    task_group.spawn(
        "submit_module_ci_proposals_{module_id}",
        move |task_handle| async move {
            while !task_handle.is_shutting_down() {
                let module_consensus_items = tokio::time::timeout(
                    CONSENSUS_PROPOSAL_TIMEOUT,
                    module.consensus_proposal(
                        &mut db
                            .begin_transaction_nc()
                            .await
                            .to_ref_with_prefix_module_id(module_id)
                            .into_nc(),
                        module_id,
                    ),
                )
                .await;

                match module_consensus_items {
                    Ok(items) => {
                        for item in items {
                            submission_sender
                                .send(ConsensusItem::Module(item))
                                .await
                                .ok();
                        }
                    }
                    Err(..) => {
                        warn!(
                            target: LOG_CONSENSUS,
                            "Module {module_id} of kind {kind} failed to propose consensus items on time"
                        );
                    }
                }

                interval.tick().await;
            }
        },
    );
}
