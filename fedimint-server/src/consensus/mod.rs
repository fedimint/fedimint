pub mod aleph_bft;
pub mod api;
pub mod db;
pub mod debug;
pub mod engine;
mod iroh_api;
pub mod transaction;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use async_channel::Sender;
use db::{ServerDbMigrationContext, get_global_database_migrations};
use fedimint_api_client::api::DynGlobalApi;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::NumPeers;
use fedimint_core::config::P2PMessage;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{Database, apply_migrations_dbtx, verify_module_db_integrity_dbtx};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{ApiAuth, FEDIMINT_API_ALPN};
use fedimint_core::net::iroh::build_iroh_endpoint;
use fedimint_core::net::peers::DynP2PConnections;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::SafeUrl;
use fedimint_logging::{LOG_CONSENSUS, LOG_CORE};
use fedimint_server_core::bitcoin_rpc::{DynServerBitcoinRpc, ServerBitcoinRpcMonitor};
use fedimint_server_core::dashboard_ui::IDashboardApi;
use fedimint_server_core::migration::apply_migrations_server_dbtx;
use fedimint_server_core::{DynServerModule, ServerModuleInitRegistry};
use jsonrpsee::RpcModule;
use jsonrpsee::server::ServerHandle;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::{ServerConfig, ServerConfigLocal};
use crate::connection_limits::ConnectionLimits;
use crate::consensus::api::ConsensusApi;
use crate::consensus::engine::ConsensusEngine;
use crate::consensus::iroh_api::{IrohApiState, run_iroh_api, run_iroh_api_next};
use crate::db::verify_server_db_integrity_dbtx;
use crate::net::api::ApiSecrets;
use crate::net::api::announcement::get_api_urls;
use crate::net::api::guardian_metadata::{
    prepare_guardian_metadata_service, reconcile_guardian_metadata, start_guardian_metadata_service,
};
use crate::net::iroh::{build_iroh_v1_endpoint, derive_iroh_v1_api_secret_key};
use crate::net::p2p::P2PStatusReceivers;
use crate::{DashboardUiRouter, IrohNextApiSettings, net, update_server_info_version_dbtx};

/// How many txs can be stored in memory before blocking the API
const TRANSACTION_BUFFER: usize = 1000;

struct IrohApiEndpoints {
    legacy: Option<iroh::Endpoint>,
    next: Option<iroh_next::Endpoint>,
}

fn eligible_iroh_next_api_settings(
    has_legacy_iroh_api: bool,
    iroh_next_api_settings: Option<&IrohNextApiSettings>,
) -> Option<&IrohNextApiSettings> {
    if iroh_next_api_settings.is_some() && !has_legacy_iroh_api {
        warn!(
            target: LOG_CONSENSUS,
            "Not starting the transitional Iroh 1.0 API because this federation was configured \
             without the legacy Iroh API"
        );
        None
    } else {
        iroh_next_api_settings
    }
}

fn resolve_iroh_next_api_bind(
    api_bind: SocketAddr,
    iroh_next_api_settings: Option<&IrohNextApiSettings>,
) -> anyhow::Result<Option<SocketAddr>> {
    iroh_next_api_settings
        .map(|settings| {
            settings.bind_override().map_or_else(
                || {
                    let mut bind = api_bind;
                    bind.set_port(
                        bind.port()
                            .checked_add(10)
                            .context("Default Iroh 1.0 API bind port would overflow")?,
                    );
                    anyhow::Ok(bind)
                },
                anyhow::Ok,
            )
        })
        .transpose()
}

#[cfg(test)]
#[test]
fn ineligible_iroh_next_api_does_not_validate_unused_default_bind() {
    let api_bind = "127.0.0.1:65535".parse().expect("valid socket address");
    let settings = IrohNextApiSettings::new(None);
    let settings = eligible_iroh_next_api_settings(false, Some(&settings));

    assert!(
        resolve_iroh_next_api_bind(api_bind, settings)
            .expect("ineligible listener should be skipped")
            .is_none()
    );
}

async fn prepare_iroh_api_endpoints(
    cfg: &ServerConfig,
    api_bind: SocketAddr,
    iroh_dns: Option<SafeUrl>,
    iroh_relays: Vec<SafeUrl>,
    iroh_next_api_settings: Option<&IrohNextApiSettings>,
) -> anyhow::Result<IrohApiEndpoints> {
    let legacy = if let Some(iroh_api_sk) = cfg.private.iroh_api_sk.clone() {
        Some(
            build_iroh_endpoint(
                iroh_api_sk,
                api_bind,
                iroh_dns.clone(),
                iroh_relays,
                FEDIMINT_API_ALPN,
            )
            .await?,
        )
    } else {
        None
    };

    let next_bind = resolve_iroh_next_api_bind(api_bind, iroh_next_api_settings)?;
    let next = if let Some(bind) = next_bind {
        let next_api_sk = derive_iroh_v1_api_secret_key(&cfg.private.broadcast_secret_key);
        Some(build_iroh_v1_endpoint(next_api_sk, bind, iroh_dns, FEDIMINT_API_ALPN).await?)
    } else {
        None
    };

    Ok(IrohApiEndpoints { legacy, next })
}

fn spawn_iroh_api_tasks(
    consensus_api: ConsensusApi,
    iroh_api_limits: ConnectionLimits,
    endpoints: IrohApiEndpoints,
    task_group: &TaskGroup,
) {
    let iroh_api = IrohApiState::new(consensus_api, iroh_api_limits);

    if let Some(endpoint) = endpoints.legacy {
        task_group.spawn_cancellable(
            "iroh-api",
            run_iroh_api(iroh_api.clone(), endpoint, task_group.clone()),
        );
    }

    if let Some(endpoint) = endpoints.next {
        task_group.spawn_cancellable(
            "iroh-next-api",
            run_iroh_api_next(iroh_api, endpoint, task_group.clone()),
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    connectors: ConnectorRegistry,
    auth_ui: Option<ApiAuth>,
    auth_api: Option<ApiAuth>,
    connections: DynP2PConnections<P2PMessage>,
    p2p_status_receivers: P2PStatusReceivers,
    api_bind: SocketAddr,
    iroh_dns: Option<SafeUrl>,
    iroh_relays: Vec<SafeUrl>,
    cfg: ServerConfig,
    db: Database,
    module_init_registry: ServerModuleInitRegistry,
    task_group: &TaskGroup,
    force_api_secrets: ApiSecrets,
    data_dir: PathBuf,
    code_version_str: String,
    code_version_hash: String,
    dyn_server_bitcoin_rpc: DynServerBitcoinRpc,
    ui_bind: SocketAddr,
    dashboard_ui_router: DashboardUiRouter,
    db_checkpoint_retention: u64,
    session_timeout: Duration,
    iroh_api_limits: ConnectionLimits,
    iroh_next_api_settings: Option<&IrohNextApiSettings>,
) -> anyhow::Result<()> {
    cfg.validate_config(&cfg.local.identity, &module_init_registry)?;

    let iroh_next_api_settings =
        eligible_iroh_next_api_settings(cfg.private.iroh_api_sk.is_some(), iroh_next_api_settings);

    let mut global_dbtx = db.begin_transaction().await;
    apply_migrations_server_dbtx(
        &mut global_dbtx.to_ref_nc(),
        Arc::new(ServerDbMigrationContext),
        "fedimint-server".to_string(),
        get_global_database_migrations(),
    )
    .await?;

    update_server_info_version_dbtx(&mut global_dbtx.to_ref_nc(), &code_version_str).await;

    if is_running_in_test_env() {
        verify_server_db_integrity_dbtx(&mut global_dbtx.to_ref_nc()).await;
    }
    global_dbtx.commit_tx_result().await?;

    let mut modules = BTreeMap::new();

    // TODO: make it work with all transports and federation secrets
    let global_api = DynGlobalApi::new(
        connectors.clone(),
        cfg.consensus
            .api_endpoints()
            .iter()
            .map(|(&peer_id, url)| (peer_id, url.url.clone()))
            .collect(),
        None,
    )?;

    let bitcoin_rpc_connection = ServerBitcoinRpcMonitor::new(
        dyn_server_bitcoin_rpc,
        if is_running_in_test_env() {
            Duration::from_millis(100)
        } else {
            Duration::from_mins(1)
        },
        task_group,
    );

    for (module_id, module_cfg) in &cfg.consensus.modules {
        match module_init_registry.get(&module_cfg.kind) {
            Some(module_init) => {
                info!(target: LOG_CORE, "Initialise module {module_id}...");

                let mut dbtx = db.begin_transaction().await;
                apply_migrations_dbtx(
                    &mut dbtx.to_ref_nc(),
                    Arc::new(ServerDbMigrationContext) as Arc<_>,
                    module_init.module_kind().to_string(),
                    module_init.get_database_migrations(),
                    Some(*module_id),
                    None,
                )
                .await?;

                if let Some(used_db_prefixes) = module_init.used_db_prefixes()
                    && is_running_in_test_env()
                {
                    verify_module_db_integrity_dbtx(
                        &mut dbtx.to_ref_nc(),
                        *module_id,
                        module_init.module_kind(),
                        &used_db_prefixes,
                    )
                    .await;
                }
                dbtx.commit_tx_result().await?;

                let module = module_init
                    .init(
                        NumPeers::from(cfg.consensus.api_endpoints().len()),
                        cfg.get_module_config(*module_id)?,
                        db.with_prefix_module_id(*module_id).0,
                        task_group,
                        cfg.local.identity,
                        global_api.with_module(*module_id),
                        bitcoin_rpc_connection.clone(),
                    )
                    .await?;

                modules.insert(*module_id, (module_cfg.kind.clone(), module));
            }
            None => bail!("Detected configuration for unsupported module id: {module_id}"),
        }
    }

    let module_registry = ModuleRegistry::from(modules);

    let client_cfg = cfg.consensus.to_client_config(&module_init_registry)?;

    let (submission_sender, submission_receiver) = async_channel::bounded(TRANSACTION_BUFFER);
    let (shutdown_sender, shutdown_receiver) = watch::channel(None);
    let (ord_latency_sender, ord_latency_receiver) = watch::channel(None);

    let mut ci_status_senders = BTreeMap::new();
    let mut ci_status_receivers = BTreeMap::new();

    for peer in cfg.consensus.broadcast_public_keys.keys().copied() {
        let (ci_sender, ci_receiver) = watch::channel(None);

        ci_status_senders.insert(peer, ci_sender);
        ci_status_receivers.insert(peer, ci_receiver);
    }

    let supported_api_versions =
        ServerConfig::supported_api_versions_summary(&cfg.consensus.modules, &module_registry);
    debug!(
        target: LOG_CONSENSUS,
        ?supported_api_versions,
        "Supported API versions",
    );

    let consensus_api = ConsensusApi {
        cfg: cfg.clone(),
        db: db.clone(),
        modules: module_registry.clone(),
        client_cfg: client_cfg.clone(),
        submission_sender: submission_sender.clone(),
        shutdown_sender,
        shutdown_receiver: shutdown_receiver.clone(),
        supported_api_versions,
        auth_ui,
        auth_api,
        p2p_status_receivers,
        ci_status_receivers,
        ord_latency_receiver,
        bitcoin_rpc_connection: bitcoin_rpc_connection.clone(),
        force_api_secret: force_api_secrets.get_active(),
        code_version_str,
        code_version_hash,
        task_group: task_group.clone(),
    };

    let guardian_metadata_api =
        prepare_guardian_metadata_service(&db, &cfg, force_api_secrets.get_active()).await?;

    let iroh_api_endpoints = prepare_iroh_api_endpoints(
        &cfg,
        api_bind,
        iroh_dns,
        iroh_relays,
        iroh_next_api_settings,
    )
    .await?;

    let guardian_metadata_updated =
        reconcile_guardian_metadata(&db, &cfg, iroh_next_api_settings).await?;

    info!(target: LOG_CONSENSUS, "Starting Consensus Api...");

    let api_handler = start_consensus_api(
        &cfg.local,
        consensus_api.clone(),
        force_api_secrets.clone(),
        api_bind,
    )
    .await;

    spawn_iroh_api_tasks(
        consensus_api.clone(),
        iroh_api_limits,
        iroh_api_endpoints,
        task_group,
    );

    start_guardian_metadata_service(
        &db,
        task_group,
        &cfg,
        guardian_metadata_api,
        guardian_metadata_updated,
    );

    info!(target: LOG_CONSENSUS, "Starting Submission of Module CI proposals...");

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

    let ui_service = dashboard_ui_router(consensus_api.clone().into_dyn()).into_make_service();

    let ui_listener = TcpListener::bind(ui_bind)
        .await
        .expect("Failed to bind dashboard UI");

    task_group.spawn("dashboard-ui", move |handle| async move {
        axum::serve(ui_listener, ui_service)
            .with_graceful_shutdown(handle.make_shutdown_rx())
            .await
            .expect("Failed to serve dashboard UI");
    });

    info!(target: LOG_CONSENSUS, "Dashboard UI running at http://{ui_bind} 🚀");

    loop {
        match bitcoin_rpc_connection.status() {
            Some(status) => {
                if let Some(progress) = status.sync_progress {
                    if progress >= 0.999 {
                        break;
                    }

                    info!(target: LOG_CONSENSUS, "Waiting for bitcoin backend to sync... {progress:.1}%");
                } else {
                    break;
                }
            }
            None => {
                info!(target: LOG_CONSENSUS, "Waiting to connect to bitcoin backend...");
            }
        }

        sleep(Duration::from_secs(1)).await;
    }

    info!(target: LOG_CONSENSUS, "Starting Consensus Engine...");

    let api_urls = get_api_urls(&db, &cfg.consensus).await;

    // FIXME: (@leonardo) How should this be handled ?
    // Using the `Connector::default()` for now!
    ConsensusEngine {
        db,
        federation_api: DynGlobalApi::new(
            connectors,
            api_urls,
            force_api_secrets.get_active().as_deref(),
        )?,
        cfg: cfg.clone(),
        connections,
        ord_latency_sender,
        ci_status_senders,
        submission_receiver,
        shutdown_receiver,
        modules: module_registry,
        task_group: task_group.clone(),
        data_dir,
        db_checkpoint_retention,
        session_timeout,
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
    api_bind: SocketAddr,
) -> ServerHandle {
    let mut rpc_module = RpcModule::new(api.clone());

    net::api::attach_endpoints(&mut rpc_module, api::server_endpoints(), None);

    for (id, _, module) in api.modules.iter_modules() {
        net::api::attach_endpoints(&mut rpc_module, module.api_endpoints(), Some(id));
    }

    net::api::spawn(
        "consensus",
        api_bind,
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
        format!("citem_proposals_{module_id}"),
        move |task_handle| async move {
            while !task_handle.is_shutting_down() {
                let module_consensus_items = tokio::time::timeout(
                    CONSENSUS_PROPOSAL_TIMEOUT,
                    module.consensus_proposal(
                        &mut db
                            .begin_transaction_nc()
                            .await
                            .to_ref_with_prefix_module_id(module_id)
                            .0
                            .into_nc(),
                        module_id,
                    ),
                )
                .await;

                match module_consensus_items {
                    Ok(items) => {
                        for item in items {
                            if submission_sender
                                .send(ConsensusItem::Module(item))
                                .await
                                .is_err()
                            {
                                warn!(
                                    target: LOG_CONSENSUS,
                                    module_id,
                                    "Unable to submit module consensus item proposal via channel"
                                );
                            }
                        }
                    }
                    Err(..) => {
                        warn!(
                            target: LOG_CONSENSUS,
                            module_id,
                            %kind,
                            "Module failed to propose consensus items on time"
                        );
                    }
                }

                interval.tick().await;
            }
        },
    );
}
