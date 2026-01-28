pub mod aleph_bft;
pub mod api;
pub mod db;
pub mod debug;
pub mod engine;
pub mod transaction;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
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
use fedimint_core::module::{ApiEndpoint, ApiError, ApiMethod, FEDIMINT_API_ALPN, IrohApiRequest};
use fedimint_core::net::iroh::build_iroh_endpoint;
use fedimint_core::net::peers::DynP2PConnections;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl};
use fedimint_logging::{LOG_CONSENSUS, LOG_CORE, LOG_NET_API};
use fedimint_server_core::bitcoin_rpc::{DynServerBitcoinRpc, ServerBitcoinRpcMonitor};
use fedimint_server_core::dashboard_ui::IDashboardApi;
use fedimint_server_core::migration::apply_migrations_server_dbtx;
use fedimint_server_core::{DynServerModule, ServerModuleInitRegistry};
use futures::FutureExt;
use iroh::Endpoint;
use iroh::endpoint::{Incoming, RecvStream, SendStream};
use jsonrpsee::RpcModule;
use jsonrpsee::server::ServerHandle;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tracing::{info, warn};

use crate::config::{ServerConfig, ServerConfigLocal};
use crate::connection_limits::ConnectionLimits;
use crate::consensus::api::{ConsensusApi, server_endpoints};
use crate::consensus::engine::ConsensusEngine;
use crate::db::verify_server_db_integrity_dbtx;
use crate::net::api::{ApiSecrets, HasApiContext};
use crate::net::p2p::P2PStatusReceivers;
use crate::{DashboardUiRouter, net, update_server_info_version_dbtx};

/// How many txs can be stored in memory before blocking the API
const TRANSACTION_BUFFER: usize = 1000;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    connectors: ConnectorRegistry,
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
    dyn_server_bitcoin_rpc: DynServerBitcoinRpc,
    ui_bind: SocketAddr,
    dashboard_ui_router: DashboardUiRouter,
    db_checkpoint_retention: u64,
    iroh_api_limits: ConnectionLimits,
) -> anyhow::Result<()> {
    cfg.validate_config(&cfg.local.identity, &module_init_registry)?;

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
            Duration::from_secs(60)
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

    let consensus_api = ConsensusApi {
        cfg: cfg.clone(),
        cfg_dir: data_dir.clone(),
        db: db.clone(),
        modules: module_registry.clone(),
        client_cfg: client_cfg.clone(),
        submission_sender: submission_sender.clone(),
        shutdown_sender,
        shutdown_receiver: shutdown_receiver.clone(),
        supported_api_versions: ServerConfig::supported_api_versions_summary(
            &cfg.consensus.modules,
            &module_init_registry,
        ),
        p2p_status_receivers,
        ci_status_receivers,
        ord_latency_receiver,
        bitcoin_rpc_connection: bitcoin_rpc_connection.clone(),
        force_api_secret: force_api_secrets.get_active(),
        code_version_str,
        task_group: task_group.clone(),
    };

    info!(target: LOG_CONSENSUS, "Starting Consensus Api...");

    let api_handler = start_consensus_api(
        &cfg.local,
        consensus_api.clone(),
        force_api_secrets.clone(),
        api_bind,
    )
    .await;

    if let Some(iroh_api_sk) = cfg.private.iroh_api_sk.clone()
        && let Err(e) = Box::pin(start_iroh_api(
            iroh_api_sk,
            api_bind,
            iroh_dns,
            iroh_relays,
            consensus_api.clone(),
            task_group,
            iroh_api_limits,
        ))
        .await
    {
        // clean up ws api before propagating error
        api_handler.stop().expect("Just started");
        api_handler.stopped().await;
        return Err(e);
    }

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

    ConsensusEngine {
        db,
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

async fn start_iroh_api(
    secret_key: iroh::SecretKey,
    api_bind: SocketAddr,
    iroh_dns: Option<SafeUrl>,
    iroh_relays: Vec<SafeUrl>,
    consensus_api: ConsensusApi,
    task_group: &TaskGroup,
    iroh_api_limits: ConnectionLimits,
) -> anyhow::Result<()> {
    let endpoint = build_iroh_endpoint(
        secret_key,
        api_bind,
        iroh_dns,
        iroh_relays,
        FEDIMINT_API_ALPN,
    )
    .await?;
    task_group.spawn_cancellable(
        "iroh-api",
        run_iroh_api(consensus_api, endpoint, task_group.clone(), iroh_api_limits),
    );

    Ok(())
}

async fn run_iroh_api(
    consensus_api: ConsensusApi,
    endpoint: Endpoint,
    task_group: TaskGroup,
    iroh_api_limits: ConnectionLimits,
) {
    let core_api = server_endpoints()
        .into_iter()
        .map(|endpoint| (endpoint.path.to_string(), endpoint))
        .collect::<BTreeMap<String, ApiEndpoint<ConsensusApi>>>();

    let module_api = consensus_api
        .modules
        .iter_modules()
        .map(|(id, _, module)| {
            let api_endpoints = module
                .api_endpoints()
                .into_iter()
                .map(|endpoint| (endpoint.path.to_string(), endpoint))
                .collect::<BTreeMap<String, ApiEndpoint<DynServerModule>>>();

            (id, api_endpoints)
        })
        .collect::<BTreeMap<ModuleInstanceId, BTreeMap<String, ApiEndpoint<DynServerModule>>>>();

    let consensus_api = Arc::new(consensus_api);
    let core_api = Arc::new(core_api);
    let module_api = Arc::new(module_api);
    let parallel_connections_limit = Arc::new(Semaphore::new(iroh_api_limits.max_connections));

    loop {
        match endpoint.accept().await {
            Some(incoming) => {
                if parallel_connections_limit.available_permits() == 0 {
                    warn!(
                        target: LOG_NET_API,
                        limit = iroh_api_limits.max_connections,
                        "Iroh API connection limit reached, blocking new connections"
                    );
                }
                let permit = parallel_connections_limit
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("semaphore should not be closed");
                task_group.spawn_cancellable_silent(
                    "handle-iroh-connection",
                    handle_incoming(
                        consensus_api.clone(),
                        core_api.clone(),
                        module_api.clone(),
                        task_group.clone(),
                        incoming,
                        permit,
                        iroh_api_limits.max_requests_per_connection,
                    )
                    .then(|result| async {
                        if let Err(err) = result {
                            warn!(target: LOG_NET_API, err = %err.fmt_compact_anyhow(), "Failed to handle iroh connection");
                        }
                    }),
                );
            }
            None => return,
        }
    }
}

async fn handle_incoming(
    consensus_api: Arc<ConsensusApi>,
    core_api: Arc<BTreeMap<String, ApiEndpoint<ConsensusApi>>>,
    module_api: Arc<BTreeMap<ModuleInstanceId, BTreeMap<String, ApiEndpoint<DynServerModule>>>>,
    task_group: TaskGroup,
    incoming: Incoming,
    _connection_permit: tokio::sync::OwnedSemaphorePermit,
    iroh_api_max_requests_per_connection: usize,
) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    let parallel_requests_limit = Arc::new(Semaphore::new(iroh_api_max_requests_per_connection));

    loop {
        let (send_stream, recv_stream) = connection.accept_bi().await?;

        if parallel_requests_limit.available_permits() == 0 {
            warn!(
                target: LOG_NET_API,
                limit = iroh_api_max_requests_per_connection,
                "Iroh API request limit reached for connection, blocking new requests"
            );
        }
        let permit = parallel_requests_limit
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore should not be closed");
        task_group.spawn_cancellable_silent(
            "handle-iroh-request",
            handle_request(
                consensus_api.clone(),
                core_api.clone(),
                module_api.clone(),
                send_stream,
                recv_stream,
                permit,
            )
            .then(|result| async {
                if let Err(err) = result {
                    warn!(target: LOG_NET_API, err = %err.fmt_compact_anyhow(), "Failed to handle iroh request");
                }
            }),
        );
    }
}

async fn handle_request(
    consensus_api: Arc<ConsensusApi>,
    core_api: Arc<BTreeMap<String, ApiEndpoint<ConsensusApi>>>,
    module_api: Arc<BTreeMap<ModuleInstanceId, BTreeMap<String, ApiEndpoint<DynServerModule>>>>,
    mut send_stream: SendStream,
    mut recv_stream: RecvStream,
    _request_permit: tokio::sync::OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    let request = recv_stream.read_to_end(100_000).await?;

    let request = serde_json::from_slice::<IrohApiRequest>(&request)?;

    let response = await_response(consensus_api, core_api, module_api, request).await;

    let response = serde_json::to_vec(&response)?;

    send_stream.write_all(&response).await?;

    send_stream.finish()?;

    Ok(())
}

async fn await_response(
    consensus_api: Arc<ConsensusApi>,
    core_api: Arc<BTreeMap<String, ApiEndpoint<ConsensusApi>>>,
    module_api: Arc<BTreeMap<ModuleInstanceId, BTreeMap<String, ApiEndpoint<DynServerModule>>>>,
    request: IrohApiRequest,
) -> Result<Value, ApiError> {
    match request.method {
        ApiMethod::Core(method) => {
            let endpoint = core_api.get(&method).ok_or(ApiError::not_found(method))?;

            let (state, context) = consensus_api.context(&request.request, None).await;

            (endpoint.handler)(state, context, request.request).await
        }
        ApiMethod::Module(module_id, method) => {
            let endpoint = module_api
                .get(&module_id)
                .ok_or(ApiError::not_found(module_id.to_string()))?
                .get(&method)
                .ok_or(ApiError::not_found(method))?;

            let (state, context) = consensus_api
                .context(&request.request, Some(module_id))
                .await;

            (endpoint.handler)(state, context, request.request).await
        }
    }
}
