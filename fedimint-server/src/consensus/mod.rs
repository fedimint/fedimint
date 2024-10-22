pub mod aleph_bft;
pub mod api;
pub mod db;
pub mod debug;
pub mod engine;
pub mod transaction;

use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use async_channel::Sender;
use db::get_global_database_migrations;
use fedimint_api_client::api::net::Connector;
use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::config::ServerModuleInitRegistry;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{apply_migrations, apply_migrations_server, Database};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{ApiEndpoint, ApiError, ApiMethod, IrohApiRequest};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::{TaskGroup, TaskHandle};
use fedimint_core::NumPeers;
use fedimint_logging::{LOG_CONSENSUS, LOG_CORE};
use iroh_net::discovery::local_swarm_discovery::LocalSwarmDiscovery;
use iroh_net::discovery::pkarr::PkarrPublisher;
use iroh_net::endpoint::{Incoming, RecvStream, SendStream};
use iroh_net::Endpoint;
use jsonrpsee::server::ServerHandle;
use serde_json::Value;
use tokio::sync::{watch, RwLock};
use tracing::info;
use tracing::log::warn;

use self::api::server_endpoints;
use crate::config::{ServerConfig, ServerConfigLocal};
use crate::consensus::api::ConsensusApi;
use crate::consensus::engine::ConsensusEngine;
use crate::envs::{FM_DB_CHECKPOINT_RETENTION_DEFAULT, FM_DB_CHECKPOINT_RETENTION_ENV};
use crate::net;
use crate::net::api::announcement::get_api_urls;
use crate::net::api::{ApiSecrets, HasApiContext, RpcHandlerCtx};

const FEDIMINT_ALPN: &[u8] = "FEDIMINT_ALPN".as_bytes();

/// How many txs can be stored in memory before blocking the API
const TRANSACTION_BUFFER: usize = 1000;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    p2p_bind_addr: SocketAddr,
    api_bind_addr: SocketAddr,
    cfg: ServerConfig,
    db: Database,
    module_init_registry: ServerModuleInitRegistry,
    task_group: &TaskGroup,
    force_api_secrets: ApiSecrets,
    data_dir: PathBuf,
    code_version_str: String,
) -> anyhow::Result<()> {
    cfg.validate_config(&cfg.local.identity, &module_init_registry)?;

    apply_migrations_server(
        &db,
        "fedimint-server".to_string(),
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
                    module_init.get_database_migrations(),
                    Some(*module_id),
                    None,
                )
                .await?;

                let module = module_init
                    .init(
                        NumPeers::from(cfg.consensus.api_endpoints.len()),
                        cfg.get_module_config(*module_id)?,
                        db.with_prefix_module_id(*module_id).0,
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
    let connection_status_channels = Arc::new(RwLock::new(BTreeMap::new()));
    let last_ci_by_peer = Arc::new(RwLock::new(BTreeMap::new()));

    let consensus_api = ConsensusApi {
        cfg: cfg.clone(),
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
        last_ci_by_peer: last_ci_by_peer.clone(),
        connection_status_channels: connection_status_channels.clone(),
        force_api_secret: force_api_secrets.get_active(),
        code_version_str,
    };

    info!(target: LOG_CONSENSUS, "Starting Consensus Api");

    let api_handler = start_consensus_api(
        &cfg.local,
        consensus_api.clone(),
        force_api_secrets.clone(),
        api_bind_addr,
    )
    .await;

    start_iroh_api(
        cfg.private.api_secret_key.clone(),
        consensus_api.clone(),
        task_group,
    )
    .await?;

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

    let checkpoint_retention: String = env::var(FM_DB_CHECKPOINT_RETENTION_ENV)
        .unwrap_or(FM_DB_CHECKPOINT_RETENTION_DEFAULT.to_string());
    let checkpoint_retention = checkpoint_retention.parse().unwrap_or_else(|_| {
        panic!("FM_DB_CHECKPOINT_RETENTION_ENV var is invalid: {checkpoint_retention}")
    });

    info!(target: LOG_CONSENSUS, "Starting Consensus Engine");

    let api_urls = get_api_urls(&db, &cfg.consensus).await;

    let federation_api = if cfg.consensus.api_public_keys.is_empty() {
        DynGlobalApi::from_endpoints(
            api_urls,
            &force_api_secrets.get_active(),
            &Connector::default(),
        )
    } else {
        DynGlobalApi::from_iroh_endpoints(cfg.consensus.api_public_keys.clone(), task_group.clone())
            .await?
    };

    // FIXME: (@leonardo) How should this be handled ?
    // Using the `Connector::default()` for now!
    ConsensusEngine {
        db,
        federation_api,
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
        data_dir,
        checkpoint_retention,
        p2p_bind_addr,
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
    let mut rpc_module = RpcHandlerCtx::new_module(api.clone());

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
        "submit_module_ci_proposals_{module_id}",
        move |task_handle| async move {
            while !task_handle.is_shutting_down() {
                let module_consensus_items = tokio::time::timeout(
                    CONSENSUS_PROPOSAL_TIMEOUT,
                    module.consensus_proposal(
                        &mut db
                            .begin_transaction_nc()
                            .await
                            .to_ref_with_prefix_module_id(module_id).0
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

async fn start_iroh_api(
    secret_key: iroh_net::key::SecretKey,
    consensus_api: ConsensusApi,
    task_group: &TaskGroup,
) -> anyhow::Result<()> {
    let endpoint = Endpoint::builder()
        .discovery(match is_running_in_test_env() {
            true => Box::new(LocalSwarmDiscovery::new(secret_key.public())?),
            false => Box::new(PkarrPublisher::n0_dns(secret_key.clone())),
        })
        .secret_key(secret_key)
        .alpns(vec![FEDIMINT_ALPN.to_vec()])
        .bind()
        .await?;

    let tg = task_group.clone();

    task_group.spawn("listen task", |handle| {
        run_listen_task(consensus_api, endpoint, handle, tg)
    });

    Ok(())
}

async fn run_listen_task(
    consensus_api: ConsensusApi,
    endpoint: Endpoint,
    task_handle: TaskHandle,
    task_group: TaskGroup,
) {
    let core_api_endpoints = server_endpoints()
        .into_iter()
        .map(|endpoint| (endpoint.path.to_string(), endpoint))
        .collect::<BTreeMap<String, ApiEndpoint<ConsensusApi>>>();

    let module_api_endpoints = consensus_api
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
    let core_api_endpoints = Arc::new(core_api_endpoints);
    let module_api_endpoints = Arc::new(module_api_endpoints);

    let mut shutdown_rx = task_handle.make_shutdown_rx();

    while !task_handle.is_shutting_down() {
        tokio::select! {
            incoming =  endpoint.accept() => {
                match incoming {
                    Some(incoming) => {
                        let ca = consensus_api.clone();
                        let cae = core_api_endpoints.clone();
                        let mae = module_api_endpoints.clone();
                        let tg = task_group.clone();

                        task_group.spawn("incoming task", |handle| async {
                            if let Err(e) = handle_incoming(
                                ca,
                                cae,
                                mae,
                                incoming,
                                handle,
                                tg)
                            .await {
                                warn!("Failed to handle incoming connection {e}");
                            }
                        });
                    }
                    None => return,
                }
            },
            () = &mut shutdown_rx => { return },
        };
    }
}

async fn handle_incoming(
    consensus_api: Arc<ConsensusApi>,
    core_api_endpoints: Arc<BTreeMap<String, ApiEndpoint<ConsensusApi>>>,
    module_api_endpoints: Arc<
        BTreeMap<ModuleInstanceId, BTreeMap<String, ApiEndpoint<DynServerModule>>>,
    >,
    incoming: Incoming,
    task_handle: TaskHandle,
    task_group: TaskGroup,
) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    let mut shutdown_rx = task_handle.make_shutdown_rx();

    while !task_handle.is_shutting_down() {
        tokio::select! {
            request =  connection.accept_bi() => {
                    let (send_stream, receive_stream) = request?;
                    let ca = consensus_api.clone();
                    let cae = core_api_endpoints.clone();
                    let mae = module_api_endpoints.clone();

                    task_group.spawn("request task", |_| async {
                        if let Err(e) = handle_request(
                            ca,
                            cae,
                            mae,
                            send_stream,
                            receive_stream
                        ).await {
                            warn!("Failed to handle request {e}");
                        }
                });
            },
            () = &mut shutdown_rx => { return Ok(()) },
        };
    }

    Ok(())
}

async fn handle_request(
    consensus_api: Arc<ConsensusApi>,
    core_api_endpoints: Arc<BTreeMap<String, ApiEndpoint<ConsensusApi>>>,
    module_api_endpoints: Arc<
        BTreeMap<ModuleInstanceId, BTreeMap<String, ApiEndpoint<DynServerModule>>>,
    >,
    mut send_stream: SendStream,
    mut receive_stream: RecvStream,
) -> anyhow::Result<()> {
    let request = receive_stream.read_to_end(100_000).await?;

    let request = serde_json::from_slice::<IrohApiRequest>(&request)?;

    let response = await_response(
        consensus_api,
        core_api_endpoints,
        module_api_endpoints,
        request,
    )
    .await;

    let response = serde_json::to_vec(&response)?;

    send_stream.write_all(&response).await?;

    send_stream.finish()?;

    Ok(())
}

async fn await_response(
    consensus_api: Arc<ConsensusApi>,
    core_api_endpoints: Arc<BTreeMap<String, ApiEndpoint<ConsensusApi>>>,
    module_api_endpoints: Arc<
        BTreeMap<ModuleInstanceId, BTreeMap<String, ApiEndpoint<DynServerModule>>>,
    >,
    request: IrohApiRequest,
) -> Result<Value, ApiError> {
    match request.method {
        ApiMethod::Core(method) => {
            let endpoint = core_api_endpoints
                .get(&method)
                .ok_or(ApiError::not_found(method))?;

            let (state, context): (&ConsensusApi, _) =
                consensus_api.context(&request.request, None).await;

            (endpoint.handler)(state, context, request.request).await
        }
        ApiMethod::Module(module_id, method) => {
            let endpoint = module_api_endpoints
                .get(&module_id)
                .ok_or(ApiError::not_found(module_id.to_string()))?
                .get(&method)
                .ok_or(ApiError::not_found(method))?;

            let (state, context): (&DynServerModule, _) = consensus_api
                .context(&request.request, Some(module_id))
                .await;

            (endpoint.handler)(state, context, request.request).await
        }
    }
}
