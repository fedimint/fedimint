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
pub mod connection_limits;
pub mod db;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use bitcoin::hashes::hex::FromHex as _;
use config::ServerConfig;
use config::io::read_server_config;
pub use connection_limits::ConnectionLimits;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::P2PMessage;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::ApiAuth;
use fedimint_core::net::peers::DynP2PConnections;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_logging::LOG_CONSENSUS;
pub use fedimint_server_core as core;
use fedimint_server_core::ServerModuleInitRegistry;
use fedimint_server_core::bitcoin_rpc::DynServerBitcoinRpc;
use fedimint_server_core::dashboard_ui::DynDashboardApi;
use fedimint_server_core::setup_ui::{DynSetupApi, ISetupApi};
use jsonrpsee::RpcModule;
use net::api::ApiSecrets;
use net::p2p::P2PStatusReceivers;
use net::p2p_connector::IrohConnector;
use tokio::net::TcpListener;
use tokio_rustls::rustls;
use tracing::info;

use crate::config::ConfigGenSettings;
use crate::config::io::write_server_config;
use crate::config::setup::{ConfigGenOutcome, SetupApi};
use crate::db::{ServerInfo, ServerInfoKey};
use crate::fedimint_core::net::peers::IP2PConnections;
use crate::metrics::initialize_gauge_metrics;
use crate::net::api::announcement::start_api_announcement_service;
use crate::net::api::guardian_metadata::start_guardian_metadata_service;
use crate::net::api::pkarr_publish::start_pkarr_publish_service;
use crate::net::p2p::{ReconnectP2PConnections, p2p_status_channels};
use crate::net::p2p_connector::{IP2PConnector, TlsTcpConnector};

pub mod metrics;

/// The actual implementation of consensus
pub mod consensus;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Fedimint toplevel config
pub mod config;

/// Runtime settings for the iroh-next 1.0-compatible dual-stack endpoints.
/// Passed as `Option<IrohNextSettings>` — `None` means disabled.
#[derive(Debug, Clone)]
pub struct IrohNextSettings {
    pub api_bind: SocketAddr,
    pub p2p_bind: SocketAddr,
}

/// A function/closure type for handling dashboard UI
pub type DashboardUiRouter = Box<dyn Fn(DynDashboardApi) -> axum::Router + Send>;

/// A function/closure type for handling setup UI
pub type SetupUiRouter = Box<dyn Fn(DynSetupApi) -> axum::Router + Send>;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    data_dir: PathBuf,
    auth_ui: Option<ApiAuth>,
    auth_api: Option<ApiAuth>,
    force_api_secrets: ApiSecrets,
    settings: ConfigGenSettings,
    db: Database,
    code_version_str: String,
    code_version_hash: String,
    module_init_registry: ServerModuleInitRegistry,
    task_group: TaskGroup,
    bitcoin_rpc: DynServerBitcoinRpc,
    setup_ui_router: SetupUiRouter,
    dashboard_ui_router: DashboardUiRouter,
    db_checkpoint_retention: u64,
    session_timeout: Duration,
    iroh_api_limits: ConnectionLimits,
    iroh_next_settings: Option<IrohNextSettings>,
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
                    settings.iroh_dns.clone(),
                    settings.iroh_relays.clone(),
                    cfg.consensus
                        .iroh_endpoints
                        .iter()
                        .map(|(peer, endpoints)| (*peer, endpoints.p2p_pk))
                        .collect(),
                    iroh_next_settings.as_ref(),
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
                code_version_hash.clone(),
                force_api_secrets.clone(),
                setup_ui_router,
                module_init_registry.clone(),
                auth_ui.clone(),
                auth_api.clone(),
                iroh_next_settings.clone(),
            ))
            .await?
        }
    };

    let iroh_enabled = !cfg.consensus.iroh_endpoints.is_empty();

    let decoders = module_init_registry.decoders_strict(
        cfg.consensus
            .modules
            .iter()
            .map(|(id, config)| (*id, &config.kind)),
    )?;

    let db = db.with_decoders(decoders);

    initialize_gauge_metrics(&task_group, &db).await;

    start_api_announcement_service(&db, &task_group, &cfg, force_api_secrets.get_active()).await?;
    start_guardian_metadata_service(
        &db,
        &task_group,
        &cfg,
        force_api_secrets.get_active(),
        iroh_next_settings.as_ref().filter(|_| iroh_enabled),
    )
    .await?;
    start_pkarr_publish_service(&db, &task_group, &cfg).await?;

    info!(target: LOG_CONSENSUS, "Starting consensus...");

    let connectors = ConnectorRegistry::build_from_server_defaults()
        .bind()
        .await?;

    Box::pin(consensus::run(
        connectors,
        auth_ui,
        auth_api,
        connections,
        p2p_status_receivers,
        settings.api_bind,
        settings.iroh_dns,
        settings.iroh_relays,
        cfg,
        db,
        module_init_registry.clone(),
        &task_group,
        force_api_secrets,
        data_dir,
        code_version_str,
        code_version_hash,
        bitcoin_rpc,
        settings.ui_bind,
        dashboard_ui_router,
        db_checkpoint_retention,
        session_timeout,
        iroh_api_limits,
        iroh_next_settings.as_ref().filter(|_| iroh_enabled),
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
    if !data_dir.join("consensus.json").exists() {
        return Ok(None);
    }

    read_server_config(data_dir).map(Some)
}

/// Validate restored TCP transport material before building `TlsTcpConnector`.
///
/// `ServerConfig::tls_config()` and `TlsTcpConnector::new()` contain invariant
/// checks that are fine for generated configs but too panic-prone for uploaded
/// restore data. This preflights the same key/certificate material and returns
/// a normal restore error before any files are installed.
///
/// Keep this in sync with the panic points in `ServerConfig::tls_config()`:
/// missing `private.tls_key`, malformed TLS private-key hex, malformed TLS
/// certificate hex, and malformed TLS private-key DER.
fn validate_restored_tcp_config(cfg: &ServerConfig) -> anyhow::Result<()> {
    let tls_key = cfg
        .private
        .tls_key
        .as_ref()
        .context("Restored TCP config is missing the TLS private key")?;
    let tls_key_bytes = Vec::from_hex(tls_key).context("Parsing restored TLS private key")?;
    rustls::pki_types::PrivateKeyDer::try_from(tls_key_bytes)
        .map_err(|e| anyhow::format_err!("Parsing restored TLS private key DER: {e}"))?;

    ensure!(
        cfg.consensus.tls_certs.contains_key(&cfg.local.identity),
        "Restored TCP config is missing our TLS certificate"
    );
    for (peer, cert) in &cfg.consensus.tls_certs {
        Vec::from_hex(cert)
            .with_context(|| format!("Parsing restored TLS certificate for peer {peer}"))?;
    }

    let tls_config = cfg.tls_config();
    let mut root_cert_store = rustls::RootCertStore::empty();
    for cert in tls_config.certificates.values() {
        root_cert_store
            .add(cert.clone())
            .context("Adding restored TLS certificate to root store")?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(root_cert_store.into())
        .build()
        .context("Creating restored TLS client verifier")?;
    let certificate = tls_config
        .certificates
        .get(&cfg.local.identity)
        .context("Restored TCP config is missing our TLS certificate")?
        .clone();
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![certificate], tls_config.private_key.clone_key())
        .context("Creating restored TLS server config")?;

    Ok(())
}

/// Validate restored Iroh transport keys and return the p2p key for connector
/// setup.
///
/// Restore data must contain both API and p2p secret keys, and both must match
/// this guardian's public keys in the restored consensus endpoints before the
/// config is installed.
fn restored_iroh_p2p_key(cfg: &ServerConfig) -> anyhow::Result<iroh::SecretKey> {
    let iroh_p2p_sk = cfg
        .private
        .iroh_p2p_sk
        .clone()
        .context("Restored Iroh config is missing the Iroh p2p secret key")?;
    let local_endpoints = cfg
        .consensus
        .iroh_endpoints
        .get(&cfg.local.identity)
        .context("Restored Iroh config is missing our Iroh endpoints")?;
    ensure!(
        iroh_p2p_sk.public() == local_endpoints.p2p_pk,
        "Restored Iroh p2p secret key does not match our Iroh endpoint"
    );

    let iroh_api_sk = cfg
        .private
        .iroh_api_sk
        .clone()
        .context("Restored Iroh config is missing the Iroh api secret key")?;
    ensure!(
        iroh_api_sk.public() == local_endpoints.api_pk,
        "Restored Iroh api secret key does not match our Iroh endpoint"
    );

    Ok(iroh_p2p_sk)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_config_gen(
    data_dir: PathBuf,
    settings: ConfigGenSettings,
    db: Database,
    task_group: &TaskGroup,
    code_version_str: String,
    code_version_hash: String,
    api_secrets: ApiSecrets,
    setup_ui_handler: SetupUiRouter,
    module_init_registry: ServerModuleInitRegistry,
    auth_ui: Option<ApiAuth>,
    auth_api: Option<ApiAuth>,
    iroh_next_settings: Option<IrohNextSettings>,
) -> anyhow::Result<(
    ServerConfig,
    DynP2PConnections<P2PMessage>,
    P2PStatusReceivers,
)> {
    info!(target: LOG_CONSENSUS, "Starting config gen");

    initialize_gauge_metrics(task_group, &db).await;

    let (cgp_sender, mut cgp_receiver) = tokio::sync::mpsc::channel(1);

    let setup_api = SetupApi::new(
        settings.clone(),
        db.clone(),
        cgp_sender,
        code_version_str.clone(),
        code_version_hash,
        auth_ui,
        auth_api,
    );

    let mut rpc_module = RpcModule::new(setup_api.clone());

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

    let ui_service = setup_ui_handler(setup_api.clone().into_dyn()).into_make_service();

    let ui_listener = TcpListener::bind(settings.ui_bind)
        .await
        .expect("Failed to bind setup UI");

    ui_task_group.spawn("setup-ui", move |handle| async move {
        axum::serve(ui_listener, ui_service)
            .with_graceful_shutdown(handle.make_shutdown_rx())
            .await
            .expect("Failed to serve setup UI");
    });

    info!(target: LOG_CONSENSUS, "Setup UI running at http://{} 🚀", settings.ui_bind);

    loop {
        let config_gen_outcome = cgp_receiver
            .recv()
            .await
            .expect("Config gen params receiver closed unexpectedly");

        match config_gen_outcome {
            ConfigGenOutcome::Generated(cg_params) => {
                // HACK: The `start-dkg` API call needs to have some time to finish
                // before we shut down api handling. There's no easy and good way to do
                // that other than just giving it some grace period.
                sleep(Duration::from_millis(100)).await;

                api_handler
                    .stop()
                    .expect("Config api should still be running");

                api_handler.stopped().await;

                ui_task_group
                    .shutdown_join_all(None)
                    .await
                    .context("Failed to shutdown UI server after config gen")?;

                let cg_params = *cg_params;
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
                        cg_params
                            .iroh_p2p_sk
                            .clone()
                            .expect("Iroh p2p secret key is required for iroh endpoints"),
                        settings.p2p_bind,
                        settings.iroh_dns,
                        settings.iroh_relays,
                        cg_params
                            .iroh_endpoints()
                            .iter()
                            .map(|(peer, endpoints)| (*peer, endpoints.p2p_pk))
                            .collect(),
                        iroh_next_settings.as_ref(),
                    )
                    .await?
                    .into_dyn()
                };

                let (p2p_status_senders, p2p_status_receivers) =
                    p2p_status_channels(connector.peers());

                let connections = ReconnectP2PConnections::new(
                    cg_params.identity,
                    connector,
                    task_group,
                    p2p_status_senders,
                )
                .into_dyn();

                let cfg = ServerConfig::distributed_gen(
                    &cg_params,
                    module_init_registry.clone(),
                    code_version_str.clone(),
                    connections.clone(),
                    p2p_status_receivers.clone(),
                )
                .await?;

                assert_ne!(
                    cfg.consensus.iroh_endpoints.is_empty(),
                    cfg.consensus.api_endpoints.is_empty(),
                );

                write_server_config(
                    &cfg,
                    &data_dir,
                    &module_init_registry,
                    api_secrets.get_active(),
                )?;

                return Ok((cfg, connections, p2p_status_receivers));
            }
            ConfigGenOutcome::Restored(restored, restore_result_sender) => {
                // Process restore outcomes while setup serving is still running. This lets the
                // HTTP handler wait for a precise success/error acknowledgement and keeps setup
                // retryable if validation or the config write fails.
                let result: anyhow::Result<_> = async {
                    let cfg = *restored;

                    module_init_registry.decoders_strict(
                        cfg.consensus
                            .modules
                            .iter()
                            .map(|(id, config)| (*id, &config.kind)),
                    )?;

                    cfg.validate_config(&cfg.local.identity, &module_init_registry)?;

                    if cfg.consensus.iroh_endpoints.is_empty() {
                        validate_restored_tcp_config(&cfg)?;
                    }

                    // Build the connector from the already validated restored config before
                    // writing it to its final location.
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
                        let iroh_p2p_sk = restored_iroh_p2p_key(&cfg)?;

                        IrohConnector::new(
                            iroh_p2p_sk,
                            settings.p2p_bind,
                            settings.iroh_dns.clone(),
                            settings.iroh_relays.clone(),
                            cfg.consensus
                                .iroh_endpoints
                                .iter()
                                .map(|(peer, endpoints)| (*peer, endpoints.p2p_pk))
                                .collect(),
                            iroh_next_settings.as_ref(),
                        )
                        .await?
                        .into_dyn()
                    };

                    let (p2p_status_senders, p2p_status_receivers) =
                        p2p_status_channels(connector.peers());

                    // Write the restored config directly into the data directory, exactly
                    // like a freshly generated config.
                    write_server_config(
                        &cfg,
                        &data_dir,
                        &module_init_registry,
                        api_secrets.get_active(),
                    )?;

                    Ok((cfg, connector, p2p_status_senders, p2p_status_receivers))
                }
                .await;

                let ack = result
                    .as_ref()
                    .map(|_| ())
                    .map_err(std::string::ToString::to_string);
                let restore_failed = ack.is_err();
                let _ = restore_result_sender.send(ack);

                if restore_failed {
                    continue;
                }

                // Give the restore API call a chance to return the acknowledged outcome before
                // shutting down setup serving.
                sleep(Duration::from_millis(100)).await;

                api_handler
                    .stop()
                    .expect("Config api should still be running");

                api_handler.stopped().await;

                ui_task_group
                    .shutdown_join_all(None)
                    .await
                    .context("Failed to shutdown UI server after restored config install")?;

                let (cfg, connector, p2p_status_senders, p2p_status_receivers) = result?;
                let connections = ReconnectP2PConnections::new(
                    cfg.local.identity,
                    connector,
                    task_group,
                    p2p_status_senders,
                )
                .into_dyn();

                return Ok((cfg, connections, p2p_status_receivers));
            }
        }
    }
}
