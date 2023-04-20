#![allow(where_clauses_object_safety)] // https://github.com/dtolnay/async-trait/issues/228
extern crate fedimint_core;

use std::fs;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow as format_err, bail, Context};
use async_trait::async_trait;
use config::ServerConfig;
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::Database;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::{ApiAuth, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased};
use fedimint_core::task::{sleep, TaskGroup};
pub use fedimint_core::*;
use fedimint_core::{NumPeers, PeerId};
use fedimint_logging::{LOG_CONSENSUS, LOG_CORE, LOG_NET_API, LOG_TASK};
use futures::FutureExt;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::types::error::CallError;
use jsonrpsee::types::ErrorObject;
use jsonrpsee::RpcModule;
use rand::rngs::OsRng;
use tracing::{debug, error, info, warn};

use crate::config::api::{ConfigGenApi, ConfigGenSettings};
use crate::config::io::PLAINTEXT_PASSWORD;
use crate::consensus::server::ConsensusServer;
use crate::consensus::HbbftConsensusOutcome;
use crate::net::api::{ConsensusApi, RpcHandlerCtx};
use crate::net::connect::TlsTcpConnector;
use crate::net::peers::ReconnectPeerConnections;

/// The actual implementation of consensus
pub mod consensus;

/// Provides interfaces for ACID-compliant data store backends
pub mod db;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Fedimint toplevel config
pub mod config;

/// Implementation of multiplexed peer connections
pub mod multiplexed;

/// How long to wait before timing out client connections
const API_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(60);

/// Has the context necessary for serving API endpoints
///
/// Returns the specific `State` the endpoint requires and the
/// `ApiEndpointContext` which all endpoints can access.
#[async_trait]
pub trait HasApiContext<State> {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&State, ApiEndpointContext<'_>);
}

/// Main server for running Fedimint consensus and APIs
pub struct FedimintServer {
    /// Location where configs are stored
    pub data_dir: PathBuf,
    /// Module and endpoint settings necessary for starting the API
    pub settings: ConfigGenSettings,
    /// Database shared by the API and consensus
    pub db: Database,
    /// Upgrade epoch if we shutdown due to an upgrade
    // TODO: should be replaced by requiring an API call instead
    pub upgrade_epoch: Option<u64>,
}

impl FedimintServer {
    /// Starts the `ConfigGenApi` unless configs already exist
    /// After configs are generated, start `ConsensusApi` and `ConsensusServer`
    pub async fn run(mut self, mut task_group: TaskGroup) -> anyhow::Result<()> {
        let task = &mut task_group;

        info!(target: LOG_CONSENSUS, "Starting config gen");
        let cfg = self.run_config_gen(task).await?;

        let server =
            ConsensusServer::new(cfg, self.db.clone(), self.settings.registry.clone(), task)
                .await
                .unwrap();

        info!(target: LOG_CONSENSUS, "Starting consensus API");
        let handle = self.run_consensus_api(&server.consensus.api, task).await?;

        self.run_consensus(server, task).await?;

        info!(target: LOG_CONSENSUS, "Stopping consensus API");
        handle.stop()?;

        Ok(())
    }

    /// Generates the `ServerConfig`
    ///
    /// If a local password file exists, will try to read the configs from the
    /// filesystem.  Otherwise, it will start the `ConfigGenApi`.
    async fn run_config_gen(&self, task_group: &mut TaskGroup) -> anyhow::Result<ServerConfig> {
        let (config_generated_tx, mut config_generated_rx) = tokio::sync::mpsc::channel(1);
        let config_gen = ConfigGenApi::new(
            self.data_dir.clone(),
            self.settings.clone(),
            self.db.clone(),
            config_generated_tx,
            task_group,
        );

        // Attempt get the config with local password, otherwise start config gen
        if let Ok(password) = fs::read_to_string(self.data_dir.join(PLAINTEXT_PASSWORD)) {
            config_gen
                .set_password(ApiAuth(password.clone()))
                .map_err(|_| format_err!("Unable to use local password"))?;
            info!(target: LOG_CONSENSUS, "Setting password from local file");

            if config_gen.start_consensus(ApiAuth(password)).await.is_ok() {
                info!(target: LOG_CONSENSUS, "Configs found locally");
                return Ok(config_generated_rx.recv().await.expect("should not close"));
            }
        }

        let mut rpc_module = RpcHandlerCtx::new_module(config_gen);
        Self::attach_endpoints(&mut rpc_module, config::api::server_endpoints(), None);
        let server_handle = self.spawn_api(rpc_module, 10, task_group).await;

        let cfg = config_generated_rx.recv().await.expect("should not close");
        server_handle.stop().expect("Unable to stop server");
        server_handle.stopped().await;
        Ok(cfg)
    }

    /// Runs the `ConsensusApi` which serves endpoints while consensus is
    /// running
    pub async fn run_consensus_api(
        &self,
        api: &ConsensusApi,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<ServerHandle> {
        let mut rpc_module = RpcHandlerCtx::new_module(api.clone());
        Self::attach_endpoints(&mut rpc_module, net::api::server_endpoints(), None);
        for (id, module) in api.modules.iter_modules() {
            Self::attach_endpoints(&mut rpc_module, module.api_endpoints(), Some(id));
        }

        let handle = self
            .spawn_api(rpc_module, api.cfg.local.max_connections, task_group)
            .await;
        Ok(handle)
    }

    /// Runs the `FedimintServer` which runs P2P consensus
    async fn run_consensus(
        &mut self,
        server: ConsensusServer,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<()> {
        // TODO: Upgrade / config validation should be part of the config gen API
        let our_hash = server
            .cfg
            .consensus
            .to_config_response(&self.settings.registry)
            .consensus_hash;

        if let Some(epoch) = self.upgrade_epoch {
            server.consensus.remove_upgrade_items(epoch).await?;
        }

        loop {
            info!(target: LOG_CONSENSUS, "Waiting for peers config {our_hash}");
            match server.api.consensus_config_hash().await {
                Ok(consensus_hash) if consensus_hash == our_hash => break,
                Ok(_) => bail!("Our consensus config doesn't match peers!"),
                Err(e) => {
                    warn!(target: LOG_CONSENSUS, "ERROR {:?}", e)
                }
            }
            sleep(Duration::from_millis(1000)).await;
        }

        server.run_consensus(task_group.make_handle()).await;

        Ok(())
    }

    /// Spawns an API server
    async fn spawn_api<T>(
        &self,
        module: RpcModule<RpcHandlerCtx<T>>,
        max_connections: u32,
        task_group: &mut TaskGroup,
    ) -> ServerHandle {
        let server_handle = ServerBuilder::new()
            .max_connections(max_connections)
            .ping_interval(Duration::from_secs(10))
            .build(&self.settings.api_bind.to_string())
            .await
            .context(format!("Bind address: {}", self.settings.api_bind))
            .expect("Could not start API server")
            .start(module)
            .expect("Could not start API server");

        let stop_handle = server_handle.clone();

        task_group
            .make_handle()
            .on_shutdown(Box::new(move || {
                Box::pin(async move {
                    debug!(target: LOG_TASK, "Shutting down jsonrpcsee server");
                    // ignore errors: we don't care if already stopped
                    let _ = stop_handle.stop();
                })
            }))
            .await;

        server_handle
    }

    /// Attaches `endpoints` to the `RpcModule`
    fn attach_endpoints<State, T>(
        rpc_module: &mut RpcModule<RpcHandlerCtx<T>>,
        endpoints: Vec<ApiEndpoint<State>>,
        module_instance_id: Option<ModuleInstanceId>,
    ) where
        T: HasApiContext<State> + Sync + Send + 'static,
        State: Sync + Send + 'static,
    {
        for endpoint in endpoints {
            let path = if let Some(module_instance_id) = module_instance_id {
                // This memory leak is fine because it only happens on server startup
                // and path has to live till the end of program anyways.
                Box::leak(
                    format!("module_{}_{}", module_instance_id, endpoint.path).into_boxed_str(),
                )
            } else {
                endpoint.path
            };
            // Check if paths contain any abnormal characters
            if path.contains(|c: char| !matches!(c, '0'..='9' | 'a'..='z' | '_')) {
                panic!("Constructing bad path name {path}");
            }

            // Another memory leak that is fine because the function is only called once at
            // startup
            let handler: &'static _ = Box::leak(endpoint.handler);

            rpc_module
                .register_async_method(path, move |params, rpc_state| async move {
                    let params = params.one::<serde_json::Value>()?;
                    let rpc_context = &rpc_state.rpc_context;

                    // Using AssertUnwindSafe here is far from ideal. In theory this means we could
                    // end up with an inconsistent state in theory. In practice most API functions
                    // are only reading and the few that do write anything are atomic. Lastly, this
                    // is only the last line of defense
                    AssertUnwindSafe(tokio::time::timeout(API_ENDPOINT_TIMEOUT, async {
                        let request = serde_json::from_value(params)
                            .map_err(|e| ApiError::bad_request(e.to_string()))?;
                        let (state, context) =
                            rpc_context.context(&request, module_instance_id).await;

                        let res = (handler)(state, context, request).await;

                        res
                    }))
                    .catch_unwind()
                    .await
                    .map_err(|_| {
                        error!(
                            target: LOG_NET_API,
                            path, "API handler panicked, DO NOT IGNORE, FIX IT!!!"
                        );
                        jsonrpsee::core::Error::Call(CallError::Custom(ErrorObject::owned(
                            500,
                            "API handler panicked",
                            None::<()>,
                        )))
                    })?
                    .map_err(|tokio::time::error::Elapsed { .. }| {
                        jsonrpsee::core::Error::RequestTimeout
                    })?
                    .map_err(|e| {
                        jsonrpsee::core::Error::Call(CallError::Custom(ErrorObject::owned(
                            e.code, e.message, None::<()>,
                        )))
                    })
                })
                .expect("Failed to register async method");
        }
    }
}
