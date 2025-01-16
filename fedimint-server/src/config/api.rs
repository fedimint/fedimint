use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::sha256;
use fedimint_api_client::api::{DynGlobalApi, StatusResponse};
use fedimint_bitcoind::create_bitcoind;
use fedimint_core::admin_client::{
    ConfigGenConnectionsRequest, ConfigGenParamsConsensus, ConfigGenParamsRequest,
    ConfigGenParamsResponse, PeerServerParams, ServerStatus,
};
use fedimint_core::config::{ConfigGenModuleParams, ServerModuleConfigGenParamsRegistry};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::Database;
use fedimint_core::encoding::Encodable;
use fedimint_core::endpoint_constants::{
    ADD_CONFIG_GEN_PEER_ENDPOINT, AUTH_ENDPOINT, CHECK_BITCOIN_STATUS_ENDPOINT,
    CONFIG_GEN_PEERS_ENDPOINT, CONSENSUS_CONFIG_GEN_PARAMS_ENDPOINT,
    DEFAULT_CONFIG_GEN_PARAMS_ENDPOINT, RESTART_FEDERATION_SETUP_ENDPOINT, RUN_DKG_ENDPOINT,
    SET_CONFIG_GEN_CONNECTIONS_ENDPOINT, SET_CONFIG_GEN_PARAMS_ENDPOINT, SET_PASSWORD_ENDPOINT,
    START_CONSENSUS_ENDPOINT, STATUS_ENDPOINT, VERIFIED_CONFIGS_ENDPOINT,
    VERIFY_CONFIG_HASH_ENDPOINT,
};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::{
    api_endpoint, ApiAuth, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased, ApiVersion,
};
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use fedimint_server_core::ServerModuleInitRegistry;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex, MutexGuard, RwLock};
use tokio::time::Instant;
use tokio_rustls::rustls;
use tracing::{error, info};

use crate::config::{gen_cert_and_key, ConfigGenParams, ServerConfig};
use crate::envs::FM_PEER_ID_SORT_BY_URL_ENV;
use crate::net::api::{check_auth, ApiResult, HasApiContext};

/// Serves the config gen API endpoints
#[derive(Clone)]
pub struct ConfigGenApi {
    /// In-memory state machine
    state: Arc<Mutex<ConfigGenState>>,
    /// DB not really used
    db: Database,
    /// Tracks when the config is generated
    config_generated_tx: Sender<ServerConfig>,
    /// Task group for running DKG
    task_group: TaskGroup,
    /// Code version str that will get encoded in consensus hash
    code_version_str: String,
    /// Api secret to use
    api_secret: Option<String>,
    p2p_bind_addr: SocketAddr,
    bitcoin_status_cache: Arc<RwLock<Option<(Instant, BitcoinRpcConnectionStatus)>>>,
    bitcoin_status_cache_duration: Duration,
}

impl ConfigGenApi {
    pub fn new(
        p2p_bind_addr: SocketAddr,
        settings: ConfigGenSettings,
        db: Database,
        config_generated_tx: Sender<ServerConfig>,
        task_group: &TaskGroup,
        code_version_str: String,
        api_secret: Option<String>,
    ) -> Self {
        let config_gen_api = Self {
            state: Arc::new(Mutex::new(ConfigGenState::new(settings))),
            db,
            config_generated_tx,
            task_group: task_group.clone(),
            code_version_str,
            api_secret,
            p2p_bind_addr,
            bitcoin_status_cache: Arc::new(RwLock::new(None)),
            bitcoin_status_cache_duration: Duration::from_secs(60),
        };
        info!(target: fedimint_logging::LOG_NET_PEER_DKG, "Created new config gen Api");
        config_gen_api
    }

    // Sets the auth and decryption key derived from the password
    pub async fn set_password(&self, auth: ApiAuth) -> ApiResult<()> {
        let mut state = self.require_status(ServerStatus::AwaitingPassword).await?;
        let auth_trimmed = auth.0.trim();
        if auth_trimmed != auth.0 {
            return Err(ApiError::bad_request(
                "Password contains leading/trailing whitespace".to_string(),
            ));
        }
        state.auth = Some(auth);
        state.status = ServerStatus::SharingConfigGenParams;
        info!(
            target: fedimint_logging::LOG_NET_PEER_DKG,
            "Set password for config gen"
        );
        Ok(())
    }

    async fn require_status(&self, status: ServerStatus) -> ApiResult<MutexGuard<ConfigGenState>> {
        let state = self.state.lock().await;
        if state.status != status {
            return Self::bad_request(&format!("Expected to be in {status:?} state"));
        }
        Ok(state)
    }

    async fn require_any_status(
        &self,
        statuses: &[ServerStatus],
    ) -> ApiResult<MutexGuard<ConfigGenState>> {
        let state = self.state.lock().await;
        if !statuses.contains(&state.status) {
            return Self::bad_request(&format!("Expected to be in one of {statuses:?} states"));
        }
        Ok(state)
    }

    /// Sets our connection info, possibly sending it to a leader
    pub async fn set_config_gen_connections(
        &self,
        request: ConfigGenConnectionsRequest,
    ) -> ApiResult<()> {
        {
            let mut state = self
                .require_status(ServerStatus::SharingConfigGenParams)
                .await?;
            state.set_request(request)?;
        }
        self.update_leader().await?;
        Ok(())
    }

    /// Sends our updated peer info to the leader (if we have one)
    async fn update_leader(&self) -> ApiResult<()> {
        let state = self.state.lock().await.clone();
        let local = state.local.clone();

        if let Some(url) = local.and_then(|local| local.leader_api_url) {
            DynGlobalApi::from_pre_peer_id_admin_endpoint(url, &self.api_secret)
                .add_config_gen_peer(state.our_peer_info()?)
                .await
                .map_err(|_| ApiError::not_found("Unable to connect to the leader".to_string()))?;
        }
        Ok(())
    }

    /// Called from `set_config_gen_connections` to add a peer's connection info
    /// to the leader
    pub async fn add_config_gen_peer(&self, peer: PeerServerParams) -> ApiResult<()> {
        let mut state = self.state.lock().await;
        state.peers.insert(peer.api_url.clone(), peer);
        info!(target: fedimint_logging::LOG_NET_PEER_DKG, "New peer added to config gen");
        Ok(())
    }

    /// Returns the peers that have called `add_config_gen_peer` on the leader
    pub async fn config_gen_peers(&self) -> ApiResult<Vec<PeerServerParams>> {
        let state = self.state.lock().await;
        Ok(state.get_peer_info().into_values().collect())
    }

    /// Returns default config gen params that can be modified by the leader
    pub async fn default_config_gen_params(&self) -> ApiResult<ConfigGenParamsRequest> {
        let state = self.state.lock().await;
        Ok(state.settings.default_params.clone())
    }

    /// Sets and validates the config gen params
    ///
    /// The leader passes consensus params, everyone passes local params
    pub async fn set_config_gen_params(&self, request: ConfigGenParamsRequest) -> ApiResult<()> {
        self.consensus_config_gen_params(&request).await?;
        let mut state = self
            .require_status(ServerStatus::SharingConfigGenParams)
            .await?;
        state.requested_params = Some(request);
        info!(
            target: fedimint_logging::LOG_NET_PEER_DKG,
            "Set params for config gen"
        );
        Ok(())
    }

    async fn get_requested_params(&self) -> ApiResult<ConfigGenParamsRequest> {
        let state = self.state.lock().await.clone();
        state.requested_params.ok_or(ApiError::bad_request(
            "Config params were not set on this guardian".to_string(),
        ))
    }

    /// Gets the consensus config gen params
    pub async fn consensus_config_gen_params(
        &self,
        request: &ConfigGenParamsRequest,
    ) -> ApiResult<ConfigGenParamsResponse> {
        let state = self.state.lock().await.clone();
        let local = state.local.clone();

        let consensus = match local.and_then(|local| local.leader_api_url) {
            Some(leader_url) => {
                let client = DynGlobalApi::from_pre_peer_id_admin_endpoint(
                    leader_url.clone(),
                    &self.api_secret,
                );
                let response = client.consensus_config_gen_params().await;
                response
                    .map_err(|_| ApiError::not_found("Cannot get leader params".to_string()))?
                    .consensus
            }
            None => ConfigGenParamsConsensus {
                peers: state.get_peer_info(),
                meta: request.meta.clone(),
                modules: request.modules.clone(),
            },
        };

        let params = state.get_config_gen_params(request, consensus.clone())?;
        Ok(ConfigGenParamsResponse {
            consensus,
            our_current_id: params.local.our_id,
        })
    }

    /// Once configs are generated, updates status to ReadyForConfigGen and
    /// spawns a task to coordinate DKG, then returns. Coordinating DKG in a
    /// separate thread allows clients to poll the server status instead of
    /// blocking until completion, which can be fragile due to timeouts, poor
    /// network connections, etc.
    ///
    /// Calling a second time will return an error.
    pub async fn run_dkg(&self) -> ApiResult<()> {
        let leader = {
            let mut state = self
                .require_status(ServerStatus::SharingConfigGenParams)
                .await?;
            // Update our state
            state.status = ServerStatus::ReadyForConfigGen;
            info!(
                target: fedimint_logging::LOG_NET_PEER_DKG,
                "Update config gen status to 'Ready for config gen'"
            );
            // Create a WSClient for the leader
            state.local.clone().and_then(|local| {
                local.leader_api_url.map(|url| {
                    DynGlobalApi::from_pre_peer_id_admin_endpoint(url, &self.api_secret.clone())
                })
            })
        };

        self.update_leader().await?;

        let self_clone = self.clone();
        let sub_group = self.task_group.make_subgroup();
        let p2p_bind_addr = self.p2p_bind_addr;
        sub_group.spawn("run dkg", move |_handle| async move {
            // Followers wait for leader to signal readiness for DKG
            if let Some(client) = leader {
                loop {
                    let status = client.status().await.map_err(|_| {
                        ApiError::not_found("Unable to connect to the leader".to_string())
                    })?;
                    if status.server == ServerStatus::ReadyForConfigGen {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            };

            // Get params and registry
            let request = self_clone.get_requested_params().await?;
            let response = self_clone.consensus_config_gen_params(&request).await?;
            let (params, registry) = {
                let state: MutexGuard<'_, ConfigGenState> = self_clone
                    .require_status(ServerStatus::ReadyForConfigGen)
                    .await?;
                let params = state.get_config_gen_params(&request, response.consensus)?;
                let registry = state.settings.registry.clone();
                (params, registry)
            };

            // Run DKG
            let task_group: TaskGroup = self_clone.task_group.make_subgroup();
            let config = ServerConfig::distributed_gen(
                p2p_bind_addr,
                &params,
                registry,
                &task_group,
                self_clone.code_version_str.clone(),
            )
            .await;
            task_group
                .shutdown_join_all(None)
                .await
                .expect("shuts down");

            {
                let mut state = self_clone.state.lock().await;
                match config {
                    Ok(config) => {
                        state.status = ServerStatus::VerifyingConfigs;
                        state.config = Some(config);
                        info!(
                            target: fedimint_logging::LOG_NET_PEER_DKG,
                            "Set config for config gen"
                        );
                    }
                    Err(e) => {
                        error!(
                            target: fedimint_logging::LOG_NET_PEER_DKG,
                            "DKG failed with {:?}", e
                        );
                        state.status = ServerStatus::ConfigGenFailed;
                        info!(
                            target: fedimint_logging::LOG_NET_PEER_DKG,
                            "Update config gen status to 'Config gen failed'"
                        );
                    }
                }
            }
            self_clone.update_leader().await
        });

        Ok(())
    }

    /// Returns tagged hashes of consensus config to be shared with other peers.
    /// The hashes are tagged with the peer id  such that they are unique to
    /// each peer and their manual verification by the guardians via the UI is
    /// more robust.
    pub async fn verify_config_hash(&self) -> ApiResult<BTreeMap<PeerId, sha256::Hash>> {
        let expected_status = [
            ServerStatus::VerifyingConfigs,
            ServerStatus::VerifiedConfigs,
        ];

        let state = self.require_any_status(&expected_status).await?;

        let config = state
            .config
            .clone()
            .ok_or(ApiError::bad_request("Missing config".to_string()))?;

        let verification_hashes = config
            .consensus
            .api_endpoints
            .keys()
            .map(|peer| (*peer, (*peer, config.consensus.clone()).consensus_hash()))
            .collect();

        Ok(verification_hashes)
    }

    /// We have verified all our peer configs
    pub async fn verified_configs(&self) -> ApiResult<()> {
        {
            let expected_status = [
                ServerStatus::VerifyingConfigs,
                ServerStatus::VerifiedConfigs,
            ];
            let mut state = self.require_any_status(&expected_status).await?;
            if state.status == ServerStatus::VerifiedConfigs {
                return Ok(());
            }
            state.status = ServerStatus::VerifiedConfigs;
            info!(
                target: fedimint_logging::LOG_NET_PEER_DKG,
                "Update config gen status to 'Verified configs'"
            );
        }

        self.update_leader().await?;
        Ok(())
    }

    pub async fn start_consensus(&self) -> ApiResult<()> {
        let state = self
            .require_any_status(&[
                ServerStatus::VerifyingConfigs,
                ServerStatus::VerifiedConfigs,
            ])
            .await?;

        self.config_generated_tx
            .send(state.config.clone().expect("Config should exist"))
            .await
            .expect("Can send");

        Ok(())
    }

    /// Returns the server status
    pub async fn server_status(&self) -> ServerStatus {
        self.state.lock().await.status.clone()
    }

    fn bad_request<T>(msg: &str) -> ApiResult<T> {
        Err(ApiError::bad_request(msg.to_string()))
    }

    pub async fn restart_federation_setup(&self) -> ApiResult<()> {
        let leader = {
            let expected_status = [
                ServerStatus::SharingConfigGenParams,
                ServerStatus::ReadyForConfigGen,
                ServerStatus::ConfigGenFailed,
                ServerStatus::VerifyingConfigs,
                ServerStatus::VerifiedConfigs,
            ];
            let mut state = self.require_any_status(&expected_status).await?;

            state.status = ServerStatus::SetupRestarted;
            info!(
                target: fedimint_logging::LOG_NET_PEER_DKG,
                "Update config gen status to 'Setup restarted'"
            );
            // Create a WSClient for the leader
            state.local.clone().and_then(|local| {
                local
                    .leader_api_url
                    .map(|url| DynGlobalApi::from_pre_peer_id_admin_endpoint(url, &self.api_secret))
            })
        };

        self.update_leader().await?;

        // Followers wait for leader to signal that all peers have restarted setup
        // The leader will signal this by setting it's status to AwaitingPassword
        let self_clone = self.clone();
        let sub_group = self.task_group.make_subgroup();
        sub_group.spawn("restart", |_handle| async move {
            if let Some(client) = leader {
                self_clone.await_leader_restart(&client).await?;
            } else {
                self_clone.await_peer_restart().await;
            }
            // Progress status to AwaitingPassword
            {
                let mut state = self_clone.state.lock().await;
                state.reset();
            }
            self_clone.update_leader().await
        });

        Ok(())
    }

    // Followers wait for leader to signal that all peers have restarted setup
    async fn await_leader_restart(&self, client: &DynGlobalApi) -> ApiResult<()> {
        let mut retries = 0;
        loop {
            if let Ok(status) = client.status().await {
                if status.server == ServerStatus::AwaitingPassword
                    || status.server == ServerStatus::SharingConfigGenParams
                {
                    break Ok(());
                }
            } else {
                if retries > 3 {
                    return Err(ApiError::not_found(
                        "Unable to connect to the leader".to_string(),
                    ));
                }
                retries += 1;
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    // Leader waits for all peers to restart setup,
    async fn await_peer_restart(&self) {
        loop {
            {
                let state = self.state.lock().await;
                let peers = state.peers.clone();
                if peers
                    .values()
                    .all(|peer| peer.status == Some(ServerStatus::SetupRestarted))
                {
                    break;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    // Check the status of the bitcoin rpc connection
    pub async fn check_bitcoin_status(&self) -> ApiResult<BitcoinRpcConnectionStatus> {
        // Check the cache first
        {
            let cached_status = self.bitcoin_status_cache.read().await;
            if let Some((timestamp, status)) = cached_status.as_ref() {
                if timestamp.elapsed() < self.bitcoin_status_cache_duration {
                    return Ok(*status);
                }
            }
        }

        // If cache is invalid or expired, fetch new status
        let status = Self::fetch_bitcoin_status().await?;

        // Update the bitcoin status cache
        let mut cached_status = self.bitcoin_status_cache.write().await;
        *cached_status = Some((Instant::now(), status));

        Ok(status)
    }

    async fn fetch_bitcoin_status() -> ApiResult<BitcoinRpcConnectionStatus> {
        let bitcoin_rpc_config = BitcoinRpcConfig::get_defaults_from_env_vars().map_err(|e| {
            ApiError::server_error(format!("Failed to get bitcoin rpc env vars: {e}"))
        })?;
        let client = create_bitcoind(&bitcoin_rpc_config).map_err(|e| {
            ApiError::server_error(format!("Failed to connect to bitcoin rpc: {e}"))
        })?;
        let block_count = client.get_block_count().await.map_err(|e| {
            ApiError::server_error(format!("Failed to get block count from bitcoin rpc: {e}"))
        })?;
        let chain_tip_block_height = block_count - 1;
        let chain_tip_block_hash = client
            .get_block_hash(chain_tip_block_height)
            .await
            .map_err(|e| {
                ApiError::server_error(format!(
                    "Failed to get block hash for block count {block_count} from bitcoin rpc: {e}"
                ))
            })?;
        let chain_tip_block = client.get_block(&chain_tip_block_hash).await.map_err(|e| {
            ApiError::server_error(format!(
                "Failed to get block for block hash {chain_tip_block_hash} from bitcoin rpc: {e}"
            ))
        })?;
        let chain_tip_block_time = chain_tip_block.header.time;
        let sync_percentage = client.get_sync_percentage().await.map_err(|e| {
            ApiError::server_error(format!(
                "Failed to get sync percentage from bitcoin rpc: {e}"
            ))
        })?;

        Ok(BitcoinRpcConnectionStatus {
            chain_tip_block_height,
            chain_tip_block_time,
            sync_percentage,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct BitcoinRpcConnectionStatus {
    chain_tip_block_height: u64,
    chain_tip_block_time: u32,
    sync_percentage: Option<f64>,
}

/// Config gen params that are only used locally, shouldn't be shared
#[derive(Debug, Clone)]
pub struct ConfigGenParamsLocal {
    /// Our peer id
    pub our_id: PeerId,
    /// Our TLS private key
    pub our_private_key: rustls::PrivateKey,
    /// Secret API auth string
    pub api_auth: ApiAuth,
    /// Bind address for P2P communication
    pub p2p_bind: SocketAddr,
    /// Bind address for API communication
    pub api_bind: SocketAddr,
    /// How many API connections we will accept
    pub max_connections: u32,
}

/// All the info we configure prior to config gen starting
#[derive(Debug, Clone)]
pub struct ConfigGenSettings {
    /// Limit on the number of times a config download token can be used
    pub download_token_limit: Option<u64>,
    /// Bind address for our P2P connection
    pub p2p_bind: SocketAddr,
    /// Bind address for our API connection
    pub api_bind: SocketAddr,
    /// URL for our P2P connection
    pub p2p_url: SafeUrl,
    /// URL for our API connection
    pub api_url: SafeUrl,
    /// The default params for the modules
    pub default_params: ConfigGenParamsRequest,
    /// How many API connections we will accept
    pub max_connections: u32,
    /// Registry for config gen
    pub registry: ServerModuleInitRegistry,
}

/// State held by the API after receiving a `ConfigGenConnectionsRequest`
#[derive(Debug, Clone)]
pub struct ConfigGenState {
    /// Our config gen settings configured locally
    settings: ConfigGenSettings,
    /// Our auth string
    auth: Option<ApiAuth>,
    /// Our local connection
    local: Option<ConfigGenLocalConnection>,
    /// Connection info received from other guardians, unique by api_url
    /// (because it's non-user configurable)
    peers: BTreeMap<SafeUrl, PeerServerParams>,
    /// The config gen params requested by the leader
    requested_params: Option<ConfigGenParamsRequest>,
    /// Our status
    status: ServerStatus,
    /// Configs that have been generated
    config: Option<ServerConfig>,
}

/// Our local connection info
#[derive(Debug, Clone)]
struct ConfigGenLocalConnection {
    /// Our TLS private key
    tls_private: rustls::PrivateKey,
    /// Our TLS public cert
    tls_cert: rustls::Certificate,
    /// Our guardian name
    our_name: String,
    /// URL of "leader" guardian to send our connection info to
    /// Will be `None` if we are the leader
    leader_api_url: Option<SafeUrl>,
}

impl ConfigGenState {
    fn new(settings: ConfigGenSettings) -> Self {
        Self {
            settings,
            auth: None,
            local: None,
            peers: BTreeMap::new(),
            requested_params: None,
            status: ServerStatus::AwaitingPassword,
            config: None,
        }
    }

    fn set_request(&mut self, request: ConfigGenConnectionsRequest) -> ApiResult<()> {
        let (tls_cert, tls_private) = gen_cert_and_key(&request.our_name)
            .map_err(|_| ApiError::server_error("Unable to generate TLS keys".to_string()))?;
        self.local = Some(ConfigGenLocalConnection {
            tls_private,
            tls_cert,
            our_name: request.our_name,
            leader_api_url: request.leader_api_url,
        });
        info!(
            target: fedimint_logging::LOG_NET_PEER_DKG,
            "Set local connection for config gen"
        );
        Ok(())
    }

    fn local_connection(&self) -> ApiResult<ConfigGenLocalConnection> {
        self.local.clone().ok_or(ApiError::bad_request(
            "Our connection info not set yet".to_string(),
        ))
    }

    fn auth(&self) -> ApiResult<ApiAuth> {
        self.auth
            .clone()
            .ok_or(ApiError::bad_request("Missing auth".to_string()))
    }

    fn our_peer_info(&self) -> ApiResult<PeerServerParams> {
        let local = self.local_connection()?;
        Ok(PeerServerParams {
            cert: local.tls_cert.clone(),
            p2p_url: self.settings.p2p_url.clone(),
            api_url: self.settings.api_url.clone(),
            name: local.our_name,
            status: Some(self.status.clone()),
        })
    }

    fn get_peer_info(&self) -> BTreeMap<PeerId, PeerServerParams> {
        self.peers
            .values()
            .cloned()
            .chain(self.our_peer_info().ok())
            // Since sort order here is arbitrary, try to sort by nick-names first for more natural
            // 'name -> id' mapping, which is helpful when operating on 'peer-ids' (debugging etc.);
            // Ties are OK (to_lowercase), not important in practice.
            .sorted_by_cached_key(|peer| {
                // in certain (very obscure) cases, it might be worthwhile to sort by urls, so
                // just expose it as an env var; probably no need to document it too much
                if std::env::var_os(FM_PEER_ID_SORT_BY_URL_ENV).is_some_and(|var| !var.is_empty()) {
                    peer.api_url.to_string()
                } else {
                    peer.name.to_lowercase()
                }
            })
            .enumerate()
            .map(|(i, peer)| (PeerId::from(i as u16), peer))
            .collect()
    }

    /// Validates and returns the params using our `request` and `consensus`
    /// which comes from the leader
    fn get_config_gen_params(
        &self,
        request: &ConfigGenParamsRequest,
        mut consensus: ConfigGenParamsConsensus,
    ) -> ApiResult<ConfigGenParams> {
        let local_connection = self.local_connection()?;

        let (our_id, _) = consensus
            .peers
            .iter()
            .find(|(_, param)| local_connection.tls_cert == param.cert)
            .ok_or(ApiError::bad_request(
                "Our TLS cert not found among peers".to_string(),
            ))?;

        let mut combined_params = vec![];
        let default_params = self.settings.default_params.modules.clone();
        let local_params = request.modules.clone();
        let consensus_params = consensus.modules.clone();
        // Use defaults in case local or consensus params are missing
        for (id, kind, default) in default_params.iter_modules() {
            let consensus = &consensus_params.get(id).unwrap_or(default).consensus;
            let local = &local_params.get(id).unwrap_or(default).local;
            let combined = ConfigGenModuleParams::new(local.clone(), consensus.clone());
            // Check that the params are parseable
            let module = self.settings.registry.get(kind).expect("Module exists");
            module.validate_params(&combined).map_err(|e| {
                ApiError::bad_request(format!(
                    "Module {} params invalid: {}",
                    id,
                    itertools::join(e.chain(), ": ")
                ))
            })?;
            combined_params.push((id, kind.clone(), combined));
        }
        consensus.modules = ServerModuleConfigGenParamsRegistry::from_iter(combined_params);

        let local = ConfigGenParamsLocal {
            our_id: *our_id,
            our_private_key: local_connection.tls_private,
            api_auth: self.auth()?,
            p2p_bind: self.settings.p2p_bind,
            api_bind: self.settings.api_bind,
            max_connections: self.settings.max_connections,
        };

        Ok(ConfigGenParams { local, consensus })
    }

    fn reset(&mut self) {
        self.auth = None;
        self.local = None;
        self.peers = BTreeMap::new();
        self.requested_params = None;
        self.status = ServerStatus::AwaitingPassword;
        self.config = None;

        info!(
            target: fedimint_logging::LOG_NET_PEER_DKG,
            "Reset config gen state"
        );
    }
}

#[async_trait]
impl HasApiContext<ConfigGenApi> for ConfigGenApi {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&ConfigGenApi, ApiEndpointContext<'_>) {
        let mut db = self.db.clone();
        let mut dbtx = self.db.begin_transaction().await;
        if let Some(id) = id {
            db = self.db.with_prefix_module_id(id).0;
            dbtx = dbtx.with_prefix_module_id(id).0;
        }
        let state = self.state.lock().await;
        let auth = request.auth.as_ref();
        let has_auth = match state.auth.clone() {
            // The first client to connect gets the set the password
            None => true,
            Some(configured_auth) => Some(&configured_auth) == auth,
        };

        (
            self,
            ApiEndpointContext::new(db, dbtx, has_auth, request.auth.clone()),
        )
    }
}

pub fn server_endpoints() -> Vec<ApiEndpoint<ConfigGenApi>> {
    vec![
        api_endpoint! {
            SET_PASSWORD_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, _v: ()| -> () {
                match context.request_auth() {
                    None => return Err(ApiError::bad_request("Missing password".to_string())),
                    Some(auth) => config.set_password(auth).await
                }
            }
        },
        api_endpoint! {
            SET_CONFIG_GEN_CONNECTIONS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, server: ConfigGenConnectionsRequest| -> () {
                check_auth(context)?;
                config.set_config_gen_connections(server).await
            }
        },
        api_endpoint! {
            ADD_CONFIG_GEN_PEER_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, _context, peer: PeerServerParams| -> () {
                // No auth required since this is an API-to-API call and the peer connections will be manually accepted or not in the UI
                config.add_config_gen_peer(peer).await
            }
        },
        api_endpoint! {
            CONFIG_GEN_PEERS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, _context, _v: ()| -> Vec<PeerServerParams> {
                config.config_gen_peers().await
            }
        },
        api_endpoint! {
            DEFAULT_CONFIG_GEN_PARAMS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context,  _v: ()| -> ConfigGenParamsRequest {
                check_auth(context)?;
                config.default_config_gen_params().await
            }
        },
        api_endpoint! {
            SET_CONFIG_GEN_PARAMS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, params: ConfigGenParamsRequest| -> () {
                check_auth(context)?;
                config.set_config_gen_params(params).await
            }
        },
        api_endpoint! {
            CONSENSUS_CONFIG_GEN_PARAMS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, _context, _v: ()| -> ConfigGenParamsResponse {
                let request = config.get_requested_params().await?;
                config.consensus_config_gen_params(&request).await
            }
        },
        api_endpoint! {
            RUN_DKG_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, _v: ()| -> () {
                check_auth(context)?;
                config.run_dkg().await
            }
        },
        api_endpoint! {
            VERIFY_CONFIG_HASH_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, _v: ()| -> BTreeMap<PeerId, sha256::Hash> {
                check_auth(context)?;
                config.verify_config_hash().await
            }
        },
        api_endpoint! {
            VERIFIED_CONFIGS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, _v: ()| -> () {
                check_auth(context)?;
                config.verified_configs().await
            }
        },
        api_endpoint! {
            START_CONSENSUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, _v: ()| -> () {
                check_auth(context)?;
                config.start_consensus().await
            }
        },
        api_endpoint! {
            STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, _context, _v: ()| -> StatusResponse {
                let server = config.server_status().await;
                Ok(StatusResponse {
                    server,
                    federation: None
                })
            }
        },
        api_endpoint! {
            AUTH_ENDPOINT,
            ApiVersion::new(0, 0),
            async |_config: &ConfigGenApi, context, _v: ()| -> () {
                check_auth(context)?;
                Ok(())
            }
        },
        api_endpoint! {
            RESTART_FEDERATION_SETUP_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, _v: ()| -> () {
                check_auth(context)?;
                config.restart_federation_setup().await
            }
        },
        api_endpoint! {
            CHECK_BITCOIN_STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, _v: ()| -> BitcoinRpcConnectionStatus {
                check_auth(context)?;
                config.check_bitcoin_status().await
            }
        },
    ]
}
