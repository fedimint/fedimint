use std::collections::{BTreeMap, BTreeSet};
use std::iter::once;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use bitcoin_hashes::sha256::HashEngine;
use bitcoin_hashes::{sha256, Hash};
use fedimint_aead::random_salt;
use fedimint_core::admin_client::{
    ConfigGenConnectionsRequest, ConfigGenParamsConsensus, ConfigGenParamsRequest,
    PeerServerParams, ServerStatus, WsAdminClient,
};
use fedimint_core::config::ServerModuleGenRegistry;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::Database;
use fedimint_core::encoding::Encodable;
use fedimint_core::module::{
    api_endpoint, ApiAuth, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased,
    DynServerModuleGen,
};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::write_new;
use fedimint_core::PeerId;
use itertools::Itertools;
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;
use tokio_rustls::rustls;
use tracing::error;
use url::Url;

use crate::config::io::{read_server_config, write_server_config, SALT_FILE};
use crate::config::{gen_cert_and_key, ConfigGenParams, ServerConfig, ServerConfigConsensus};
use crate::db::ConsensusUpgradeKey;
use crate::net::peers::DelayCalculator;
use crate::HasApiContext;

pub type ApiResult<T> = std::result::Result<T, ApiError>;

/// Serves the config gen API endpoints
pub struct ConfigGenApi {
    /// Directory the configs will be created in
    data_dir: PathBuf,
    /// In-memory state machine
    state: Mutex<ConfigApiState>,
    /// DB not really used
    db: Database,
    /// Our connection info configured locally
    settings: ConfigGenSettings,
    /// Notify if we receive connections from peer
    notify_peer_connection: Notify,
    /// Tracks when the config is generated
    config_generated_tx: Sender<ServerConfig>,
    /// Task group for running DKG
    task_group: TaskGroup,
}

impl ConfigGenApi {
    pub fn new(
        data_dir: PathBuf,
        settings: ConfigGenSettings,
        db: Database,
        config_generated_tx: Sender<ServerConfig>,
        task_group: &mut TaskGroup,
    ) -> Self {
        Self {
            data_dir,
            state: Mutex::new(ConfigApiState::SetPassword),
            db,
            settings,
            notify_peer_connection: Default::default(),
            config_generated_tx,
            task_group: task_group.clone(),
        }
    }

    // Sets the auth and decryption key derived from the password
    pub fn set_password(&self, auth: ApiAuth) -> ApiResult<()> {
        let mut state = self.state.lock().expect("lock poisoned");

        match &*state {
            ConfigApiState::SetPassword => *state = ConfigApiState::SetConnections(auth),
            _ => return Err(ApiError::bad_request("Password already set".to_string())),
        }

        Ok(())
    }

    /// Sets our connection info, possibly sending it to a leader
    pub async fn set_config_gen_connections(
        &self,
        request: ConfigGenConnectionsRequest,
    ) -> ApiResult<()> {
        let connection = {
            let mut state = self.state.lock().expect("lock poisoned");

            let connection = match (*state).clone() {
                ConfigApiState::SetConnections(auth) => {
                    ConfigGenConnectionsState::new(request, self.settings.clone(), auth)?
                }
                ConfigApiState::SetConfigGenParams(old) => old.with_request(request)?,
                _ => return Err(ApiError::bad_request("Config already set".to_string())),
            };
            *state = ConfigApiState::SetConfigGenParams(connection.clone());

            connection
        };

        if let Some(url) = connection.request.leader_api_url.clone() {
            // Note PeerIds don't really exist at this point, but id doesn't matter because
            // it's not used in the WS client for anything, perhaps it should be removed
            let client = WsAdminClient::new(url, PeerId::from(0), connection.auth.clone());
            client
                .add_config_gen_peer(connection.as_peer_info())
                .await
                .map_err(|_| ApiError::not_found("Unable to connect to the leader".to_string()))?;
        }

        self.notify_peer_connection.notify_one();
        Ok(())
    }

    /// Called from `set_config_gen_connections` to add a peer's connection info
    /// to the leader
    pub fn add_config_gen_peer(&self, peer: PeerServerParams) -> ApiResult<()> {
        let mut connection = self.get_connection_state()?;
        connection.peers.insert(peer.api_url.clone(), peer);

        let mut state = self.state.lock().expect("lock poisoned");
        *state = ConfigApiState::SetConfigGenParams(connection);

        self.notify_peer_connection.notify_one();
        Ok(())
    }

    /// Returns the peers that have called `add_config_gen_peer` on the leader
    pub fn get_config_gen_peers(&self) -> ApiResult<Vec<PeerServerParams>> {
        let state = self.state.lock().expect("lock poisoned");

        let peers = match &*state {
            ConfigApiState::SetConfigGenParams(connection) => Ok(connection.get_peer_info()),
            ConfigApiState::VerifyConfigParams(_, params) => {
                Ok(params.consensus.peers.values().cloned().collect())
            }
            _ => Self::bad_request("Set the config connections first"),
        }?;

        Ok(peers)
    }

    /// Waits for at least `num_peers` connections to be added
    pub async fn await_config_gen_peers(&self, peers: usize) -> ApiResult<Vec<PeerServerParams>> {
        let mut peer_info = self.get_config_gen_peers()?;
        while peer_info.len() < peers {
            self.notify_peer_connection.notified().await;
            peer_info = self.get_config_gen_peers()?;
        }

        Ok(peer_info)
    }

    /// Returns default config gen params that can be modified by the leader
    pub fn get_default_config_gen_params(&self) -> ApiResult<ConfigGenParamsRequest> {
        Ok(self.settings.default_params.clone())
    }

    /// Sets the config gen params, should only be called by the leader
    pub async fn set_config_gen_params(&self, requested: ConfigGenParamsRequest) -> ApiResult<()> {
        let connection = self.get_connection_state()?;

        let peers: BTreeMap<PeerId, PeerServerParams> = connection
            .get_peer_info()
            .into_iter()
            .enumerate()
            .map(|(i, peer)| (PeerId::from(i as u16), peer))
            .collect();

        let consensus = ConfigGenParamsConsensus { peers, requested };
        self.set_config_state(connection, consensus)?;

        Ok(())
    }

    /// Gets the consensus config gen params, if we have a leader get it from
    /// the leader
    pub async fn get_consensus_config_gen_params(&self) -> ApiResult<ConfigGenParamsConsensus> {
        let connection = {
            let state = self.state.lock().expect("lock poisoned");

            match &*state {
                ConfigApiState::VerifyConfigParams(_, param) => return Ok(param.consensus.clone()),
                ConfigApiState::SetConfigGenParams(connection) => connection.clone(),
                _ => return Self::bad_request("Not in a state that can return params"),
            }
        };

        let url = connection
            .request
            .leader_api_url
            .clone()
            .ok_or(ApiError::bad_request(
                "Need to set the consensus params first".to_string(),
            ))?;

        let client = WsAdminClient::new(url, PeerId::from(0), connection.auth.clone());
        let consensus = client
            .get_consensus_config_gen_params()
            .await
            .map_err(|_| ApiError::not_found("Unable to get params from leader".to_string()))?;

        self.set_config_state(connection, consensus.clone())?;

        Ok(consensus)
    }

    /// Once configs are generated, starts DKG and await its
    /// completion, calling a second time will return an error
    pub async fn run_dkg(&self) -> ApiResult<()> {
        let dkg_failed = Err(ApiError::server_error("DKG failed".to_string()));

        let (params, auth) = {
            let mut state = self.state.lock().expect("lock poisoned");

            let (params, auth) = match &*state {
                ConfigApiState::VerifyConfigParams(auth, params) => (params.clone(), auth.clone()),
                ConfigApiState::VerifyConsensusConfig(_) | ConfigApiState::RunningDkg(_) => {
                    return Self::bad_request("DKG already run")
                }
                ConfigApiState::FailedDkg(_) => return dkg_failed,
                _ => return Self::bad_request("Must generate configs first"),
            };

            *state = ConfigApiState::RunningDkg(auth.clone());
            (params, auth)
        };

        let module_gens = self.settings.module_gens.clone();

        let mut task_group = self.task_group.make_subgroup().await;
        let config = ServerConfig::distributed_gen(
            &params,
            module_gens,
            DelayCalculator::PROD_DEFAULT,
            &mut task_group,
        )
        .await;
        task_group
            .shutdown_join_all(None)
            .await
            .expect("shuts down");

        let mut state = self.state.lock().expect("lock poisoned");
        match config {
            Ok(config) => {
                *state = ConfigApiState::VerifyConsensusConfig(config);
                Ok(())
            }
            Err(e) => {
                error!(
                    target: fedimint_logging::LOG_NET_PEER_DKG,
                    "DKG failed with {:?}", e
                );
                *state = ConfigApiState::FailedDkg(auth);
                dkg_failed
            }
        }
    }

    /// Returns the consensus config hash, tweaked by our TLS cert, to be shared
    /// with other peers
    pub fn get_verify_config_hash(&self) -> ApiResult<sha256::Hash> {
        let state = self.state.lock().expect("lock poisoned");
        let dkg_failed = Err(ApiError::server_error("DKG failed".to_string()));

        match &*state {
            ConfigApiState::VerifyConsensusConfig(config) => Ok(self
                .get_hashes(&config.consensus)
                .remove(&config.local.identity)
                .expect("our id should exist")),
            ConfigApiState::FailedDkg(_) => dkg_failed,
            _ => Self::bad_request("Must run DKG first"),
        }
    }

    /// User must pass in the hashes received from other peers in order to
    /// confirm that all guardians have the same consensus config.  If
    /// successful, writes the configs to disk.  We stretch the auth string with
    /// `get_encryption_key` to make brute-force attacks against the
    /// encrypted configs more difficult.
    pub async fn verify_configs(&self, user_hashes: BTreeSet<sha256::Hash>) -> ApiResult<()> {
        let state = self.state.lock().expect("lock poisoned");

        let config = match &*state {
            ConfigApiState::VerifyConsensusConfig(config) => config.clone(),
            _ => return Self::bad_request("Not in a state that has configs"),
        };

        let hashes: BTreeSet<_> = self
            .get_hashes(&config.consensus)
            .values()
            .cloned()
            .collect();

        if user_hashes != hashes {
            return Self::bad_request("Config verification failed");
        }

        let auth = config.private.api_auth.0.clone();
        write_new(self.data_dir.join(SALT_FILE), random_salt())
            .map_err(|e| ApiError::server_error(format!("Unable to write to data dir {e:?}")))?;
        write_server_config(
            &config,
            self.data_dir.clone(),
            &auth,
            &self.settings.registry,
        )
        .map_err(|e| ApiError::server_error(format!("Unable to encrypt configs {e:?}")))
    }

    /// Attempts to decrypt the config files from disk using the auth string.
    ///
    /// Will force shut down the config gen API so the consensus API can start.
    /// Removes the upgrade flag when called.
    pub async fn start_consensus(&self, auth: ApiAuth) -> ApiResult<()> {
        let cfg = read_server_config(&auth.0, self.data_dir.clone())
            .map_err(|e| ApiError::bad_request(format!("Unable to decrypt configs {e:?}")))?;

        let mut tx = self.db.begin_transaction().await;
        tx.remove_entry(&ConsensusUpgradeKey).await;
        tx.commit_tx().await;

        self.config_generated_tx.send(cfg).await.expect("Can send");

        Ok(())
    }

    /// Returns the server status
    pub async fn status(&self) -> ServerStatus {
        let has_upgrade_flag = { self.has_upgrade_flag().await };

        let state = self.state.lock().expect("lock poisoned");
        match &*state {
            ConfigApiState::SetPassword => ServerStatus::AwaitingPassword,
            _ if has_upgrade_flag => ServerStatus::Upgrading,
            _ => ServerStatus::GeneratingConfig,
        }
    }

    /// Returns true if the upgrade flag is set indicating that the server was
    /// shutdown due to a planned upgrade
    pub async fn has_upgrade_flag(&self) -> bool {
        let mut tx = self.db.begin_transaction().await;
        tx.get_value(&ConsensusUpgradeKey).await.is_some()
    }

    fn get_hashes(&self, config: &ServerConfigConsensus) -> BTreeMap<PeerId, sha256::Hash> {
        let mut hashes = BTreeMap::new();
        for (peer, cert) in config.tls_certs.iter() {
            let mut engine = HashEngine::default();
            let hashed = config
                .try_to_config_response(&self.settings.registry)
                .expect("hashes");

            hashed
                .consensus_hash
                .consensus_encode(&mut engine)
                .expect("hashes");
            cert.consensus_encode(&mut engine).expect("hashes");

            let hash = sha256::Hash::from_engine(engine);
            hashes.insert(*peer, hash);
        }
        hashes
    }

    fn get_connection_state(&self) -> ApiResult<ConfigGenConnectionsState> {
        let state = self.state.lock().expect("lock poisoned");

        match &*state {
            ConfigApiState::SetConfigGenParams(connection) => Ok(connection.clone()),
            ConfigApiState::SetConnections(_) => {
                Self::bad_request("Set the config connections first")
            }
            _ => Self::bad_request("Config params were already generated"),
        }
    }

    fn bad_request<T>(msg: &str) -> ApiResult<T> {
        Err(ApiError::bad_request(msg.to_string()))
    }

    fn set_config_state(
        &self,
        connection: ConfigGenConnectionsState,
        consensus: ConfigGenParamsConsensus,
    ) -> ApiResult<()> {
        let mut state = self.state.lock().expect("lock poisoned");

        let (our_id, _) = consensus
            .peers
            .iter()
            .find(|(_, param)| connection.tls_cert == param.cert)
            .ok_or(ApiError::bad_request(
                "Our TLS cert not found among peers".to_string(),
            ))?;

        let auth = connection.auth.clone();
        let local = ConfigGenParamsLocal {
            our_id: *our_id,
            our_private_key: connection.tls_private,
            api_auth: connection.auth,
            p2p_bind: connection.settings.p2p_bind,
            api_bind: connection.settings.api_bind,
            download_token_limit: connection.settings.download_token_limit,
        };

        let params = ConfigGenParams { local, consensus };
        *state = ConfigApiState::VerifyConfigParams(auth, params);

        Ok(())
    }
}

/// Config params that are only used locally, shouldn't be shared
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
    /// Limit on the number of times a config download token can be used
    pub download_token_limit: Option<u64>,
}

/// All the connections info we configure locally without talking to peers
#[derive(Debug, Clone)]
pub struct ConfigGenSettings {
    /// Limit on the number of times a config download token can be used
    pub download_token_limit: Option<u64>,
    /// Bind address for our P2P connection
    pub p2p_bind: SocketAddr,
    /// Bind address for our API connection
    pub api_bind: SocketAddr,
    /// Url for our P2P connection
    pub p2p_url: Url,
    /// Url for our API connection
    pub api_url: Url,
    /// The default params for the modules
    pub default_params: ConfigGenParamsRequest,
    /// Modules that will generate configs
    pub module_gens: BTreeMap<u16, (ModuleKind, DynServerModuleGen)>,
    /// Registry for config gen
    pub registry: ServerModuleGenRegistry,
}

/// State held by the API after receiving a `ConfigGenConnectionsRequest`
#[derive(Debug, Clone)]
pub struct ConfigGenConnectionsState {
    /// Our config gen settings configured locally
    settings: ConfigGenSettings,
    /// Our auth string
    auth: ApiAuth,
    /// Our TLS private key
    tls_private: rustls::PrivateKey,
    /// Our TLS public cert
    tls_cert: rustls::Certificate,
    /// Info sent by the admin user
    request: ConfigGenConnectionsRequest,
    /// Connection info received from other guardians, unique by api_url
    /// (because it's non-user configurable)
    peers: BTreeMap<Url, PeerServerParams>,
}

impl ConfigGenConnectionsState {
    fn new(
        request: ConfigGenConnectionsRequest,
        our_connections: ConfigGenSettings,
        auth: ApiAuth,
    ) -> ApiResult<Self> {
        let (tls_cert, tls_private) = gen_cert_and_key(&request.our_name)
            .map_err(|_| ApiError::server_error("Unable to generate TLS keys".to_string()))?;
        Ok(Self {
            settings: our_connections,
            auth,
            tls_private,
            tls_cert,
            request,
            peers: Default::default(),
        })
    }

    fn with_request(self, request: ConfigGenConnectionsRequest) -> ApiResult<Self> {
        Self::new(request, self.settings, self.auth)
    }

    fn as_peer_info(&self) -> PeerServerParams {
        PeerServerParams {
            cert: self.tls_cert.clone(),
            p2p_url: self.settings.p2p_url.clone(),
            api_url: self.settings.api_url.clone(),
            name: self.request.our_name.clone(),
        }
    }

    fn get_peer_info(&self) -> Vec<PeerServerParams> {
        self.peers
            .values()
            .cloned()
            .chain(once(self.as_peer_info()))
            .sorted_by_key(|peer| peer.cert.clone())
            .collect()
    }
}

/// The current state of config generation, required in a top-to-bottom order
#[derive(Debug, Clone)]
/// State machine for config generation, required in a top-to-bottom order
pub enum ConfigApiState {
    /// Guardian must first enter a password for auth/decryption
    SetPassword,
    /// Guardians must send connection info to a "leader"
    SetConnections(ApiAuth),
    /// A "leader" guardian (possibly us) must set the config gen parameters
    SetConfigGenParams(ConfigGenConnectionsState),
    /// Guardian must verify the correct config gen params
    VerifyConfigParams(ApiAuth, ConfigGenParams),
    /// Running DKG may take a minute
    RunningDkg(ApiAuth),
    /// DKG failed, user should restart config gen from the beginning
    FailedDkg(ApiAuth),
    /// Awaiting guardian verification to write configs
    VerifyConsensusConfig(ServerConfig),
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
            db = self.db.new_isolated(id);
            dbtx = dbtx.new_module_tx(id)
        }
        let state = self.state.lock().expect("locks");
        let auth = request.auth.as_ref();
        let has_auth = match &*state {
            // The first client to connect gets the set the password
            ConfigApiState::SetPassword => true,
            ConfigApiState::SetConnections(api_auth) => Some(api_auth) == auth,
            ConfigApiState::SetConfigGenParams(connections) => Some(&connections.auth) == auth,
            ConfigApiState::VerifyConfigParams(api_auth, _) => Some(api_auth) == auth,
            ConfigApiState::RunningDkg(api_auth) => Some(api_auth) == auth,
            ConfigApiState::FailedDkg(api_auth) => Some(api_auth) == auth,
            ConfigApiState::VerifyConsensusConfig(cfg) => Some(&cfg.private.api_auth) == auth,
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
            "set_password",
            async |config: &ConfigGenApi, context, _v: ()| -> () {
                match context.request_auth() {
                    None => return Err(ApiError::bad_request("Missing password".to_string())),
                    Some(auth) => config.set_password(auth)
                }
            }
        },
        api_endpoint! {
            "set_config_gen_connections",
            async |config: &ConfigGenApi, context, server: ConfigGenConnectionsRequest| -> () {
                check_auth(context)?;
                config.set_config_gen_connections(server).await
            }
        },
        api_endpoint! {
            "add_config_gen_peer",
            async |config: &ConfigGenApi, context, peer: PeerServerParams| -> () {
                // No auth required since this is an API-to-API call and the peer connections will be manually accepted or not in the UI
                check_no_auth(context)?;
                config.add_config_gen_peer(peer)
            }
        },
        api_endpoint! {
            "get_config_gen_peers",
            async |config: &ConfigGenApi, context, _v: ()| -> Vec<PeerServerParams> {
                check_no_auth(context)?;
                config.get_config_gen_peers()
            }
        },
        api_endpoint! {
            "await_config_gen_peers",
            async |config: &ConfigGenApi, context, peers: usize| -> Vec<PeerServerParams> {
                check_no_auth(context)?;
                config.await_config_gen_peers(peers).await
            }
        },
        api_endpoint! {
            "get_default_config_gen_params",
            async |config: &ConfigGenApi, context,  _v: ()| -> ConfigGenParamsRequest {
                check_auth(context)?;
                config.get_default_config_gen_params()
            }
        },
        api_endpoint! {
            "set_config_gen_params",
            async |config: &ConfigGenApi, context, params: ConfigGenParamsRequest| -> () {
                check_auth(context)?;
                config.set_config_gen_params(params).await
            }
        },
        api_endpoint! {
            "get_consensus_config_gen_params",
            async |config: &ConfigGenApi, context, _v: ()| -> ConfigGenParamsConsensus {
                check_no_auth(context)?;
                config.get_consensus_config_gen_params().await
            }
        },
        api_endpoint! {
            "run_dkg",
            async |config: &ConfigGenApi, context, _v: ()| -> () {
                check_auth(context)?;
                config.run_dkg().await
            }
        },
        api_endpoint! {
            "get_verify_config_hash",
            async |config: &ConfigGenApi, context, _v: ()| -> sha256::Hash {
                check_auth(context)?;
                config.get_verify_config_hash()
            }
        },
        api_endpoint! {
            "verify_configs",
            async |config: &ConfigGenApi, context, user_hashes: BTreeSet<sha256::Hash>| -> () {
                check_auth(context)?;
                config.verify_configs(user_hashes).await
            }
        },
        api_endpoint! {
            "start_consensus",
            async |config: &ConfigGenApi, context, _v: ()| -> () {
                check_auth(context)?;
                let request_auth = context.request_auth();
                match request_auth {
                    None => return Err(ApiError::bad_request("Missing password".to_string())),
                    Some(auth) => config.start_consensus(auth).await
                }
            }
        },
        api_endpoint! {
            "status",
            async |config: &ConfigGenApi, context, _v: ()| -> ServerStatus {
                if context.has_auth() {
                    Ok(config.status().await)
                } else {
                    Err(ApiError::unauthorized())
                }
            }
        },
    ]
}

fn check_no_auth(context: &mut ApiEndpointContext) -> ApiResult<()> {
    if context.has_auth() {
        Err(ApiError::bad_request(
            "Should not pass auth to this endpoint".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn check_auth(context: &mut ApiEndpointContext) -> ApiResult<()> {
    if !context.has_auth() {
        Err(ApiError::unauthorized())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::time::Duration;
    use std::{env, fs};

    use fedimint_core::admin_client::{ServerStatus, WsAdminClient};
    use fedimint_core::api::FederationResult;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::ApiAuth;
    use fedimint_core::task::{sleep, TaskGroup};
    use fedimint_core::util::write_new;
    use fedimint_core::PeerId;
    use futures::future::join_all;
    use itertools::Itertools;
    use url::Url;

    use crate::config::api::{ConfigGenConnectionsRequest, ConfigGenSettings};
    use crate::config::DEFAULT_CONFIG_DOWNLOAD_LIMIT;
    use crate::{FedimintServer, PLAINTEXT_PASSWORD};

    /// Helper in config API tests for simulating a guardian's client and server
    struct TestConfigApi {
        client: WsAdminClient,
        name: String,
        settings: ConfigGenSettings,
        auth: ApiAuth,
        dir: PathBuf,
    }

    impl TestConfigApi {
        /// Creates a new test API taking up a port, with P2P endpoint on the
        /// next port
        async fn new(
            port: u16,
            name_suffix: u16,
            data_dir: PathBuf,
        ) -> (TestConfigApi, FedimintServer) {
            let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

            let name = format!("peer{name_suffix}");
            let api_bind = format!("127.0.0.1:{port}").parse().expect("parses");
            let api_url: Url = format!("ws://127.0.0.1:{port}").parse().expect("parses");
            let p2p_bind = format!("127.0.0.1:{}", port + 1).parse().expect("parses");
            let p2p_url = format!("fedimint://127.0.0.1:{}", port + 1)
                .parse()
                .expect("parses");
            let settings = ConfigGenSettings {
                download_token_limit: Some(DEFAULT_CONFIG_DOWNLOAD_LIMIT),
                p2p_bind,
                api_bind,
                p2p_url,
                api_url: api_url.clone(),
                default_params: Default::default(),
                module_gens: Default::default(),
                registry: Default::default(),
            };
            let dir = data_dir.join(name_suffix.to_string());
            fs::create_dir_all(dir.clone()).expect("Unable to create test dir");

            let api = FedimintServer {
                data_dir: dir.clone(),
                settings: settings.clone(),
                db,
            };

            // our id doesn't really exist at this point
            let auth = ApiAuth(format!("password-{port}"));
            let client = WsAdminClient::new(api_url, PeerId::from(0), auth.clone());

            (
                TestConfigApi {
                    client,
                    name,
                    settings,
                    auth,
                    dir,
                },
                api,
            )
        }

        /// Helper function to shutdown consensus with an upgrade signal
        async fn retry_signal_upgrade(&self) {
            while self.client.signal_upgrade().await.is_err() {
                sleep(Duration::from_millis(1000)).await;
                tracing::info!(
                    target: fedimint_logging::LOG_TEST,
                    "Test retrying upgrade signal"
                )
            }
        }

        /// Helper function using generated urls
        async fn set_connections(&self, leader: &Option<Url>) -> FederationResult<()> {
            self.client
                .set_config_gen_connections(ConfigGenConnectionsRequest {
                    our_name: self.name.clone(),
                    leader_api_url: leader.clone(),
                })
                .await
        }

        /// Helper for getting server status
        async fn server_status(&self) -> ServerStatus {
            loop {
                match self.client.status().await {
                    Ok(status) => return status,
                    Err(_) => sleep(Duration::from_millis(1000)).await,
                }
                tracing::info!(
                    target: fedimint_logging::LOG_TEST,
                    "Test retrying server status"
                )
            }
        }

        /// Helper for writing the password file to bypass the API
        fn write_password_file(&self) {
            write_new(self.dir.join(PLAINTEXT_PASSWORD), &self.auth.0).unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_config_api() {
        let (parent, _maybe_tmp_dir_guard) = match env::var("FM_TEST_DIR") {
            Ok(directory) => (directory, None),
            Err(_) => {
                let guard = tempfile::Builder::new()
                    .prefix("fm-cfg-api")
                    .tempdir()
                    .unwrap();
                let directory = guard.path().to_str().unwrap().to_owned();
                (directory, Some(guard))
            }
        };
        let data_dir = PathBuf::from(parent).join("test-config-api");

        // TODO: Choose port in common way with `fedimint_env`
        let base_port = 18103;

        // let mut join_handles = vec![];
        let mut apis = vec![];
        let mut followers = vec![];
        let (mut leader, api) = TestConfigApi::new(base_port, 0, data_dir.clone()).await;
        apis.push(api);

        for i in 1..=2 {
            let port = base_port + (i * 2);
            let (follower, api) = TestConfigApi::new(port, i, data_dir.clone()).await;
            apis.push(api);
            followers.push(follower);
        }

        let test = async {
            assert_eq!(leader.server_status().await, ServerStatus::AwaitingPassword);

            // Cannot set the password twice
            leader.client.set_password().await.unwrap();
            assert!(leader.client.set_password().await.is_err());
            assert_eq!(leader.server_status().await, ServerStatus::GeneratingConfig);

            // We can call this twice to change the leader name
            leader.set_connections(&None).await.unwrap();
            leader.name = "leader".to_string();
            leader.set_connections(&None).await.unwrap();

            // Setup followers and send connection info
            for follower in &mut followers {
                assert_eq!(
                    follower.server_status().await,
                    ServerStatus::AwaitingPassword
                );
                follower.client.set_password().await.unwrap();
                let leader_url = Some(leader.settings.api_url.clone());
                follower.set_connections(&leader_url).await.unwrap();
                follower.name = format!("{}_", follower.name);
                follower.set_connections(&leader_url).await.unwrap();
            }

            // Confirm we can get peer servers if we are the leader
            let peers = leader.client.await_config_gen_peers(3).await.unwrap();
            let names: Vec<_> = peers.into_iter().map(|peer| peer.name).sorted().collect();
            assert_eq!(names, vec!["leader", "peer1_", "peer2_"]);

            // Leader sets the configs and followers can fetch them
            let mut configs = vec![];
            let defaults = leader.client.get_default_config_gen_params().await.unwrap();
            leader.client.set_config_gen_params(defaults).await.unwrap();
            for peer in &followers {
                configs.push(peer.client.get_consensus_config_gen_params().await.unwrap());
            }
            // Confirm all configs are the same
            configs.dedup();
            assert_eq!(configs.len(), 1);

            // all peers run DKG
            followers.push(leader);
            join_all(followers.iter().map(|peer| peer.client.run_dkg())).await;

            // verify configs for all peers
            let mut hashes = BTreeSet::new();
            for peer in &followers {
                hashes.insert(peer.client.get_verify_config_hash().await.unwrap());
            }
            for peer in &followers {
                peer.client.verify_configs(hashes.clone()).await.unwrap();
            }

            // start consensus
            for peer in &followers {
                peer.client.start_consensus().await.ok();
                assert_eq!(peer.server_status().await, ServerStatus::ConsensusRunning);
            }

            // shutdown
            for peer in &followers {
                peer.retry_signal_upgrade().await;
            }
        };

        // Run the Fedimint servers and test concurrently
        tokio::join!(
            join_all(apis.iter_mut().map(|api| api.run(TaskGroup::new()))),
            test
        );

        // Test writing the password file to bypass the API
        for peer in &followers {
            peer.write_password_file();
        }

        let test2 = async {
            // Confirm we are stuck in upgrading after an upgrade
            for peer in &followers {
                assert_eq!(peer.server_status().await, ServerStatus::Upgrading);
                peer.client.start_consensus().await.ok();
                assert_eq!(peer.server_status().await, ServerStatus::ConsensusRunning);
            }

            // shutdown again
            for peer in &followers {
                peer.retry_signal_upgrade().await;
            }
        };

        //  Restart the Fedimint servers and a new test concurrently
        tokio::join!(
            join_all(apis.iter_mut().map(|api| api.run(TaskGroup::new()))),
            test2
        );
    }
}
