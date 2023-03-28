use std::collections::{BTreeMap, BTreeSet};
use std::iter::once;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin_hashes::sha256::HashEngine;
use bitcoin_hashes::{sha256, Hash};
use fedimint_core::admin_client::{
    ConfigGenConnectionsRequest, ConfigGenParamsConsensus, ConfigGenParamsRequest,
    PeerServerParams, WsAdminClient,
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
use fedimint_core::PeerId;
use itertools::Itertools;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::RpcModule;
use tokio::sync::Notify;
use tokio_rustls::rustls;
use tracing::error;
use url::Url;

use crate::config::{gen_cert_and_key, ServerConfig, ServerConfigConsensus, ServerConfigParams};
use crate::net::api::{attach_endpoints, HasApiContext, RpcHandlerCtx};
use crate::net::connect::TlsConfig;
use crate::net::peers::{DelayCalculator, NetworkConfig};

pub type ApiResult<T> = std::result::Result<T, ApiError>;

/// Serves the config gen API endpoints
pub struct ConfigGenApi {
    /// Directory the configs will be created in
    _data_dir: PathBuf,
    /// In-memory state machine
    state: Mutex<ConfigApiState>,
    /// DB not really used
    db: Database,
    /// Our connection info configured locally
    our_connections: ConfigGenConnections,
    /// Notify if we receive connections from peer
    notify_peer_connection: Notify,
    /// The default params for the modules
    default_params: ConfigGenParamsRequest,
    /// Modules that will generate configs
    module_gens: BTreeMap<u16, (ModuleKind, DynServerModuleGen)>,
    /// Registry for config gen
    registry: ServerModuleGenRegistry,
}

impl ConfigGenApi {
    pub fn new(
        data_dir: PathBuf,
        our_connections: ConfigGenConnections,
        db: Database,
        default_params: ConfigGenParamsRequest,
        module_gens: BTreeMap<u16, (ModuleKind, DynServerModuleGen)>,
        registry: ServerModuleGenRegistry,
    ) -> Self {
        Self {
            _data_dir: data_dir,
            state: Mutex::new(ConfigApiState::SetPassword),
            db,
            our_connections,
            notify_peer_connection: Default::default(),
            default_params,
            module_gens,
            registry,
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
        // TODO: should probably just replace bad chars with '_' in `TlsTcpConnector`
        if rustls::ServerName::try_from(request.our_name.as_str()).is_err() {
            return Self::bad_request("Name must be a valid domain string");
        }

        let connection = {
            let mut state = self.state.lock().expect("lock poisoned");

            let connection = match (*state).clone() {
                ConfigApiState::SetConnections(auth) => {
                    ConfigGenConnectionsState::new(request, self.our_connections.clone(), auth)?
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
        Ok(self.default_params.clone())
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
                ConfigApiState::RunningConsensus(_)
                | ConfigApiState::VerifyConsensusConfig(_, _)
                | ConfigApiState::RunningDkg(_) => return Self::bad_request("DKG already run"),
                ConfigApiState::FailedDkg(_) => return dkg_failed,
                _ => return Self::bad_request("Must generate configs first"),
            };

            *state = ConfigApiState::RunningDkg(auth.clone());
            (params, auth)
        };

        let task_group = TaskGroup::new();
        let mut subgroup = task_group.make_subgroup().await;
        let module_gens = self.module_gens.clone();

        let config = ServerConfig::distributed_gen(
            &params.to_server_params(),
            module_gens,
            DelayCalculator::default(),
            &mut subgroup,
        )
        .await;

        let mut state = self.state.lock().expect("lock poisoned");
        match config {
            Ok(config) => {
                *state = ConfigApiState::VerifyConsensusConfig(auth, config);
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
            ConfigApiState::VerifyConsensusConfig(_, config) => Ok(self
                .get_hashes(&config.consensus)
                .remove(&config.local.identity)
                .expect("our id should exist")),
            ConfigApiState::FailedDkg(_) => dkg_failed,
            _ => Self::bad_request("Must run DKG first"),
        }
    }

    /// Returns the consensus config hash, tweaked by our TLS cert, to be shared
    /// with other peers
    pub async fn verify_configs(&self, user_hashes: BTreeSet<sha256::Hash>) -> ApiResult<()> {
        let mut state = self.state.lock().expect("lock poisoned");

        let (auth, config) = match &*state {
            ConfigApiState::VerifyConsensusConfig(auth, config) => (auth.clone(), config.clone()),
            _ => return Self::bad_request("Not in a state that has configs"),
        };

        let hashes: BTreeSet<_> = self
            .get_hashes(&config.consensus)
            .values()
            .cloned()
            .collect();
        if user_hashes == hashes {
            *state = ConfigApiState::RunningConsensus(auth);
            Ok(())
        } else {
            Self::bad_request("Config verification failed")
        }
    }

    fn get_hashes(&self, config: &ServerConfigConsensus) -> BTreeMap<PeerId, sha256::Hash> {
        let mut hashes = BTreeMap::new();
        for (peer, cert) in config.tls_certs.iter() {
            let mut engine = HashEngine::default();
            let hashed = config
                .try_to_config_response(&self.registry)
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
            p2p_bind: connection.our_connections.p2p_bind,
            api_bind: connection.our_connections.api_bind,
        };

        let params = ConfigGenParams { local, consensus };
        *state = ConfigApiState::VerifyConfigParams(auth, params);

        Ok(())
    }
}

#[derive(Debug, Clone)]
/// All the parameters necessary for generating the `ServerConfig` during setup
///
/// * Guardians can create the parameters using a setup UI or CLI tool
/// * Used for distributed or trusted config generation
// TODO: Replace `ServerConfigParams` with this
pub struct ConfigGenParams {
    pub local: ConfigGenParamsLocal,
    pub consensus: ConfigGenParamsConsensus,
}

impl ConfigGenParams {
    pub fn to_server_params(self) -> ServerConfigParams {
        ServerConfigParams {
            our_id: self.local.our_id,
            peer_ids: self.consensus.peers.keys().copied().collect(),
            api_auth: self.local.api_auth,
            tls: TlsConfig {
                our_private_key: self.local.our_private_key,
                peer_certs: self
                    .consensus
                    .peers
                    .iter()
                    .map(|(id, peer)| (*id, peer.cert.clone()))
                    .collect(),
                peer_names: self
                    .consensus
                    .peers
                    .iter()
                    .map(|(id, peer)| (*id, peer.name.clone()))
                    .collect(),
            },
            p2p_network: NetworkConfig {
                identity: self.local.our_id,
                bind_addr: self.local.p2p_bind,
                peers: self
                    .consensus
                    .peers
                    .iter()
                    .map(|(id, peer)| (*id, peer.p2p_url.clone()))
                    .collect(),
            },
            api_network: NetworkConfig {
                identity: self.local.our_id,
                bind_addr: self.local.api_bind,
                peers: self
                    .consensus
                    .peers
                    .iter()
                    .map(|(id, peer)| (*id, peer.api_url.clone()))
                    .collect(),
            },
            meta: self.consensus.requested.meta,
            modules: self.consensus.requested.modules,
        }
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
}

/// All the connections info we configure locally without talking to peers
#[derive(Debug, Clone)]
pub struct ConfigGenConnections {
    /// Bind address for our P2P connection
    pub p2p_bind: SocketAddr,
    /// Bind address for our API connection
    pub api_bind: SocketAddr,
    /// Url for our P2P connection
    pub p2p_url: Url,
    /// Url for our API connection
    pub api_url: Url,
}

/// State held by the API after receiving a `ConfigGenConnectionsRequest`
#[derive(Debug, Clone)]
pub struct ConfigGenConnectionsState {
    /// Our connection info configured locally
    our_connections: ConfigGenConnections,
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
        our_connections: ConfigGenConnections,
        auth: ApiAuth,
    ) -> ApiResult<Self> {
        let (tls_cert, tls_private) = gen_cert_and_key(&request.our_name)
            .map_err(|_| ApiError::server_error("Unable to generate TLS keys".to_string()))?;
        Ok(Self {
            our_connections,
            auth,
            tls_private,
            tls_cert,
            request,
            peers: Default::default(),
        })
    }

    fn with_request(self, request: ConfigGenConnectionsRequest) -> ApiResult<Self> {
        Self::new(request, self.our_connections, self.auth)
    }

    fn as_peer_info(&self) -> PeerServerParams {
        PeerServerParams {
            cert: self.tls_cert.clone(),
            p2p_url: self.our_connections.p2p_url.clone(),
            api_url: self.our_connections.api_url.clone(),
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
    /// Configs are created, awaiting guardian verification
    VerifyConsensusConfig(ApiAuth, ServerConfig),
    /// We all agree on consensus configs, we can run consensus
    RunningConsensus(ApiAuth),
}

#[async_trait]
impl HasApiContext<ConfigGenApi> for ConfigGenApi {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&ConfigGenApi, ApiEndpointContext<'_>) {
        let dbtx = self.db.begin_transaction().await;
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
            ConfigApiState::VerifyConsensusConfig(api_auth, _) => Some(api_auth) == auth,
            ConfigApiState::RunningConsensus(api_auth) => Some(api_auth) == auth,
        };

        (self, ApiEndpointContext::new(has_auth, dbtx, id))
    }
}

/// Starts the configuration server
// TODO: combine with net::run_server and replace DKG CLI with the API
pub async fn run_server(
    data_dir: PathBuf,
    our_connections: ConfigGenConnections,
    db: Database,
    default_params: ConfigGenParamsRequest,
    module_gens: BTreeMap<u16, (ModuleKind, DynServerModuleGen)>,
    registry: ServerModuleGenRegistry,
) -> ServerHandle {
    let state = RpcHandlerCtx {
        rpc_context: Arc::new(ConfigGenApi::new(
            data_dir,
            our_connections.clone(),
            db,
            default_params,
            module_gens,
            registry,
        )),
    };
    let mut rpc_module = RpcModule::new(state);

    attach_endpoints(&mut rpc_module, config_endpoints(), None);

    ServerBuilder::new()
        .max_connections(10)
        .ping_interval(Duration::from_secs(10))
        .build(&our_connections.api_bind.to_string())
        .await
        .expect("Could not start API server")
        .start(rpc_module)
        .expect("Could not start API server")
}

/// Returns the endpoints that are necessary prior to the config being generated
fn config_endpoints() -> Vec<ApiEndpoint<ConfigGenApi>> {
    vec![
        api_endpoint! {
            "set_password",
            async |config: &ConfigGenApi, context, auth: ApiAuth| -> () {
                check_auth(context)?;
                config.set_password(auth)
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
    use std::{env, fs};

    use fedimint_core::admin_client::WsAdminClient;
    use fedimint_core::api::FederationResult;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::ApiAuth;
    use fedimint_core::PeerId;
    use futures::future::join_all;
    use itertools::Itertools;
    use jsonrpsee::server::ServerHandle;
    use url::Url;

    use crate::config::api::{run_server, ConfigGenConnections, ConfigGenConnectionsRequest};

    /// Helper in config API tests for simulating a guardian's client and server
    struct TestConfigApi {
        client: WsAdminClient,
        server: ServerHandle,
        auth: ApiAuth,
        name: String,
        our_connections: ConfigGenConnections,
    }

    impl TestConfigApi {
        /// Creates a new test API taking up a port, with P2P endpoint on the
        /// next port
        async fn new(port: u16, name_suffix: u16, data_dir: PathBuf) -> TestConfigApi {
            let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

            let name = format!("peer{name_suffix}").to_string();
            let api_bind = format!("127.0.0.1:{port}").parse().expect("parses");
            let api_url: Url = format!("ws://127.0.0.1:{port}").parse().expect("parses");
            let p2p_bind = format!("127.0.0.1:{}", port + 1).parse().expect("parses");
            let p2p_url = format!("ws://127.0.0.1:{}", port + 1)
                .parse()
                .expect("parses");
            let our_connections = ConfigGenConnections {
                p2p_bind,
                api_bind,
                p2p_url,
                api_url: api_url.clone(),
            };
            let server = run_server(
                data_dir.clone(),
                our_connections.clone(),
                db,
                Default::default(),
                Default::default(),
                Default::default(),
            )
            .await;
            // our id doesn't really exist at this point
            let auth = ApiAuth(format!("password-{port}"));
            let client = WsAdminClient::new(api_url.clone(), PeerId::from(0), auth.clone());

            TestConfigApi {
                client,
                server,
                auth,
                name,
                our_connections,
            }
        }

        /// Helper function using the auth we generated
        async fn set_password(&self) -> FederationResult<()> {
            self.client.set_password(self.auth.clone()).await
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
    }

    #[test_log::test(tokio::test)]
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
        fs::create_dir(data_dir.clone()).expect("Unable to create test dir");

        // TODO: Choose port in common way with `fedimint_env`
        let base_port = 18103;
        let mut leader = TestConfigApi::new(base_port, 0, data_dir.clone()).await;

        // Cannot set the password twice
        leader.set_password().await.unwrap();
        assert!(leader.set_password().await.is_err());

        // We can call this twice to change the leader name
        leader.set_connections(&None).await.unwrap();
        leader.name = "leader".to_string();
        leader.set_connections(&None).await.unwrap();

        // Setup followers and send connection info
        let mut followers = vec![];
        for i in 1..=3 {
            let port = base_port + (i * 2);
            let mut follower = TestConfigApi::new(port, i, data_dir.clone()).await;
            follower.set_password().await.unwrap();
            let leader_url = Some(leader.our_connections.api_url.clone());
            follower.set_connections(&leader_url).await.unwrap();
            follower.name = format!("{}_", follower.name);
            follower.set_connections(&leader_url).await.unwrap();
            followers.push(follower);
        }

        // Confirm we can get peer servers if we are the leader
        let peers = leader.client.await_config_gen_peers(4).await.unwrap();
        let names: Vec<_> = peers.into_iter().map(|peer| peer.name).sorted().collect();
        assert_eq!(names, vec!["leader", "peer1_", "peer2_", "peer3_"]);

        // Leader sets the configs and followers can fetch them
        let mut configs = vec![];
        let defaults = leader.client.get_default_config_gen_params().await.unwrap();
        leader.client.set_config_gen_params(defaults).await.unwrap();
        configs.push(
            leader
                .client
                .get_consensus_config_gen_params()
                .await
                .unwrap(),
        );
        for follower in &followers {
            configs.push(
                follower
                    .client
                    .get_consensus_config_gen_params()
                    .await
                    .unwrap(),
            );
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
            peer.client.verify_configs(hashes.clone()).await.unwrap()
        }

        for peer in followers {
            peer.server.stop().expect("server stops");
        }
        fs::remove_dir(data_dir).expect("Unable to remove dir");
    }
}
