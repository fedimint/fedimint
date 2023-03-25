use std::collections::BTreeMap;
use std::iter::once;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fedimint_core::admin_client::{ConfigGenConnectionsRequest, PeerServerParams, WsAdminClient};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::Database;
use fedimint_core::module::{
    api_endpoint, ApiAuth, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased,
};
use fedimint_core::PeerId;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::RpcModule;
use tokio::sync::Notify;
use tokio_rustls::rustls;
use url::Url;

use crate::config::gen_cert_and_key;
use crate::net::api::{attach_endpoints, HasApiContext, RpcHandlerCtx};

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
}

impl ConfigGenApi {
    pub fn new(data_dir: PathBuf, our_connections: ConfigGenConnections, db: Database) -> Self {
        Self {
            _data_dir: data_dir,
            state: Mutex::new(ConfigApiState::SetPassword),
            db,
            our_connections,
            notify_peer_connection: Default::default(),
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
                    ConfigGenConnectionsState::new(request, self.our_connections.clone(), auth)?
                }
                ConfigApiState::SetConfigGenParams(old) => old.with_request(request),
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
        let mut state = self.state.lock().expect("lock poisoned");

        let mut connection = match &*state {
            ConfigApiState::SetConfigGenParams(connection) => connection.clone(),
            _ => return Self::bad_request("Not ready to receive peer server params"),
        };
        connection.peers.insert(peer.cert.clone(), peer);
        *state = ConfigApiState::SetConfigGenParams(connection);

        self.notify_peer_connection.notify_one();
        Ok(())
    }

    /// Returns the peers that have called `add_config_gen_peer` on the leader
    pub fn get_config_gen_peers(&self) -> ApiResult<Vec<PeerServerParams>> {
        let state = self.state.lock().expect("lock poisoned");

        let connection = match &*state {
            ConfigApiState::SetConfigGenParams(connection) => connection.clone(),
            _ => return Self::bad_request("Not ready to return peer server params"),
        };

        Ok(connection.get_peer_info())
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

    fn bad_request<T>(msg: &str) -> ApiResult<T> {
        Err(ApiError::bad_request(msg.to_string()))
    }
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
    _tls_private: rustls::PrivateKey,
    /// Our TLS public cert
    tls_cert: rustls::Certificate,
    /// Info sent by the admin user
    request: ConfigGenConnectionsRequest,
    /// Connection info received from other guardians, unique by certificate
    /// (because it's non-user configurable)
    peers: BTreeMap<rustls::Certificate, PeerServerParams>,
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
            _tls_private: tls_private,
            tls_cert,
            request,
            peers: Default::default(),
        })
    }

    fn with_request(mut self, request: ConfigGenConnectionsRequest) -> Self {
        self.request = request;
        self
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
    VerifyConfigParams,
    /// Running DKG may take a minute
    RunningDkg,
    /// Configs are created, awaiting guardian verification
    VerifyConsensusConfig,
    /// We all agree on consensus configs, we can run consensus
    RunningConsensus,
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
            ConfigApiState::VerifyConfigParams => false,
            ConfigApiState::RunningDkg => false,
            ConfigApiState::VerifyConsensusConfig => false,
            ConfigApiState::RunningConsensus => false,
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
) -> ServerHandle {
    let state = RpcHandlerCtx {
        rpc_context: Arc::new(ConfigGenApi::new(data_dir, our_connections.clone(), db)),
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
            "/set_password",
            async |config: &ConfigGenApi, context, auth: ApiAuth| -> () {
                check_auth(context)?;
                config.set_password(auth)
            }
        },
        api_endpoint! {
            "/set_config_gen_connections",
            async |config: &ConfigGenApi, context, server: ConfigGenConnectionsRequest| -> () {
                check_auth(context)?;
                config.set_config_gen_connections(server).await
            }
        },
        api_endpoint! {
            "/add_config_gen_peer",
            async |config: &ConfigGenApi, _context, peer: PeerServerParams| -> () {
                // No auth required since this is an API-to-API call and the peer connections will be manually accepted or not in the UI
                config.add_config_gen_peer(peer)
            }
        },
        api_endpoint! {
            "/get_config_gen_peers",
            async |config: &ConfigGenApi, _context, _v: ()| -> Vec<PeerServerParams> {
                config.get_config_gen_peers()
            }
        },
        api_endpoint! {
            "/await_config_gen_peers",
            async |config: &ConfigGenApi, _context, peers: usize| -> Vec<PeerServerParams> {
                config.await_config_gen_peers(peers).await
            }
        },
    ]
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

    use std::path::PathBuf;
    use std::{env, fs};

    use fedimint_core::admin_client::WsAdminClient;
    use fedimint_core::api::FederationResult;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::ApiAuth;
    use fedimint_core::PeerId;
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
            let server = run_server(data_dir.clone(), our_connections.clone(), db).await;
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
        for i in 1..=3 {
            let port = base_port + (i * 2);
            let mut follower = TestConfigApi::new(port, i, data_dir.clone()).await;
            follower.set_password().await.unwrap();
            let leader_url = Some(leader.our_connections.api_url.clone());
            follower.set_connections(&leader_url).await.unwrap();
            follower.name = format!("{}!", follower.name);
            follower.set_connections(&leader_url).await.unwrap();
        }

        // Confirm we can get peer servers if we are the leader
        let peers = leader.client.await_config_gen_peers(4).await.unwrap();
        let names: Vec<_> = peers.into_iter().map(|peer| peer.name).sorted().collect();
        assert_eq!(names, vec!["leader", "peer1!", "peer2!", "peer3!"]);

        leader.server.stop().expect("stops");
        fs::remove_dir(data_dir).expect("Unable to remove dir");
    }
}
